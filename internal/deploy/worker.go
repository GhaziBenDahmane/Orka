package deploy

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	backupstore "github.com/bendahma/dokploy-go/internal/backup"
	"github.com/bendahma/dokploy-go/internal/cryptox"
	"github.com/bendahma/dokploy-go/internal/database"
	"github.com/bendahma/dokploy-go/internal/observability"
	"github.com/bendahma/dokploy-go/internal/store"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

type Worker struct {
	Store              *store.Store
	Box                *cryptox.Box
	Compiler           Compiler
	Swarm              Scheduler
	Concurrency        int
	Logger             *slog.Logger
	ID                 string
	Databases          *database.Registry
	BackupDirectory    string
	Builder            Builder
	Metrics            *observability.Metrics
	NotificationClient *http.Client
	// notificationTLS lets conformance tests trust an isolated SMTP server
	// without weakening the system trust store used in production.
	notificationTLS    *tls.Config
	RemoteScheduler    func(uuid.UUID) Scheduler
}

type job struct {
	ID          uuid.UUID
	LeaseID     uuid.UUID
	Kind        string
	Payload     []byte
	Attempts    int
	MaxAttempts int
}

func (w *Worker) Run(ctx context.Context) {
	w.recoverStale(ctx)
	var wg sync.WaitGroup
	wg.Add(4)
	go func() { defer wg.Done(); w.scheduleBackups(ctx) }()
	go func() { defer wg.Done(); w.pruneAuditEvents(ctx) }()
	go func() { defer wg.Done(); w.scheduleAuditArchives(ctx) }()
	go func() { defer wg.Done(); w.reconcileStacks(ctx) }()
	for i := 0; i < w.Concurrency; i++ {
		wg.Add(1)
		go func() { defer wg.Done(); w.loop(ctx) }()
	}
	<-ctx.Done()
	wg.Wait()
}

func (w *Worker) reconcileStacks(ctx context.Context) {
	ticker := time.NewTicker(time.Minute)
	defer ticker.Stop()
	for {
		leader, err := w.Store.AcquireControllerLease(ctx, "stack-reconciler", w.ID, 90*time.Second)
		if err != nil && ctx.Err() == nil {
			w.Logger.Error("acquire stack reconciler lease", "error", err)
		} else if leader {
			w.reconcileStackBatch(ctx)
		}
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

func (w *Worker) reconcileStackBatch(ctx context.Context) {
	candidates, err := w.Store.ListReconciliationCandidates(ctx, 50)
	if err != nil {
		w.Logger.Error("list reconciliation candidates", "error", err)
		return
	}
	jobs := make(chan store.ReconciliationCandidate)
	var workers sync.WaitGroup
	workerCount := min(8, len(candidates))
	for range workerCount {
		workers.Add(1)
		go func() {
			defer workers.Done()
			for candidate := range jobs {
				w.reconcileStack(ctx, candidate)
			}
		}()
	}
	for _, candidate := range candidates {
		select {
		case <-ctx.Done():
			close(jobs)
			workers.Wait()
			return
		case jobs <- candidate:
		}
	}
	close(jobs)
	workers.Wait()
}

func (w *Worker) reconcileStack(ctx context.Context, candidate store.ReconciliationCandidate) {
	inspector, ok := w.scheduler(candidate.ClusterID).(StackInspector)
	if !ok {
		if _, recordErr := w.Store.RecordReconciliation(ctx, candidate, "unknown", "scheduler does not support stack inspection"); recordErr != nil {
			w.Logger.Error("record reconciliation", "service", candidate.ServiceID, "error", recordErr)
		}
		return
	}
	inspectCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	status, inspectErr := inspector.Status(inspectCtx, candidate.StackName)
	cancel()
	state, detail := "healthy", ""
	if inspectErr != nil {
		state, detail = "unknown", inspectErr.Error()
	} else if !status.Exists {
		state, detail = "missing", "stack has no services"
	} else if status.HealthyServices != status.Services {
		state = "degraded"
		detail = fmt.Sprintf("%d/%d services healthy; %d/%d tasks running; degraded=%s", status.HealthyServices, status.Services, status.RunningTasks, status.DesiredTasks, strings.Join(status.Degraded, ","))
	}
	repair, recordErr := w.Store.RecordReconciliation(ctx, candidate, state, detail)
	if recordErr != nil {
		if !errors.Is(recordErr, store.ErrNotFound) {
			w.Logger.Error("record reconciliation", "service", candidate.ServiceID, "error", recordErr)
		}
		return
	}
	if repair != nil {
		w.Logger.Warn("queued drift repair", "service", candidate.ServiceID, "deployment", repair.ID, "state", state)
	}
}

func (w *Worker) scheduleAuditArchives(ctx context.Context) {
	ticker := time.NewTicker(time.Minute)
	defer ticker.Stop()
	for {
		leader, leaseErr := w.Store.AcquireControllerLease(ctx, "audit-archiver", w.ID, 90*time.Second)
		if leaseErr != nil && ctx.Err() == nil {
			w.Logger.Error("acquire audit archiver lease", "error", leaseErr)
		} else if leader {
			for ctx.Err() == nil {
				_, err := w.Store.QueueNextAuditArchive(ctx)
				if errors.Is(err, store.ErrNotFound) {
					break
				}
				if err != nil {
					w.Logger.Error("schedule audit archive", "error", err)
					break
				}
			}
		}
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

func (w *Worker) pruneAuditEvents(ctx context.Context) {
	ticker := time.NewTicker(time.Hour)
	defer ticker.Stop()
	for {
		leader, leaseErr := w.Store.AcquireControllerLease(ctx, "audit-pruner", w.ID, 2*time.Hour)
		if leaseErr != nil && ctx.Err() == nil {
			w.Logger.Error("acquire audit pruner lease", "error", leaseErr)
		} else if leader {
			if _, err := w.Store.PruneAuditEvents(ctx); err != nil && ctx.Err() == nil {
				w.Logger.Error("prune audit events", "error", err)
			}
			if _, err := w.Store.PruneAuthenticationRateLimits(ctx, 24*time.Hour); err != nil && ctx.Err() == nil {
				w.Logger.Error("prune authentication rate limits", "error", err)
			}
		}
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

func (w *Worker) scheduleBackups(ctx context.Context) {
	ticker := time.NewTicker(time.Minute)
	defer ticker.Stop()
	for {
		leader, leaseErr := w.Store.AcquireControllerLease(ctx, "backup-scheduler", w.ID, 90*time.Second)
		if leaseErr != nil && ctx.Err() == nil {
			w.Logger.Error("acquire backup scheduler lease", "error", leaseErr)
		} else if leader {
			for ctx.Err() == nil {
				err := w.enqueueDueBackup(ctx)
				if errors.Is(err, store.ErrNotFound) {
					break
				}
				if err != nil {
					w.Logger.Error("schedule backup", "error", err)
					break
				}
			}
		}
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

func (w *Worker) enqueueDueBackup(ctx context.Context) error {
	tx, err := w.Store.Pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	var policyID, databaseID uuid.UUID
	var destinationID *uuid.UUID
	var intervalSeconds, retentionCount int
	var verifyRestore bool
	err = tx.QueryRow(ctx, `SELECT id,database_instance_id,interval_seconds,retention_count,destination_id,verify_restore FROM backup_policies WHERE enabled AND next_run_at<=now() AND (NOT $1 OR destination_id IS NOT NULL) ORDER BY next_run_at FOR UPDATE SKIP LOCKED LIMIT 1`, w.Store.RequireRemoteBackups).Scan(&policyID, &databaseID, &intervalSeconds, &retentionCount, &destinationID, &verifyRestore)
	if errors.Is(err, pgx.ErrNoRows) {
		return store.ErrNotFound
	}
	if err != nil {
		return err
	}
	backupID := uuid.New()
	if _, err = tx.Exec(ctx, `INSERT INTO database_backups(id,database_instance_id,status,format,destination_id) VALUES($1,$2,'queued','native',$3)`, backupID, databaseID, destinationID); err != nil {
		return err
	}
	payload, _ := json.Marshal(map[string]any{"backupId": backupID.String(), "retentionCount": retentionCount, "verifyRestore": verifyRestore})
	if _, err = tx.Exec(ctx, `INSERT INTO jobs(id,kind,payload,resource_key) VALUES($1,'backup.database',$2,$3)`, uuid.New(), payload, "database:"+databaseID.String()); err != nil {
		return err
	}
	_, err = tx.Exec(ctx, `UPDATE backup_policies SET last_run_at=now(),next_run_at=now()+($2::int * interval '1 second'),updated_at=now() WHERE id=$1`, policyID, intervalSeconds)
	if err != nil {
		return err
	}
	return tx.Commit(ctx)
}

func (w *Worker) loop(ctx context.Context) {
	ticker := time.NewTicker(time.Second)
	reaper := time.NewTicker(30 * time.Second)
	defer ticker.Stop()
	defer reaper.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-reaper.C:
			w.recoverStale(ctx)
		case <-ticker.C:
			j, err := w.claim(ctx)
			if errors.Is(err, store.ErrNotFound) {
				continue
			}
			if err != nil {
				w.Logger.Error("claim job", "error", err)
				continue
			}
			started := time.Now()
			jobCtx, span := observability.StartOperation(ctx, j.Kind, j.ID.String())
			jobErr := w.runClaimed(jobCtx, j)
			finishErr := w.finish(ctx, j, jobErr)
			operationErr := errors.Join(jobErr, finishErr)
			observability.EndOperation(span, operationErr)
			status := "succeeded"
			if operationErr != nil {
				status = "failed"
			}
			if w.Metrics != nil {
				w.Metrics.ObserveOperation(j.Kind, status, time.Since(started))
			}
			if finishErr != nil {
				w.Logger.Error("finish job", "error", finishErr)
			}
		}
	}
}

func (w *Worker) recoverStale(ctx context.Context) {
	tx, err := w.Store.Pool.Begin(ctx)
	if err != nil {
		w.Logger.Error("recover stale jobs", "error", err)
		return
	}
	defer tx.Rollback(ctx)
	rows, err := tx.Query(ctx, `SELECT id,kind,payload,cancel_requested_at IS NOT NULL FROM jobs WHERE status='running' AND locked_at < now()-interval '1 minute' FOR UPDATE SKIP LOCKED`)
	if err != nil {
		w.Logger.Error("recover stale jobs", "error", err)
		return
	}
	type expiredJob struct {
		id        uuid.UUID
		kind      string
		payload   json.RawMessage
		cancelled bool
	}
	var expired []expiredJob
	for rows.Next() {
		var item expiredJob
		if err = rows.Scan(&item.id, &item.kind, &item.payload, &item.cancelled); err != nil {
			rows.Close()
			w.Logger.Error("recover stale jobs", "error", err)
			return
		}
		expired = append(expired, item)
	}
	if err = rows.Err(); err != nil {
		rows.Close()
		w.Logger.Error("recover stale jobs", "error", err)
		return
	}
	rows.Close()
	retried := 0
	for _, item := range expired {
		if item.cancelled {
			if err = markCancelledResourceTx(ctx, tx, item.kind, item.payload); err != nil {
				w.Logger.Error("recover stale jobs", "error", err)
				return
			}
			_, err = tx.Exec(ctx, `UPDATE jobs SET status='cancelled',finished_at=now(),locked_at=NULL,locked_by=NULL,lease_id=NULL WHERE id=$1`, item.id)
		} else {
			_, err = tx.Exec(ctx, `UPDATE jobs SET status='pending',locked_at=NULL,locked_by=NULL,lease_id=NULL,run_after=now() WHERE id=$1`, item.id)
			retried++
		}
		if err != nil {
			w.Logger.Error("recover stale jobs", "error", err)
			return
		}
	}
	if err = tx.Commit(ctx); err != nil {
		w.Logger.Error("recover stale jobs", "error", err)
		return
	}
	if retried > 0 {
		w.Logger.Warn("recovered stale jobs", "count", retried)
	}
}

func markCancelledResourceTx(ctx context.Context, tx pgx.Tx, kind string, rawPayload json.RawMessage) error {
	var payload map[string]string
	if json.Unmarshal(rawPayload, &payload) != nil {
		return nil
	}
	var key string
	switch kind {
	case "deploy.compose":
		key = "deploymentId"
	case "backup.database":
		key = "backupId"
	case "restore.database":
		key = "restoreId"
	case "migrate.database":
		key = "migrationId"
	default:
		return nil
	}
	id, err := uuid.Parse(payload[key])
	if err != nil {
		return nil
	}
	var query string
	switch kind {
	case "deploy.compose":
		query = `UPDATE deployments SET status='cancelled',error='cancelled by user',finished_at=now() WHERE id=$1`
	case "backup.database":
		query = `UPDATE database_backups SET status='cancelled',error='cancelled by user',finished_at=now() WHERE id=$1`
	case "restore.database":
		query = `UPDATE database_restores SET status='cancelled',error='cancelled by user',finished_at=now() WHERE id=$1`
	case "migrate.database":
		query = `UPDATE database_migrations SET status='cancelled',error='cancelled by user',finished_at=now() WHERE id=$1`
	}
	_, err = tx.Exec(ctx, query, id)
	return err
}

// runClaimed keeps the lease alive and turns a database cancellation request into
// context cancellation, which also terminates Docker and Git child processes.
func (w *Worker) runClaimed(parent context.Context, j job) error {
	ctx, cancel := context.WithCancel(parent)
	done := make(chan struct{})
	go func() {
		ticker := time.NewTicker(10 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-done:
				return
			case <-ctx.Done():
				return
			case <-ticker.C:
				owned, err := w.renewJobLease(ctx, j)
				if err != nil {
					w.Logger.Error("heartbeat job", "job", j.ID, "error", err)
					continue
				}
				if !owned {
					cancel()
					return
				}
			}
		}
	}()
	err := w.execute(ctx, j)
	close(done)
	cancel()
	return err
}

func (w *Worker) claim(ctx context.Context) (job, error) {
	tx, err := w.Store.Pool.Begin(ctx)
	if err != nil {
		return job{}, err
	}
	defer tx.Rollback(ctx)
	var j job
	err = tx.QueryRow(ctx, `SELECT j.id,j.kind,j.payload,j.attempts,j.max_attempts FROM jobs j WHERE j.status='pending' AND j.cancel_requested_at IS NULL AND j.run_after<=now()
		AND (j.kind<>'deploy.compose' OR NOT EXISTS (SELECT 1 FROM jobs older JOIN deployments old_deployment ON old_deployment.id=(older.payload->>'deploymentId')::uuid JOIN deployments this_deployment ON this_deployment.id=(j.payload->>'deploymentId')::uuid WHERE older.kind='deploy.compose' AND older.status IN ('pending','running') AND old_deployment.compose_service_id=this_deployment.compose_service_id AND older.created_at<j.created_at))
		AND (j.kind<>'commit.status' OR NOT EXISTS (SELECT 1 FROM commit_status_deliveries current_delivery JOIN commit_status_deliveries earlier_delivery ON earlier_delivery.deployment_id=current_delivery.deployment_id JOIN jobs earlier_job ON earlier_job.kind='commit.status' AND earlier_job.payload->>'deliveryId'=earlier_delivery.id::text WHERE current_delivery.id=(j.payload->>'deliveryId')::uuid AND earlier_delivery.created_at<current_delivery.created_at AND earlier_job.status IN ('pending','running')))
		AND (j.resource_key IS NULL OR NOT EXISTS (SELECT 1 FROM jobs resource_job WHERE resource_job.resource_key=j.resource_key AND resource_job.status IN ('pending','running') AND (resource_job.created_at,resource_job.id)<(j.created_at,j.id)))
		ORDER BY j.created_at,j.id FOR UPDATE OF j SKIP LOCKED LIMIT 1`).Scan(&j.ID, &j.Kind, &j.Payload, &j.Attempts, &j.MaxAttempts)
	if errors.Is(err, pgx.ErrNoRows) {
		return job{}, store.ErrNotFound
	}
	if err != nil {
		return job{}, err
	}
	j.LeaseID = uuid.New()
	_, err = tx.Exec(ctx, `UPDATE jobs SET status='running',attempts=attempts+1,locked_at=now(),locked_by=$2,lease_id=$3 WHERE id=$1`, j.ID, w.ID, j.LeaseID)
	if err != nil {
		return job{}, err
	}
	return j, tx.Commit(ctx)
}

func (w *Worker) renewJobLease(ctx context.Context, j job) (bool, error) {
	result, err := w.Store.Pool.Exec(ctx, `UPDATE jobs SET locked_at=now() WHERE id=$1 AND status='running' AND lease_id=$2 AND cancel_requested_at IS NULL`, j.ID, j.LeaseID)
	return result.RowsAffected() == 1, err
}

func (w *Worker) updateResourceForJob(ctx context.Context, j job, query string, args ...any) error {
	return w.Store.WithJobLease(ctx, j.ID, j.LeaseID, func(tx pgx.Tx) error {
		result, err := tx.Exec(ctx, query, args...)
		if err != nil {
			return err
		}
		if result.RowsAffected() != 1 {
			return store.ErrNotFound
		}
		return nil
	})
}

func (w *Worker) execute(ctx context.Context, j job) error {
	if j.Kind == "delete.compose" {
		return w.deleteComposeService(ctx, j)
	}
	if j.Kind == "delete.environment" {
		return w.deleteEnvironment(ctx, j)
	}
	if j.Kind == "delete.project" {
		return w.deleteProject(ctx, j)
	}
	if j.Kind == "delete.cluster" {
		return w.deleteCluster(ctx, j)
	}
	if j.Kind == "backup.database" {
		return w.backupDatabase(ctx, j)
	}
	if j.Kind == "restore.database" {
		return w.restoreDatabase(ctx, j)
	}
	if j.Kind == "migrate.database" {
		return w.migrateDatabase(ctx, j)
	}
	if j.Kind == "notify.webhook" {
		return w.deliverNotification(ctx, j)
	}
	if j.Kind == "commit.status" {
		return w.deliverCommitStatus(ctx, j)
	}
	if j.Kind == "audit.archive" {
		return w.archiveAuditEvents(ctx, j)
	}
	if j.Kind != "deploy.compose" {
		return fmt.Errorf("unsupported job kind %q", j.Kind)
	}
	var payload struct {
		DeploymentID string `json:"deploymentId"`
	}
	if err := json.Unmarshal(j.Payload, &payload); err != nil {
		return err
	}
	id, err := uuid.Parse(payload.DeploymentID)
	if err != nil {
		return err
	}
	var serviceID uuid.UUID
	var stack, compose, encrypted, trigger string
	var clusterID *uuid.UUID
	err = w.Store.WithJobLease(ctx, j.ID, j.LeaseID, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `UPDATE deployments d SET status='running',started_at=now() FROM compose_services s,environments e WHERE d.id=$1 AND s.id=d.compose_service_id AND e.id=s.environment_id RETURNING s.id,s.stack_name,d.compose_snapshot,d.env_snapshot,d.trigger,e.cluster_id`, id).Scan(&serviceID, &stack, &compose, &encrypted, &trigger, &clusterID)
	})
	if err != nil {
		return err
	}
	rows, err := w.Store.Pool.Query(ctx, `SELECT r.id,r.compose_service_id,r.service_name,r.host,r.path_prefix,r.target_port,r.tls,r.certificate_resolver FROM routes r JOIN deployments d ON d.compose_service_id=r.compose_service_id WHERE d.id=$1`, id)
	if err != nil {
		return err
	}
	routes := []store.Route{}
	for rows.Next() {
		var r store.Route
		if err := rows.Scan(&r.ID, &r.ComposeServiceID, &r.ServiceName, &r.Host, &r.PathPrefix, &r.TargetPort, &r.TLS, &r.CertificateResolver); err != nil {
			rows.Close()
			return err
		}
		routes = append(routes, r)
	}
	rows.Close()
	compiled := compose
	if trigger != "reconcile" {
		compiled, err = w.Compiler.Compile(compose, routes)
	}
	if err != nil {
		w.markDeployment(ctx, j, id, "failed", "", err)
		return err
	}
	env := map[string]string{}
	if encrypted != "" {
		plain, e := w.Box.DecryptResource(encrypted, "compose-env", serviceID.String(), "compose-env")
		if e != nil {
			err = e
		} else if e = json.Unmarshal(plain, &env); e != nil {
			err = e
		}
	}
	buildOutput := ""
	var deploymentRegistryCredential *Credential
	if err == nil && trigger != "reconcile" {
		var source store.ApplicationSource
		source.ComposeServiceID = uuid.Nil
		var gitCredentialID, registryCredentialID *uuid.UUID
		var gitKind, gitServer, gitUser, gitSecret, registryServer, registryUser, registrySecret string
		var encryptedArchive *string
		sourceErr := w.Store.Pool.QueryRow(ctx, `SELECT a.compose_service_id,a.source_type,a.repository_url,a.git_ref,a.context_directory,a.dockerfile,a.build_type,a.builder_image,a.output_directory,a.build_target,a.enable_submodules,a.encrypted_build_config,a.target_service,a.registry_image,a.updated_at,gc.id,COALESCE(gc.kind,''),COALESCE(gc.server,''),COALESCE(gc.username,''),COALESCE(gc.encrypted_secret,''),rc.id,COALESCE(rc.server,''),COALESCE(rc.username,''),COALESCE(rc.encrypted_secret,''),x.encrypted_archive FROM application_sources a JOIN deployments d ON d.compose_service_id=a.compose_service_id LEFT JOIN source_credentials gc ON gc.id=a.git_credential_id LEFT JOIN source_credentials rc ON rc.id=a.registry_credential_id LEFT JOIN application_artifacts x ON x.compose_service_id=a.compose_service_id WHERE d.id=$1`, id).Scan(&source.ComposeServiceID, &source.SourceType, &source.RepositoryURL, &source.GitRef, &source.ContextDirectory, &source.Dockerfile, &source.BuildType, &source.BuilderImage, &source.OutputDirectory, &source.BuildTarget, &source.EnableSubmodules, &source.EncryptedBuildConfig, &source.TargetService, &source.RegistryImage, &source.UpdatedAt, &gitCredentialID, &gitKind, &gitServer, &gitUser, &gitSecret, &registryCredentialID, &registryServer, &registryUser, &registrySecret, &encryptedArchive)
		if sourceErr == nil {
			if source.EncryptedBuildConfig != "" {
				plain, decryptErr := w.Box.Decrypt(source.EncryptedBuildConfig, "application-build-config:"+source.ComposeServiceID.String())
				if decryptErr != nil {
					err = decryptErr
				} else {
					var buildConfig store.ApplicationBuildConfig
					if jsonErr := json.Unmarshal(plain, &buildConfig); jsonErr != nil {
						err = jsonErr
					} else {
						source.BuildArguments, source.BuildSecrets = buildConfig.Arguments, buildConfig.Secrets
					}
				}
			}
			credentials := BuildCredentials{Git: Credential{Kind: gitKind, Server: gitServer, Username: gitUser}, Registry: Credential{Kind: "registry", Server: registryServer, Username: registryUser}}
			if gitSecret != "" {
				plain, decryptErr := w.Box.DecryptResource(gitSecret, "source-credential", gitCredentialID.String(), "source-credential")
				if decryptErr != nil {
					err = decryptErr
				} else {
					if gitKind == "git-ssh" {
						var material map[string]string
						if jsonErr := json.Unmarshal(plain, &material); jsonErr != nil {
							err = jsonErr
						} else {
							credentials.Git.Secret, credentials.Git.KnownHosts = material["privateKey"], material["knownHosts"]
						}
					} else {
						credentials.Git.Secret = string(plain)
					}
				}
			}
			if err == nil && registrySecret != "" {
				plain, decryptErr := w.Box.DecryptResource(registrySecret, "source-credential", registryCredentialID.String(), "source-credential")
				if decryptErr != nil {
					err = decryptErr
				} else {
					credentials.Registry.Secret = string(plain)
					credential := credentials.Registry
					deploymentRegistryCredential = &credential
				}
			}
			if err == nil {
				buildCtx, cancel := context.WithTimeout(ctx, 45*time.Minute)
				var tag, output string
				var buildErr error
				if source.SourceType == "drop" {
					if encryptedArchive == nil || *encryptedArchive == "" {
						buildErr = errors.New("uploaded ZIP source is missing")
					} else {
						var archive []byte
						archive, buildErr = w.Box.Decrypt(*encryptedArchive, "application-artifact:"+source.ComposeServiceID.String())
						if buildErr == nil {
							tag, output, buildErr = w.Builder.BuildArchive(buildCtx, source, id, credentials.Registry, archive)
						}
					}
				} else {
					tag, output, buildErr = w.Builder.Build(buildCtx, source, id, credentials)
				}
				cancel()
				buildOutput = output
				if buildErr != nil {
					err = buildErr
				} else {
					compiled, err = SetServiceImage(compiled, source.TargetService, tag)
				}
			}
		} else if !errors.Is(sourceErr, pgx.ErrNoRows) {
			err = sourceErr
		}
	}
	if err == nil {
		if snapshotErr := w.Store.SetDeploymentEffectiveComposeForJob(ctx, j.ID, j.LeaseID, id, compiled); snapshotErr != nil {
			err = snapshotErr
		}
	}
	if err == nil {
		var output string
		output, err = w.scheduler(clusterID).Deploy(ctx, stack, compiled, env, deploymentRegistryCredential)
		w.markDeployment(ctx, j, id, map[bool]string{true: "failed", false: "succeeded"}[err != nil], buildOutput+output, err)
	} else {
		w.markDeployment(ctx, j, id, "failed", buildOutput, err)
	}
	return err
}

func (w *Worker) deleteComposeService(ctx context.Context, j job) error {
	var payload struct {
		ServiceID     string `json:"serviceId"`
		StackName     string `json:"stackName"`
		DeleteVolumes bool   `json:"deleteVolumes"`
	}
	if err := json.Unmarshal(j.Payload, &payload); err != nil {
		return err
	}
	serviceID, err := uuid.Parse(payload.ServiceID)
	if err != nil {
		return err
	}
	var clusterID *uuid.UUID
	if err = w.Store.Pool.QueryRow(ctx, `SELECT e.cluster_id FROM compose_services s JOIN environments e ON e.id=s.environment_id WHERE s.id=$1`, serviceID).Scan(&clusterID); err != nil {
		return err
	}
	if _, err = w.scheduler(clusterID).Remove(ctx, payload.StackName); err != nil {
		return err
	}
	if payload.DeleteVolumes {
		if _, err = w.scheduler(clusterID).RemoveVolumes(ctx, payload.StackName); err != nil {
			return err
		}
	}
	rows, err := w.Store.Pool.Query(ctx, `SELECT b.path,b.destination_id,b.object_key FROM database_backups b JOIN database_instances d ON d.id=b.database_instance_id WHERE d.compose_service_id=$1`, serviceID)
	if err != nil {
		return err
	}
	type backupArtifact struct {
		path, objectKey string
		destinationID   *uuid.UUID
	}
	artifacts := []backupArtifact{}
	for rows.Next() {
		var artifact backupArtifact
		if err = rows.Scan(&artifact.path, &artifact.destinationID, &artifact.objectKey); err != nil {
			rows.Close()
			return err
		}
		artifacts = append(artifacts, artifact)
	}
	rows.Close()
	for _, artifact := range artifacts {
		if artifact.destinationID != nil && artifact.objectKey != "" {
			remote, remoteErr := w.s3(ctx, *artifact.destinationID)
			if remoteErr != nil {
				return remoteErr
			}
			if remoteErr = remote.Delete(ctx, artifact.objectKey); remoteErr != nil {
				return remoteErr
			}
		}
	}
	tx, err := w.Store.Pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	if _, err = tx.Exec(ctx, `DELETE FROM database_instances WHERE compose_service_id=$1`, serviceID); err != nil {
		return err
	}
	tag, err := tx.Exec(ctx, `DELETE FROM compose_services WHERE id=$1`, serviceID)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return nil
	}
	if err = tx.Commit(ctx); err != nil {
		return err
	}
	root := filepath.Clean(w.BackupDirectory)
	for _, artifact := range artifacts {
		if artifact.path == "" {
			continue
		}
		relative, relErr := filepath.Rel(root, filepath.Clean(artifact.path))
		if relErr == nil && relative != ".." && !strings.HasPrefix(relative, ".."+string(filepath.Separator)) {
			_ = os.RemoveAll(filepath.Dir(artifact.path))
		}
	}
	return nil
}

func (w *Worker) deleteEnvironment(ctx context.Context, j job) error {
	var payload struct {
		EnvironmentID string `json:"environmentId"`
	}
	if err := json.Unmarshal(j.Payload, &payload); err != nil {
		return err
	}
	id, err := uuid.Parse(payload.EnvironmentID)
	if err != nil {
		return err
	}
	tag, err := w.Store.Pool.Exec(ctx, `DELETE FROM environments e WHERE e.id=$1 AND e.deletion_requested_at IS NOT NULL AND NOT EXISTS(SELECT 1 FROM compose_services s WHERE s.environment_id=e.id)`, id)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		var exists bool
		if checkErr := w.Store.Pool.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM environments WHERE id=$1)`, id).Scan(&exists); checkErr != nil {
			return checkErr
		}
		if exists {
			return errors.New("environment child finalizers are still running")
		}
	}
	return nil
}

func (w *Worker) deleteProject(ctx context.Context, j job) error {
	var payload struct {
		ProjectID string `json:"projectId"`
	}
	if err := json.Unmarshal(j.Payload, &payload); err != nil {
		return err
	}
	id, err := uuid.Parse(payload.ProjectID)
	if err != nil {
		return err
	}
	tag, err := w.Store.Pool.Exec(ctx, `DELETE FROM projects p WHERE p.id=$1 AND p.deletion_requested_at IS NOT NULL AND NOT EXISTS(SELECT 1 FROM environments e WHERE e.project_id=p.id)`, id)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		var exists bool
		if checkErr := w.Store.Pool.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM projects WHERE id=$1)`, id).Scan(&exists); checkErr != nil {
			return checkErr
		}
		if exists {
			return errors.New("project child finalizers are still running")
		}
	}
	return nil
}

func (w *Worker) deleteCluster(ctx context.Context, j job) error {
	var payload struct {
		ClusterID string `json:"clusterId"`
	}
	if err := json.Unmarshal(j.Payload, &payload); err != nil {
		return err
	}
	id, err := uuid.Parse(payload.ClusterID)
	if err != nil {
		return err
	}
	tag, err := w.Store.Pool.Exec(ctx, `DELETE FROM clusters c WHERE c.id=$1 AND c.deletion_requested_at IS NOT NULL AND NOT EXISTS(SELECT 1 FROM environments e WHERE e.cluster_id=c.id)`, id)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		var exists bool
		if checkErr := w.Store.Pool.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM clusters WHERE id=$1)`, id).Scan(&exists); checkErr != nil {
			return checkErr
		}
		if exists {
			return errors.New("cluster still has assigned environments")
		}
	}
	return nil
}

func (w *Worker) scheduler(clusterID *uuid.UUID) Scheduler {
	if clusterID != nil && w.RemoteScheduler != nil {
		return w.RemoteScheduler(*clusterID)
	}
	return w.Swarm
}

func (w *Worker) backupDatabase(ctx context.Context, j job) error {
	var payload struct {
		BackupID       string `json:"backupId"`
		RetentionCount int    `json:"retentionCount"`
		VerifyRestore  bool   `json:"verifyRestore"`
	}
	if err := json.Unmarshal(j.Payload, &payload); err != nil {
		return err
	}
	backupID, err := uuid.Parse(payload.BackupID)
	if err != nil {
		return err
	}
	var databaseID uuid.UUID
	var engine, version, stackName, serviceName, encrypted string
	var destinationID *uuid.UUID
	var clusterID *uuid.UUID
	err = w.Store.WithJobLease(ctx, j.ID, j.LeaseID, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `UPDATE database_backups b SET status='running',started_at=now() FROM database_instances d,compose_services s,environments e WHERE b.id=$1 AND d.id=b.database_instance_id AND s.id=d.compose_service_id AND e.id=s.environment_id RETURNING d.id,d.engine,d.version,s.stack_name,d.slug,d.encrypted_credentials,b.destination_id,e.cluster_id`, backupID).Scan(&databaseID, &engine, &version, &stackName, &serviceName, &encrypted, &destinationID, &clusterID)
	})
	if err != nil {
		return err
	}
	plain, err := w.Box.DecryptResource(encrypted, "database-credentials", databaseID.String(), "database-credentials")
	if err != nil {
		return w.failBackup(ctx, j, backupID, err)
	}
	credentials := map[string]string{}
	if err = json.Unmarshal(plain, &credentials); err != nil {
		return w.failBackup(ctx, j, backupID, err)
	}
	extension, supported := w.Databases.BackupExtension(engine)
	if !supported {
		return w.failBackup(ctx, j, backupID, fmt.Errorf("verified backups are not implemented for database engine %q", engine))
	}
	filename := backupID.String() + "." + extension
	plan, err := w.Databases.Backup(engine, version, serviceName, credentials, filename)
	if err != nil {
		return w.failBackup(ctx, j, backupID, err)
	}
	if err = database.ValidateUtilityPlan(plan); err != nil {
		return w.failBackup(ctx, j, backupID, err)
	}
	if clusterID != nil {
		remote, ok := w.scheduler(clusterID).(RemoteSwarm)
		if !ok {
			return w.failBackup(ctx, j, backupID, errors.New("remote cluster scheduler does not support artifact transport"))
		}
		return w.backupDatabaseRemote(ctx, j, backupID, serviceName, stackName, filename, plan, destinationID, payload.RetentionCount, payload.VerifyRestore, remote)
	}
	directory := filepath.Join(w.BackupDirectory, backupID.String())
	if err = os.MkdirAll(directory, 0700); err != nil {
		return w.failBackup(ctx, j, backupID, err)
	}
	keepLocalArtifact := false
	defer func() {
		if !keepLocalArtifact {
			_ = os.RemoveAll(directory)
		}
	}()
	if err = writePlanFiles(directory, plan.Files); err != nil {
		return w.failBackup(ctx, j, backupID, err)
	}
	defer removePlanFiles(directory, plan.Files)
	jobCtx, cancel := context.WithTimeout(ctx, 30*time.Minute)
	defer cancel()
	_, err = w.Swarm.RunContainerJob(jobCtx, stackName+"_default", plan.Image, directory, plan.Environment, plan.Command)
	if err != nil {
		return w.failBackup(ctx, j, backupID, err)
	}
	plainPath := filepath.Join(directory, filename)
	defer os.Remove(plainPath)
	plainSum, _, err := checksumFile(plainPath)
	if err != nil {
		return w.failBackup(ctx, j, backupID, err)
	}
	encryptedPath := plainPath + ".enc"
	dataKey := make([]byte, 32)
	if _, err = rand.Read(dataKey); err != nil {
		return w.failBackup(ctx, j, backupID, err)
	}
	artifactBox, err := cryptox.New(dataKey)
	if err != nil {
		return w.failBackup(ctx, j, backupID, err)
	}
	wrappedDataKey, err := w.Box.Encrypt(dataKey, "backup-data-key:"+backupID.String())
	clear(dataKey)
	if err != nil {
		return w.failBackup(ctx, j, backupID, err)
	}
	if err = encryptBackupFile(artifactBox, plainPath, encryptedPath, backupID); err != nil {
		return w.failBackup(ctx, j, backupID, err)
	}
	if err = os.Remove(plainPath); err != nil {
		return w.failBackup(ctx, j, backupID, fmt.Errorf("remove plaintext backup: %w", err))
	}
	sum, size, err := checksumFile(encryptedPath)
	if err != nil {
		return w.failBackup(ctx, j, backupID, err)
	}
	storedPath, objectKey := encryptedPath, ""
	var remote *backupstore.S3
	if destinationID != nil {
		var remoteErr error
		remote, remoteErr = w.s3(ctx, *destinationID)
		if remoteErr != nil {
			return w.failBackup(ctx, j, backupID, remoteErr)
		}
		objectKey = remote.ObjectKey(serviceName + "/" + filename + ".enc")
		if remoteErr = remote.Put(ctx, objectKey, encryptedPath); remoteErr != nil {
			return w.failBackup(ctx, j, backupID, remoteErr)
		}
		storedPath = ""
	}
	err = w.updateResourceForJob(ctx, j, `UPDATE database_backups SET status='succeeded',path=$2,object_key=$3,size_bytes=$4,sha256=$5,encrypted=true,plaintext_sha256=$6,encrypted_data_key=$7,finished_at=now() WHERE id=$1`, backupID, storedPath, objectKey, size, sum, plainSum, wrappedDataKey)
	if err != nil {
		// The object is not referenced until the metadata update commits. Remove
		// it with a fresh context when cancellation or a transient database error
		// happens after a successful upload.
		if remote != nil {
			cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cleanupCancel()
			if cleanupErr := remote.Delete(cleanupCtx, objectKey); cleanupErr != nil {
				w.Logger.Error("delete uncommitted remote backup", "backup", backupID, "error", cleanupErr)
			}
		}
		return err
	}
	if remote == nil {
		keepLocalArtifact = true
	}
	if payload.RetentionCount > 0 {
		w.pruneBackups(ctx, backupID, payload.RetentionCount)
	}
	if payload.VerifyRestore {
		if err = w.queueRestoreDrill(ctx, backupID); err != nil {
			return err
		}
	}
	return nil
}

func (w *Worker) backupDatabaseRemote(ctx context.Context, j job, backupID uuid.UUID, serviceName, stackName, filename string, plan database.BackupPlan, destinationID *uuid.UUID, retention int, verify bool, remote RemoteSwarm) error {
	if destinationID == nil {
		return w.failBackup(ctx, j, backupID, errors.New("remote database backups require an S3-compatible destination"))
	}
	storage, err := w.s3(ctx, *destinationID)
	if err != nil {
		return w.failBackup(ctx, j, backupID, err)
	}
	objectKey := storage.ObjectKey(serviceName + "/" + filename + ".enc")
	putURL, err := storage.PresignedPut(ctx, objectKey, time.Hour)
	if err != nil {
		return w.failBackup(ctx, j, backupID, err)
	}
	dataKey := make([]byte, 32)
	if _, err = rand.Read(dataKey); err != nil {
		return w.failBackup(ctx, j, backupID, err)
	}
	wrapped, err := w.Box.Encrypt(dataKey, "backup-data-key:"+backupID.String())
	if err != nil {
		clear(dataKey)
		return w.failBackup(ctx, j, backupID, err)
	}
	result, err := remote.RunArtifactJob(ctx, RemoteArtifactJob{Mode: "upload", Network: stackName + "_default", Image: plan.Image, Environment: plan.Environment, Command: plan.Command, Files: plan.Files, ArtifactName: filename, TransferURL: putURL, EncryptionKey: base64.RawStdEncoding.EncodeToString(dataKey), EncryptionAAD: "database-backup:" + backupID.String()})
	clear(dataKey)
	if err != nil {
		return w.failBackup(ctx, j, backupID, err)
	}
	err = w.updateResourceForJob(ctx, j, `UPDATE database_backups SET status='succeeded',path='',object_key=$2,size_bytes=$3,sha256=$4,encrypted=true,plaintext_sha256=$5,encrypted_data_key=$6,finished_at=now() WHERE id=$1`, backupID, objectKey, result.SizeBytes, result.SHA256, result.PlaintextSHA256, wrapped)
	if err != nil {
		cleanupCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		_ = storage.Delete(cleanupCtx, objectKey)
		return err
	}
	if retention > 0 {
		w.pruneBackups(ctx, backupID, retention)
	}
	if verify {
		return w.queueRestoreDrill(ctx, backupID)
	}
	return nil
}

func (w *Worker) queueRestoreDrill(ctx context.Context, backupID uuid.UUID) error {
	restoreID := uuid.New()
	payload, _ := json.Marshal(map[string]string{"restoreId": restoreID.String()})
	_, err := w.Store.Pool.Exec(ctx, `WITH inserted AS (INSERT INTO database_restores(id,database_backup_id,status,kind) VALUES($1,$2,'queued','drill') ON CONFLICT(database_backup_id) WHERE kind='drill' DO NOTHING RETURNING id), target AS (SELECT database_instance_id FROM database_backups WHERE id=$2) INSERT INTO jobs(id,kind,payload,resource_key) SELECT $3,'restore.database',$4,'database:' || target.database_instance_id::text FROM inserted CROSS JOIN target`, restoreID, backupID, uuid.New(), payload)
	return err
}

func (w *Worker) pruneBackups(ctx context.Context, newestID uuid.UUID, keep int) {
	rows, err := w.Store.Pool.Query(ctx, `SELECT old.id,old.path,old.destination_id,old.object_key FROM database_backups old JOIN database_backups newest ON newest.database_instance_id=old.database_instance_id WHERE newest.id=$1 AND old.status='succeeded' AND NOT EXISTS (SELECT 1 FROM database_restores r WHERE r.database_backup_id=old.id AND r.kind='manual') ORDER BY old.created_at DESC OFFSET $2`, newestID, keep)
	if err != nil {
		w.Logger.Error("select expired backups", "error", err)
		return
	}
	type expired struct {
		id              uuid.UUID
		path, objectKey string
		destinationID   *uuid.UUID
	}
	items := []expired{}
	for rows.Next() {
		var item expired
		if err = rows.Scan(&item.id, &item.path, &item.destinationID, &item.objectKey); err == nil {
			items = append(items, item)
		}
	}
	rows.Close()
	for _, item := range items {
		tx, txErr := w.Store.Pool.Begin(ctx)
		if txErr != nil {
			w.Logger.Error("prune backup metadata", "backup", item.id, "error", txErr)
			continue
		}
		if _, txErr = tx.Exec(ctx, `DELETE FROM database_restores WHERE database_backup_id=$1 AND kind='drill'`, item.id); txErr == nil {
			var deleted uuid.UUID
			txErr = tx.QueryRow(ctx, `DELETE FROM database_backups WHERE id=$1 AND NOT EXISTS (SELECT 1 FROM database_restores WHERE database_backup_id=$1) RETURNING id`, item.id).Scan(&deleted)
		}
		if txErr == nil {
			txErr = tx.Commit(ctx)
		} else {
			_ = tx.Rollback(ctx)
		}
		if txErr != nil {
			if !errors.Is(txErr, pgx.ErrNoRows) {
				w.Logger.Error("prune backup metadata", "backup", item.id, "error", txErr)
			}
			continue
		}
		if item.destinationID != nil && item.objectKey != "" {
			remote, remoteErr := w.s3(ctx, *item.destinationID)
			if remoteErr == nil {
				remoteErr = remote.Delete(ctx, item.objectKey)
			}
			if remoteErr != nil {
				w.Logger.Error("delete expired remote backup", "backup", item.id, "error", remoteErr)
				continue
			}
		}
		if item.path != "" {
			_ = os.RemoveAll(filepath.Dir(item.path))
		}
	}
}

func (w *Worker) failBackup(ctx context.Context, j job, id uuid.UUID, backupErr error) error {
	query := `UPDATE database_backups SET status='failed',error=$2,finished_at=now() WHERE id=$1`
	if j.Attempts+1 < j.MaxAttempts {
		query = `UPDATE database_backups SET status='running',error=$2,finished_at=NULL WHERE id=$1`
	}
	if err := w.updateResourceForJob(ctx, j, query, id, truncate(backupErr.Error(), 8192)); err != nil {
		return errors.Join(backupErr, err)
	}
	return backupErr
}

func (w *Worker) restoreDatabase(ctx context.Context, j job) error {
	var payload struct {
		RestoreID string `json:"restoreId"`
	}
	if err := json.Unmarshal(j.Payload, &payload); err != nil {
		return err
	}
	restoreID, err := uuid.Parse(payload.RestoreID)
	if err != nil {
		return err
	}
	var backupID, databaseID uuid.UUID
	var kind, engine, version, stackName, serviceName, encryptedCredentials, path, expectedHash, plaintextHash, encryptedDataKey, objectKey string
	var artifactEncrypted bool
	var expectedSize *int64
	var destinationID *uuid.UUID
	var clusterID *uuid.UUID
	err = w.Store.WithJobLease(ctx, j.ID, j.LeaseID, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `UPDATE database_restores r SET status='running',started_at=now() FROM database_backups b,database_instances d,compose_services s,environments e WHERE r.id=$1 AND b.id=r.database_backup_id AND d.id=b.database_instance_id AND s.id=d.compose_service_id AND e.id=s.environment_id RETURNING r.kind,b.id,d.id,d.engine,d.version,s.stack_name,d.slug,d.encrypted_credentials,b.path,b.sha256,b.size_bytes,b.encrypted,b.plaintext_sha256,b.encrypted_data_key,b.destination_id,b.object_key,e.cluster_id`, restoreID).Scan(&kind, &backupID, &databaseID, &engine, &version, &stackName, &serviceName, &encryptedCredentials, &path, &expectedHash, &expectedSize, &artifactEncrypted, &plaintextHash, &encryptedDataKey, &destinationID, &objectKey, &clusterID)
	})
	if err != nil {
		return err
	}
	if clusterID != nil {
		remote, ok := w.scheduler(clusterID).(RemoteSwarm)
		if !ok {
			return w.failRestore(ctx, j, restoreID, errors.New("remote cluster scheduler does not support artifact transport"))
		}
		return w.restoreDatabaseRemote(ctx, j, restoreID, backupID, databaseID, kind, engine, version, stackName, serviceName, encryptedCredentials, expectedHash, plaintextHash, encryptedDataKey, objectKey, expectedSize, destinationID, artifactEncrypted, remote)
	}
	cleanRoot := filepath.Clean(w.BackupDirectory)
	cleanPath := filepath.Clean(path)
	if destinationID != nil {
		directory := filepath.Join(cleanRoot, "restore-"+restoreID.String())
		if err = os.MkdirAll(directory, 0700); err != nil {
			return w.failRestore(ctx, j, restoreID, err)
		}
		defer os.RemoveAll(directory)
		cleanPath = filepath.Join(directory, filepath.Base(objectKey))
		remote, remoteErr := w.s3(ctx, *destinationID)
		if remoteErr != nil {
			return w.failRestore(ctx, j, restoreID, remoteErr)
		}
		if remoteErr = remote.Get(ctx, objectKey, cleanPath); remoteErr != nil {
			return w.failRestore(ctx, j, restoreID, remoteErr)
		}
	}
	relative, err := filepath.Rel(cleanRoot, cleanPath)
	if err != nil || strings.HasPrefix(relative, "..") {
		return w.failRestore(ctx, j, restoreID, errors.New("backup path escapes configured directory"))
	}
	actualHash, _, err := checksumFile(cleanPath)
	if err != nil {
		return w.failRestore(ctx, j, restoreID, err)
	}
	if actualHash != expectedHash {
		return w.failRestore(ctx, j, restoreID, errors.New("backup checksum mismatch"))
	}
	if artifactEncrypted {
		dataKey, keyErr := w.Box.Decrypt(encryptedDataKey, "backup-data-key:"+backupID.String())
		if keyErr != nil {
			return w.failRestore(ctx, j, restoreID, keyErr)
		}
		artifactBox, keyErr := cryptox.New(dataKey)
		clear(dataKey)
		if keyErr != nil {
			return w.failRestore(ctx, j, restoreID, keyErr)
		}
		decryptedPath := strings.TrimSuffix(cleanPath, ".enc")
		if decryptedPath == cleanPath {
			decryptedPath += ".plain"
		}
		if err = decryptBackupFile(artifactBox, cleanPath, decryptedPath, backupID); err != nil {
			return w.failRestore(ctx, j, restoreID, err)
		}
		defer os.Remove(decryptedPath)
		cleanPath = decryptedPath
		if actualPlainHash, _, hashErr := checksumFile(cleanPath); hashErr != nil || actualPlainHash != plaintextHash {
			if hashErr == nil {
				hashErr = errors.New("backup plaintext checksum mismatch")
			}
			return w.failRestore(ctx, j, restoreID, hashErr)
		}
	}
	credentials := map[string]string{}
	if kind == "drill" {
		drillName := "verify"
		rendered, renderErr := w.Databases.Render(engine, database.Request{Name: drillName, Version: version})
		if renderErr != nil {
			return w.failRestore(ctx, j, restoreID, renderErr)
		}
		drillStack := "drill-" + strings.Split(restoreID.String(), "-")[0]
		if _, err = w.Swarm.Deploy(ctx, drillStack, rendered.ComposeYAML, rendered.Environment, nil); err != nil {
			return w.failRestore(ctx, j, restoreID, err)
		}
		defer func() {
			cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), 2*time.Minute)
			defer cleanupCancel()
			if _, cleanupErr := w.Swarm.Remove(cleanupCtx, drillStack); cleanupErr != nil {
				w.Logger.Error("remove restore drill stack", "stack", drillStack, "error", cleanupErr)
			}
		}()
		stackName, serviceName, credentials = drillStack, drillName, rendered.Credentials
		readiness, readinessErr := w.Databases.Readiness(engine, version, serviceName, credentials)
		if readinessErr != nil {
			return w.failRestore(ctx, j, restoreID, readinessErr)
		}
		ready := false
		for attempt := 0; attempt < 12; attempt++ {
			if _, readinessErr = w.Swarm.RunContainerJob(ctx, stackName+"_default", readiness.Image, "", readiness.Environment, readiness.Command); readinessErr == nil {
				ready = true
				break
			}
			select {
			case <-ctx.Done():
				return w.failRestore(ctx, j, restoreID, ctx.Err())
			case <-time.After(5 * time.Second):
			}
		}
		if !ready {
			return w.failRestore(ctx, j, restoreID, fmt.Errorf("restore drill database did not become ready: %w", readinessErr))
		}
	} else {
		plain, decryptErr := w.Box.DecryptResource(encryptedCredentials, "database-credentials", databaseID.String(), "database-credentials")
		if decryptErr != nil {
			return w.failRestore(ctx, j, restoreID, decryptErr)
		}
		if err = json.Unmarshal(plain, &credentials); err != nil {
			return w.failRestore(ctx, j, restoreID, err)
		}
	}
	plan, err := w.Databases.Restore(engine, version, serviceName, credentials, filepath.Base(cleanPath))
	if err != nil {
		return w.failRestore(ctx, j, restoreID, err)
	}
	if err = database.ValidateUtilityPlan(plan); err != nil {
		return w.failRestore(ctx, j, restoreID, err)
	}
	if err = writePlanFiles(filepath.Dir(cleanPath), plan.Files); err != nil {
		return w.failRestore(ctx, j, restoreID, err)
	}
	defer removePlanFiles(filepath.Dir(cleanPath), plan.Files)
	jobCtx, cancel := context.WithTimeout(ctx, 30*time.Minute)
	defer cancel()
	_, err = w.Swarm.RunContainerJob(jobCtx, stackName+"_default", plan.Image, filepath.Dir(cleanPath), plan.Environment, plan.Command)
	if err != nil {
		return w.failRestore(ctx, j, restoreID, err)
	}
	err = w.updateResourceForJob(ctx, j, `UPDATE database_restores SET status='succeeded',finished_at=now() WHERE id=$1`, restoreID)
	return err
}

func (w *Worker) restoreDatabaseRemote(ctx context.Context, j job, restoreID, backupID, databaseID uuid.UUID, kind, engine, version, stackName, serviceName, encryptedCredentials, expectedHash, plaintextHash, encryptedDataKey, objectKey string, expectedSize *int64, destinationID *uuid.UUID, encrypted bool, remote RemoteSwarm) error {
	if destinationID == nil || objectKey == "" || !encrypted {
		return w.failRestore(ctx, j, restoreID, errors.New("remote restores require an encrypted S3 backup"))
	}
	storage, err := w.s3(ctx, *destinationID)
	if err != nil {
		return w.failRestore(ctx, j, restoreID, err)
	}
	getURL, err := storage.PresignedGet(ctx, objectKey, time.Hour)
	if err != nil {
		return w.failRestore(ctx, j, restoreID, err)
	}
	dataKey, err := w.Box.Decrypt(encryptedDataKey, "backup-data-key:"+backupID.String())
	if err != nil {
		return w.failRestore(ctx, j, restoreID, err)
	}
	defer clear(dataKey)
	credentials := map[string]string{}
	if kind == "drill" {
		drillName := "verify"
		rendered, renderErr := w.Databases.Render(engine, database.Request{Name: drillName, Version: version})
		if renderErr != nil {
			return w.failRestore(ctx, j, restoreID, renderErr)
		}
		drillStack := "drill-" + strings.Split(restoreID.String(), "-")[0]
		if _, err = remote.Deploy(ctx, drillStack, rendered.ComposeYAML, rendered.Environment, nil); err != nil {
			return w.failRestore(ctx, j, restoreID, err)
		}
		defer func() {
			cleanupCtx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
			defer cancel()
			if _, cleanupErr := remote.Remove(cleanupCtx, drillStack); cleanupErr != nil {
				w.Logger.Error("remove remote restore drill stack", "stack", drillStack, "error", cleanupErr)
			}
		}()
		stackName, serviceName, credentials = drillStack, drillName, rendered.Credentials
		readiness, readinessErr := w.Databases.Readiness(engine, version, serviceName, credentials)
		if readinessErr != nil {
			return w.failRestore(ctx, j, restoreID, readinessErr)
		}
		ready := false
		for attempt := 0; attempt < 12; attempt++ {
			if _, readinessErr = remote.RunContainerJob(ctx, stackName+"_default", readiness.Image, "", readiness.Environment, readiness.Command); readinessErr == nil {
				ready = true
				break
			}
			select {
			case <-ctx.Done():
				return w.failRestore(ctx, j, restoreID, ctx.Err())
			case <-time.After(5 * time.Second):
			}
		}
		if !ready {
			return w.failRestore(ctx, j, restoreID, fmt.Errorf("remote restore drill database did not become ready: %w", readinessErr))
		}
	} else {
		plain, decryptErr := w.Box.DecryptResource(encryptedCredentials, "database-credentials", databaseID.String(), "database-credentials")
		if decryptErr != nil {
			return w.failRestore(ctx, j, restoreID, decryptErr)
		}
		if err = json.Unmarshal(plain, &credentials); err != nil {
			return w.failRestore(ctx, j, restoreID, err)
		}
	}
	artifactName := strings.TrimSuffix(filepath.Base(objectKey), ".enc")
	plan, err := w.Databases.Restore(engine, version, serviceName, credentials, artifactName)
	if err != nil {
		return w.failRestore(ctx, j, restoreID, err)
	}
	size := int64(0)
	if expectedSize != nil {
		size = *expectedSize
	}
	_, err = remote.RunArtifactJob(ctx, RemoteArtifactJob{Mode: "download", Network: stackName + "_default", Image: plan.Image, Environment: plan.Environment, Command: plan.Command, Files: plan.Files, ArtifactName: artifactName, TransferURL: getURL, EncryptionKey: base64.RawStdEncoding.EncodeToString(dataKey), EncryptionAAD: "database-backup:" + backupID.String(), SHA256: expectedHash, PlaintextSHA256: plaintextHash, SizeBytes: size})
	if err != nil {
		return w.failRestore(ctx, j, restoreID, err)
	}
	err = w.updateResourceForJob(ctx, j, `UPDATE database_restores SET status='succeeded',finished_at=now() WHERE id=$1`, restoreID)
	return err
}

type databaseTransferRunner interface {
	RunDatabaseTransfer(context.Context, DatabaseTransferJob) (DatabaseTransferResult, error)
}

func (w *Worker) migrateDatabase(ctx context.Context, j job) error {
	var payload struct {
		MigrationID string `json:"migrationId"`
	}
	if err := json.Unmarshal(j.Payload, &payload); err != nil {
		return err
	}
	migrationID, err := uuid.Parse(payload.MigrationID)
	if err != nil {
		return err
	}
	var databaseID uuid.UUID
	var sourceEngine, sourceVersion, sourceHost, encryptedSource, targetEngine, targetVersion, targetHost, encryptedTarget, stackName, databaseStatus string
	var clusterID *uuid.UUID
	err = w.Store.WithJobLease(ctx, j.ID, j.LeaseID, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `UPDATE database_migrations m SET status='running',started_at=COALESCE(started_at,now()),error='' FROM database_instances d,compose_services s,environments e WHERE m.id=$1 AND d.id=m.database_instance_id AND s.id=d.compose_service_id AND e.id=d.environment_id RETURNING d.id,m.source_engine,m.source_version,m.source_host,m.encrypted_source_config,d.engine,d.version,d.slug,d.encrypted_credentials,s.stack_name,d.status,e.cluster_id`, migrationID).Scan(&databaseID, &sourceEngine, &sourceVersion, &sourceHost, &encryptedSource, &targetEngine, &targetVersion, &targetHost, &encryptedTarget, &stackName, &databaseStatus, &clusterID)
	})
	if err != nil {
		return err
	}
	redactions := map[string]string{}
	fail := func(cause error) error {
		return w.failDatabaseMigration(ctx, j, migrationID, redactBuildError(cause, redactions))
	}
	if sourceEngine != targetEngine {
		return fail(fmt.Errorf("source engine %q does not match target engine %q", sourceEngine, targetEngine))
	}
	if databaseStatus != "running" {
		return fail(errors.New("target database must have a successful deployment before data migration"))
	}
	if w.Databases == nil {
		return fail(errors.New("database registry is not configured"))
	}
	sourcePlain, err := w.Box.Decrypt(encryptedSource, "database-migration-source:"+migrationID.String())
	if err != nil {
		return fail(err)
	}
	defer clear(sourcePlain)
	var sourceConnection database.SourceConnection
	if err = json.Unmarshal(sourcePlain, &sourceConnection); err != nil {
		return fail(err)
	}
	redactions["sourcePassword"] = sourceConnection.Password
	targetPlain, err := w.Box.DecryptResource(encryptedTarget, "database-credentials", databaseID.String(), "database-credentials")
	if err != nil {
		return fail(err)
	}
	targetCredentials := map[string]string{}
	if err = json.Unmarshal(targetPlain, &targetCredentials); err != nil {
		clear(targetPlain)
		return fail(err)
	}
	clear(targetPlain)
	redactions["targetPassword"] = targetCredentials["password"]
	sourceCredentials := map[string]string{"username": sourceConnection.Username, "password": sourceConnection.Password, "database": sourceConnection.Database}
	if sourceConnection.Port > 0 {
		sourceCredentials["port"] = fmt.Sprint(sourceConnection.Port)
	}
	extension, supported := w.Databases.BackupExtension(sourceEngine)
	if !supported {
		return fail(fmt.Errorf("native data migration is not implemented for database engine %q", sourceEngine))
	}
	artifactName := migrationID.String() + "." + extension
	backupPlan, err := w.Databases.Backup(sourceEngine, sourceVersion, sourceHost, sourceCredentials, artifactName)
	if err != nil {
		return fail(err)
	}
	restorePlan, err := w.Databases.Restore(targetEngine, targetVersion, targetHost, targetCredentials, artifactName)
	if err != nil {
		return fail(err)
	}
	scheduler := w.scheduler(clusterID)
	readiness, err := w.Databases.Readiness(targetEngine, targetVersion, targetHost, targetCredentials)
	if err != nil {
		return fail(err)
	}
	if _, err = scheduler.RunContainerJob(ctx, stackName+"_default", readiness.Image, "", readiness.Environment, readiness.Command); err != nil {
		return fail(fmt.Errorf("target database is not ready: %w", err))
	}
	runner, ok := scheduler.(databaseTransferRunner)
	if !ok {
		return fail(errors.New("target scheduler does not support database transfer"))
	}
	transferCtx, cancel := context.WithTimeout(ctx, 2*time.Hour)
	result, transferErr := runner.RunDatabaseTransfer(transferCtx, DatabaseTransferJob{Network: stackName + "_default", ArtifactName: artifactName, Backup: backupPlan, Restore: restorePlan})
	cancel()
	output := truncate(redactBuildText(result.Output, redactions), 64<<10)
	if transferErr != nil {
		return fail(transferErr)
	}
	if result.SizeBytes <= 0 || !regexp.MustCompile(`^[a-f0-9]{64}$`).MatchString(result.SHA256) {
		return fail(errors.New("database transfer returned invalid checksum evidence"))
	}
	return w.updateResourceForJob(ctx, j, `UPDATE database_migrations SET status='succeeded',size_bytes=$2,sha256=$3,output=$4,error='',finished_at=now() WHERE id=$1`, migrationID, result.SizeBytes, result.SHA256, output)
}

func (w *Worker) failDatabaseMigration(ctx context.Context, j job, id uuid.UUID, migrationErr error) error {
	query := `UPDATE database_migrations SET status='failed',error=$2,finished_at=now() WHERE id=$1`
	if j.Attempts+1 < j.MaxAttempts {
		// Keep the migration active while its durable job is waiting to retry.
		// This preserves the one-transfer-per-target fence for destructive restores.
		query = `UPDATE database_migrations SET status='running',error=$2,finished_at=NULL WHERE id=$1`
	}
	if err := w.updateResourceForJob(ctx, j, query, id, truncate(migrationErr.Error(), 8192)); err != nil {
		return errors.Join(migrationErr, err)
	}
	return migrationErr
}

func (w *Worker) s3(ctx context.Context, id uuid.UUID) (*backupstore.S3, error) {
	var endpoint, region, bucket, prefix, encrypted string
	var useTLS bool
	err := w.Store.Pool.QueryRow(ctx, `SELECT endpoint,region,bucket,prefix,use_tls,encrypted_credentials FROM backup_destinations WHERE id=$1`, id).Scan(&endpoint, &region, &bucket, &prefix, &useTLS, &encrypted)
	if err != nil {
		return nil, err
	}
	plain, err := w.Box.DecryptResource(encrypted, "backup-destination", id.String(), "backup-destination")
	if err != nil {
		return nil, err
	}
	var credentials map[string]string
	if err = json.Unmarshal(plain, &credentials); err != nil {
		return nil, err
	}
	return backupstore.NewS3(backupstore.S3Config{Endpoint: endpoint, Region: region, Bucket: bucket, Prefix: prefix, UseTLS: useTLS, AccessKey: credentials["accessKey"], SecretKey: credentials["secretKey"], SessionToken: credentials["sessionToken"]})
}
func (w *Worker) failRestore(ctx context.Context, j job, id uuid.UUID, restoreErr error) error {
	query := `UPDATE database_restores SET status='failed',error=$2,finished_at=now() WHERE id=$1`
	if j.Attempts+1 < j.MaxAttempts {
		query = `UPDATE database_restores SET status='running',error=$2,finished_at=NULL WHERE id=$1`
	}
	if err := w.updateResourceForJob(ctx, j, query, id, truncate(restoreErr.Error(), 8192)); err != nil {
		return errors.Join(restoreErr, err)
	}
	return restoreErr
}

func (w *Worker) markDeployment(ctx context.Context, j job, id uuid.UUID, status, output string, deployErr error) {
	message := ""
	if deployErr != nil {
		message = deployErr.Error()
	}
	if err := w.Store.FinishDeploymentForJob(ctx, j.ID, j.LeaseID, id, status, output, message); err != nil {
		w.Logger.Error("finish deployment", "deployment", id, "error", err)
	}
}

func (w *Worker) finish(ctx context.Context, j job, jobErr error) error {
	tx, err := w.Store.Pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	var cancellationRequested bool
	if err = tx.QueryRow(ctx, `SELECT cancel_requested_at IS NOT NULL FROM jobs WHERE id=$1 AND status='running' AND lease_id=$2 FOR UPDATE`, j.ID, j.LeaseID).Scan(&cancellationRequested); errors.Is(err, pgx.ErrNoRows) {
		return store.ErrLeaseLost
	} else if err != nil {
		return err
	}
	var query string
	var args []any
	if cancellationRequested {
		query = `UPDATE jobs SET status='cancelled',finished_at=now(),locked_at=NULL,locked_by=NULL,lease_id=NULL WHERE id=$1 AND status='running' AND lease_id=$2`
		args = []any{j.ID, j.LeaseID}
	} else if jobErr == nil {
		query = `UPDATE jobs SET status='succeeded',finished_at=now(),locked_at=NULL,locked_by=NULL,lease_id=NULL WHERE id=$1 AND status='running' AND lease_id=$2`
		args = []any{j.ID, j.LeaseID}
	} else if j.Attempts+1 < j.MaxAttempts {
		query = `UPDATE jobs SET status='pending',run_after=now()+($3::int * interval '15 seconds'),last_error=$4,locked_at=NULL,locked_by=NULL,lease_id=NULL WHERE id=$1 AND status='running' AND lease_id=$2`
		args = []any{j.ID, j.LeaseID, j.Attempts + 1, truncate(jobErr.Error(), 8192)}
	} else {
		query = `UPDATE jobs SET status='failed',last_error=$3,finished_at=now(),locked_at=NULL,locked_by=NULL,lease_id=NULL WHERE id=$1 AND status='running' AND lease_id=$2`
		args = []any{j.ID, j.LeaseID, truncate(jobErr.Error(), 8192)}
	}
	result, err := tx.Exec(ctx, query, args...)
	if err != nil {
		return err
	}
	if result.RowsAffected() != 1 {
		return store.ErrLeaseLost
	}
	if cancellationRequested {
		if err = markCancelledResourceTx(ctx, tx, j.Kind, j.Payload); err != nil {
			return err
		}
	}
	if err = tx.Commit(ctx); err != nil {
		return err
	}
	if cancellationRequested && j.Kind == "deploy.compose" {
		var payload map[string]string
		if json.Unmarshal(j.Payload, &payload) == nil {
			if deploymentID, parseErr := uuid.Parse(payload["deploymentId"]); parseErr == nil {
				if statusErr := w.Store.QueueCommitStatus(ctx, deploymentID, "error"); statusErr != nil {
					w.Logger.Error("queue cancelled deployment status", "deployment", deploymentID, "error", statusErr)
				}
			}
		}
	}
	if jobErr != nil && j.Attempts+1 >= j.MaxAttempts && j.Kind != "notify.webhook" {
		if notificationErr := w.Store.QueueFailureNotifications(ctx, j.Kind, j.Payload, jobErr); notificationErr != nil {
			w.Logger.Error("queue failure notification", "job", j.ID, "error", notificationErr)
		}
	}
	return nil
}

func (w *Worker) deliverNotification(ctx context.Context, j job) error {
	var payload struct {
		DeliveryID string `json:"deliveryId"`
	}
	if err := json.Unmarshal(j.Payload, &payload); err != nil {
		return err
	}
	id, err := uuid.Parse(payload.DeliveryID)
	if err != nil {
		return err
	}
	delivery, endpoint, err := w.Store.GetNotificationDeliveryForJob(ctx, j.ID, j.LeaseID, id)
	if err != nil {
		return err
	}
	urlBytes, err := w.Box.Decrypt(endpoint.EncryptedURL, "notification-url:"+endpoint.ID.String())
	if err != nil {
		return errors.Join(err, w.Store.FinishNotificationDeliveryForJob(ctx, j.ID, j.LeaseID, id, 0, err))
	}
	secret, err := w.Box.Decrypt(endpoint.EncryptedSecret, "notification-secret:"+endpoint.ID.String())
	if err != nil {
		return errors.Join(err, w.Store.FinishNotificationDeliveryForJob(ctx, j.ID, j.LeaseID, id, 0, err))
	}
	var code int
	switch endpoint.Kind {
	case "webhook", "slack":
		code, err = sendNotification(ctx, w.notificationClient(), string(urlBytes), secret, delivery)
	case "pagerduty", "opsgenie":
		code, err = sendIncidentNotification(ctx, w.notificationClient(), endpoint.Kind, string(urlBytes), string(secret), delivery)
	case "smtp":
		code, err = sendSMTPNotificationWithTLS(ctx, string(urlBytes), secret, delivery, w.notificationTLS)
	default:
		err = fmt.Errorf("unsupported notification endpoint kind %q", endpoint.Kind)
	}
	return errors.Join(err, w.Store.FinishNotificationDeliveryForJob(ctx, j.ID, j.LeaseID, id, code, err))
}

func (w *Worker) notificationClient() *http.Client {
	if w.NotificationClient != nil {
		return w.NotificationClient
	}
	return &http.Client{Timeout: 15 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return errors.New("notification redirects are disabled") }}
}

func sendNotification(ctx context.Context, client *http.Client, endpointURL string, secret []byte, delivery store.NotificationDelivery) (int, error) {
	timestamp := fmt.Sprintf("%d", time.Now().Unix())
	mac := hmac.New(sha256.New, secret)
	_, _ = mac.Write([]byte(timestamp + "."))
	_, _ = mac.Write(delivery.Payload)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpointURL, bytes.NewReader(delivery.Payload))
	if err != nil {
		return 0, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "Dockyard-Notifications/1.0")
	req.Header.Set("X-Dockyard-Event", delivery.EventType)
	req.Header.Set("X-Dockyard-Delivery", delivery.ID.String())
	req.Header.Set("X-Dockyard-Timestamp", timestamp)
	req.Header.Set("X-Dockyard-Signature-256", "sha256="+hex.EncodeToString(mac.Sum(nil)))
	response, err := client.Do(req)
	code := 0
	if response != nil {
		code = response.StatusCode
		_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, 64<<10))
		_ = response.Body.Close()
	}
	if err == nil && (code < 200 || code >= 300) {
		err = fmt.Errorf("notification endpoint returned HTTP %d", code)
	}
	return code, err
}

func truncate(value string, max int) string {
	value = strings.TrimSpace(value)
	if len(value) > max {
		return value[:max]
	}
	return value
}

func checksumFile(path string) (string, int64, error) {
	file, err := os.Open(path)
	if err != nil {
		return "", 0, err
	}
	defer file.Close()
	hash := sha256.New()
	size, err := io.Copy(hash, file)
	if err != nil {
		return "", 0, err
	}
	return hex.EncodeToString(hash.Sum(nil)), size, nil
}

func encryptBackupFile(box *cryptox.Box, source, destination string, backupID uuid.UUID) error {
	input, err := os.Open(source)
	if err != nil {
		return err
	}
	defer input.Close()
	return writeEncryptedBackup(box, input, destination, "database-backup:"+backupID.String(), true)
}

func decryptBackupFile(box *cryptox.Box, source, destination string, backupID uuid.UUID) error {
	input, err := os.Open(source)
	if err != nil {
		return err
	}
	defer input.Close()
	return writeEncryptedBackup(box, input, destination, "database-backup:"+backupID.String(), false)
}

func writeEncryptedBackup(box *cryptox.Box, input io.Reader, destination, context string, encrypt bool) (err error) {
	temporary := destination + ".tmp"
	_ = os.Remove(temporary)
	output, err := os.OpenFile(temporary, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	closed := false
	defer func() {
		if !closed {
			if closeErr := output.Close(); err == nil {
				err = closeErr
			}
		}
		if err != nil {
			_ = os.Remove(temporary)
		}
	}()
	if encrypt {
		err = box.EncryptStream(output, input, context)
	} else {
		err = box.DecryptStream(output, input, context)
	}
	if err != nil {
		return err
	}
	if err = output.Sync(); err != nil {
		return err
	}
	if err = output.Close(); err != nil {
		return err
	}
	closed = true
	return os.Rename(temporary, destination)
}

func writePlanFiles(directory string, files map[string]string) error {
	if err := database.ValidateUtilityFiles(files); err != nil {
		return err
	}
	names := make([]string, 0, len(files))
	for name := range files {
		names = append(names, name)
	}
	sort.Strings(names)
	created := make([]string, 0, len(names))
	for _, name := range names {
		path := filepath.Join(directory, name)
		file, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
		if err == nil {
			created = append(created, path)
			_, err = io.WriteString(file, files[name])
			if closeErr := file.Close(); err == nil {
				err = closeErr
			}
		}
		if err != nil {
			for _, createdPath := range created {
				_ = os.Remove(createdPath)
			}
			return err
		}
	}
	return nil
}

func removePlanFiles(directory string, files map[string]string) {
	if database.ValidateUtilityFiles(files) != nil {
		return
	}
	for name := range files {
		_ = os.Remove(filepath.Join(directory, name))
	}
}
