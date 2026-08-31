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
	"github.com/bendahma/dokploy-go/internal/netpolicy"
	"github.com/bendahma/dokploy-go/internal/observability"
	"github.com/bendahma/dokploy-go/internal/store"
	"github.com/bendahma/dokploy-go/internal/volumeartifact"
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
	EgressPolicy       *netpolicy.Policy
	EgressTransport    http.RoundTripper
	// notificationTLS lets conformance tests trust an isolated SMTP server
	// without weakening the system trust store used in production.
	notificationTLS *tls.Config
	RemoteScheduler func(uuid.UUID) Scheduler
	LocalEdgeProxy  EdgeProxySpec
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
	wg.Add(7)
	go func() { defer wg.Done(); w.scheduleBackups(ctx) }()
	go func() { defer wg.Done(); w.scheduleServiceCommands(ctx) }()
	go func() { defer wg.Done(); w.pruneAuditEvents(ctx) }()
	go func() { defer wg.Done(); w.scheduleAuditArchives(ctx) }()
	go func() { defer wg.Done(); w.scheduleBackupArtifactCleanup(ctx) }()
	go func() { defer wg.Done(); w.reconcileStacks(ctx) }()
	go func() { defer wg.Done(); w.scheduleEdgeCertificateReconciliation(ctx) }()
	for i := 0; i < w.Concurrency; i++ {
		wg.Add(1)
		go func() { defer wg.Done(); w.loop(ctx) }()
	}
	<-ctx.Done()
	wg.Wait()
}

func (w *Worker) scheduleEdgeCertificateReconciliation(ctx context.Context) {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()
	for {
		leader, err := w.Store.AcquireControllerLease(ctx, "edge-certificate-scheduler", w.ID, 90*time.Second)
		if err != nil && ctx.Err() == nil {
			w.Logger.Error("acquire edge certificate scheduler lease", "error", err)
		} else if leader {
			if _, err = w.Store.QueueAllEdgeCertificateReconciliations(ctx); err != nil {
				w.Logger.Error("schedule edge certificate reconciliation", "error", err)
			}
		}
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

func (w *Worker) scheduleServiceCommands(ctx context.Context) {
	ticker := time.NewTicker(time.Minute)
	defer ticker.Stop()
	for {
		leader, err := w.Store.AcquireControllerLease(ctx, "service-command-scheduler", w.ID, 90*time.Second)
		if err != nil && ctx.Err() == nil {
			w.Logger.Error("acquire service command scheduler lease", "error", err)
		} else if leader {
			for queued := 0; queued < 100 && ctx.Err() == nil; queued++ {
				_, queueErr := w.Store.QueueNextDueServiceSchedule(ctx, time.Now())
				if errors.Is(queueErr, store.ErrNotFound) {
					break
				}
				if queueErr != nil {
					w.Logger.Error("schedule service command", "error", queueErr)
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
			for ctx.Err() == nil {
				err := w.enqueueDueVolumeBackup(ctx)
				if errors.Is(err, store.ErrNotFound) {
					break
				}
				if err != nil {
					w.Logger.Error("schedule volume backup", "error", err)
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

func (w *Worker) scheduleBackupArtifactCleanup(ctx context.Context) {
	ticker := time.NewTicker(time.Minute)
	defer ticker.Stop()
	for {
		leader, err := w.Store.AcquireControllerLease(ctx, "backup-artifact-cleaner", w.ID, 90*time.Second)
		if err != nil && ctx.Err() == nil {
			w.Logger.Error("acquire backup artifact cleanup lease", "error", err)
		} else if leader {
			for processed := 0; processed < 100 && ctx.Err() == nil; processed++ {
				found, cleanupErr := w.cleanupNextBackupArtifact(ctx)
				if cleanupErr != nil {
					w.Logger.Error("delete queued backup artifact", "error", cleanupErr)
				}
				if !found {
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

type backupArtifactDeletion struct {
	id            uuid.UUID
	destinationID uuid.UUID
	objectKey     string
	attempts      int
}

func (w *Worker) cleanupNextBackupArtifact(ctx context.Context) (bool, error) {
	var item backupArtifactDeletion
	err := w.Store.Pool.QueryRow(ctx, `SELECT id,destination_id,object_key,attempts FROM backup_artifact_deletions WHERE next_attempt_at<=now() ORDER BY next_attempt_at,id LIMIT 1`).Scan(&item.id, &item.destinationID, &item.objectKey, &item.attempts)
	if errors.Is(err, pgx.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	storage, err := w.s3(ctx, item.destinationID)
	if err != nil {
		return true, w.deferBackupArtifactDeletion(ctx, item, err)
	}
	return true, w.deleteQueuedBackupArtifact(ctx, item, storage)
}

func (w *Worker) deleteQueuedBackupArtifact(ctx context.Context, item backupArtifactDeletion, storage *backupstore.S3) error {
	if err := storage.Delete(ctx, item.objectKey); err != nil {
		return w.deferBackupArtifactDeletion(ctx, item, err)
	}
	_, err := w.Store.Pool.Exec(ctx, `DELETE FROM backup_artifact_deletions WHERE id=$1`, item.id)
	return err
}

func (w *Worker) deferBackupArtifactDeletion(ctx context.Context, item backupArtifactDeletion, deleteErr error) error {
	delay := 15 * time.Second * time.Duration(1<<min(item.attempts, 8))
	if delay > time.Hour {
		delay = time.Hour
	}
	_, recordErr := w.Store.Pool.Exec(ctx, `UPDATE backup_artifact_deletions SET attempts=attempts+1,next_attempt_at=$2,last_error=$3,updated_at=now() WHERE id=$1`, item.id, time.Now().Add(delay), truncate(deleteErr.Error(), 2048))
	return errors.Join(deleteErr, recordErr)
}

func (w *Worker) enqueueDueVolumeBackup(ctx context.Context) error {
	tx, err := w.Store.Pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	var policyID, serviceID, destinationID uuid.UUID
	var volumeName, nodeID string
	var intervalSeconds, retentionCount int
	var quiesce bool
	err = tx.QueryRow(ctx, `SELECT policy.id,policy.compose_service_id,policy.volume_name,policy.destination_id,policy.interval_seconds,policy.retention_count,service.storage_node_id,policy.quiesce
		FROM volume_backup_policies policy
		JOIN compose_services service ON service.id=policy.compose_service_id
		WHERE policy.enabled AND policy.next_run_at<=now() AND service.storage_node_id<>'' AND service.deletion_requested_at IS NULL AND service.desired_state='running'
			AND NOT EXISTS(SELECT 1 FROM volume_backups backup WHERE backup.compose_service_id=service.id AND backup.volume_name=policy.volume_name AND backup.status IN ('queued','running'))
			AND NOT EXISTS(SELECT 1 FROM jobs job WHERE job.resource_key='service:' || service.id::text AND job.kind='backup.volume' AND job.status IN ('pending','running'))
		ORDER BY policy.next_run_at FOR UPDATE OF policy,service SKIP LOCKED LIMIT 1`).Scan(&policyID, &serviceID, &volumeName, &destinationID, &intervalSeconds, &retentionCount, &nodeID, &quiesce)
	if errors.Is(err, pgx.ErrNoRows) {
		return store.ErrNotFound
	}
	if err != nil {
		return err
	}
	backupID := uuid.New()
	if _, err = tx.Exec(ctx, `INSERT INTO volume_backups(id,volume_backup_policy_id,compose_service_id,volume_name,storage_node_id,destination_id,quiesce,status) VALUES($1,$2,$3,$4,$5,$6,$7,'queued')`, backupID, policyID, serviceID, volumeName, nodeID, destinationID, quiesce); err != nil {
		return err
	}
	payload, _ := json.Marshal(map[string]any{"backupId": backupID.String(), "retentionCount": retentionCount})
	if _, err = tx.Exec(ctx, `INSERT INTO jobs(id,kind,payload,resource_key) VALUES($1,'backup.volume',$2,$3)`, uuid.New(), payload, "service:"+serviceID.String()); err != nil {
		return err
	}
	if _, err = tx.Exec(ctx, `UPDATE volume_backup_policies SET last_run_at=now(),next_run_at=now()+($2::int * interval '1 second'),updated_at=now() WHERE id=$1`, policyID, intervalSeconds); err != nil {
		return err
	}
	return tx.Commit(ctx)
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
			if _, err := w.Store.PruneAIAuditRuns(ctx); err != nil && ctx.Err() == nil {
				w.Logger.Error("prune AI audit runs", "error", err)
			}
			if _, err := w.Store.PruneAuthenticationRateLimits(ctx, 24*time.Hour); err != nil && ctx.Err() == nil {
				w.Logger.Error("prune authentication rate limits", "error", err)
			}
			if _, err := w.Store.PruneExpiredCredentials(ctx, store.DefaultCredentialRetention); err != nil && ctx.Err() == nil {
				w.Logger.Error("prune expired credentials", "error_type", fmt.Sprintf("%T", err))
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
	var composeServiceID *uuid.UUID
	var destinationID *uuid.UUID
	var intervalSeconds, retentionCount int
	var verifyRestore bool
	err = tx.QueryRow(ctx, `SELECT policy.id,policy.database_instance_id,policy.interval_seconds,policy.retention_count,policy.destination_id,policy.verify_restore,database.compose_service_id
		FROM backup_policies policy
		JOIN database_instances database ON database.id=policy.database_instance_id
		JOIN environments environment ON environment.id=database.environment_id
		JOIN projects project ON project.id=environment.project_id
		WHERE policy.enabled AND policy.next_run_at<=now() AND (NOT $1 OR policy.destination_id IS NOT NULL)
			AND environment.deletion_requested_at IS NULL AND project.deletion_requested_at IS NULL
			AND (database.compose_service_id IS NULL OR EXISTS(SELECT 1 FROM compose_services service WHERE service.id=database.compose_service_id AND service.deletion_requested_at IS NULL AND service.desired_state='running'))
			AND NOT EXISTS(SELECT 1 FROM database_backups backup WHERE backup.database_instance_id=database.id AND backup.status IN ('queued','running'))
			AND NOT EXISTS(SELECT 1 FROM jobs job WHERE job.resource_key='database:' || database.id::text AND job.kind='backup.database' AND job.status IN ('pending','running'))
		ORDER BY policy.next_run_at FOR UPDATE OF policy,database SKIP LOCKED LIMIT 1`, w.Store.RequireRemoteBackups).Scan(&policyID, &databaseID, &intervalSeconds, &retentionCount, &destinationID, &verifyRestore, &composeServiceID)
	if errors.Is(err, pgx.ErrNoRows) {
		return store.ErrNotFound
	}
	if err != nil {
		return err
	}
	if composeServiceID != nil {
		var lockedServiceID uuid.UUID
		if err = tx.QueryRow(ctx, `SELECT id FROM compose_services WHERE id=$1 AND deletion_requested_at IS NULL AND desired_state='running' FOR UPDATE`, *composeServiceID).Scan(&lockedServiceID); errors.Is(err, pgx.ErrNoRows) {
			return store.ErrNotFound
		} else if err != nil {
			return err
		}
	}
	var parentsActive bool
	if err = tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM database_instances database JOIN environments environment ON environment.id=database.environment_id JOIN projects project ON project.id=environment.project_id WHERE database.id=$1 AND environment.deletion_requested_at IS NULL AND project.deletion_requested_at IS NULL)`, databaseID).Scan(&parentsActive); err != nil {
		return err
	}
	if !parentsActive {
		return store.ErrNotFound
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
			if w.Metrics != nil && errors.Is(jobErr, ErrBuildWorkspaceLimit) {
				w.Metrics.ObserveBuildWorkspaceLimitRejection()
			}
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
		if item.kind == "run.service-schedule" {
			var payload map[string]string
			if json.Unmarshal(item.payload, &payload) == nil {
				if executionID, parseErr := uuid.Parse(payload["executionId"]); parseErr == nil {
					status, message := "failed", "worker lease expired; command was not retried to avoid duplicate side effects"
					if item.cancelled {
						status, message = "cancelled", "cancelled by user"
					}
					if _, err = tx.Exec(ctx, `UPDATE service_schedule_executions SET status=$2,error=$3,finished_at=now() WHERE id=$1 AND status IN ('queued','running')`, executionID, status, message); err != nil {
						w.Logger.Error("recover stale scheduled command", "error", err)
						return
					}
				}
			}
			jobStatus := "failed"
			if item.cancelled {
				jobStatus = "cancelled"
			}
			_, err = tx.Exec(ctx, `UPDATE jobs SET status=$2,last_error='worker lease expired',finished_at=now(),locked_at=NULL,locked_by=NULL,lease_id=NULL WHERE id=$1`, item.id, jobStatus)
			if err != nil {
				w.Logger.Error("recover stale scheduled command", "error", err)
				return
			}
			continue
		}
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
	case "backup.volume":
		key = "backupId"
	case "restore.volume":
		key = "restoreId"
	case "migrate.database":
		key = "migrationId"
	case "run.service-schedule":
		key = "executionId"
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
	case "backup.volume":
		query = `UPDATE volume_backups SET status='cancelled',error='cancelled by user',finished_at=now() WHERE id=$1`
	case "restore.volume":
		query = `UPDATE volume_restores SET status='cancelled',error='cancelled by user',finished_at=now() WHERE id=$1`
	case "migrate.database":
		query = `UPDATE database_migrations SET status='cancelled',error='cancelled by user',finished_at=now() WHERE id=$1`
	case "run.service-schedule":
		query = `UPDATE service_schedule_executions SET status='cancelled',error='cancelled by user',finished_at=now() WHERE id=$1 AND status IN ('queued','running','failed')`
	}
	_, err = tx.Exec(ctx, query, id)
	return err
}

// runClaimed keeps the lease alive and turns a database cancellation request into
// context cancellation, which also terminates Docker and Git child processes.
func (w *Worker) runClaimed(parent context.Context, j job) error {
	ctx, cancel := context.WithCancel(parent)
	ctx = withRemoteCommandOwner(ctx, j.ID, j.LeaseID)
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
	if j.Kind == "run.service-schedule" {
		return w.runServiceSchedule(ctx, j)
	}
	if j.Kind == "stop.compose" {
		return w.stopComposeService(ctx, j)
	}
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
	if j.Kind == "network.create" {
		return w.createManagedNetwork(ctx, j)
	}
	if j.Kind == "network.delete" {
		return w.deleteManagedNetwork(ctx, j)
	}
	if j.Kind == "edge-certificates.reconcile" {
		return w.reconcileEdgeCertificates(ctx, j)
	}
	if j.Kind == "backup.database" {
		return w.backupDatabase(ctx, j)
	}
	if j.Kind == "restore.database" {
		return w.restoreDatabase(ctx, j)
	}
	if j.Kind == "backup.volume" {
		return w.backupVolume(ctx, j)
	}
	if j.Kind == "restore.volume" {
		return w.restoreVolume(ctx, j)
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
	var organizationID uuid.UUID
	err = w.Store.WithJobLease(ctx, j.ID, j.LeaseID, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `UPDATE deployments d SET status='running',started_at=now() FROM compose_services s,environments e,projects p WHERE d.id=$1 AND s.id=d.compose_service_id AND e.id=s.environment_id AND p.id=e.project_id RETURNING s.id,s.stack_name,d.compose_snapshot,d.env_snapshot,d.trigger,e.cluster_id,p.organization_id`, id).Scan(&serviceID, &stack, &compose, &encrypted, &trigger, &clusterID, &organizationID)
	})
	if err != nil {
		return err
	}
	rows, err := w.Store.Pool.Query(ctx, `SELECT r.id,r.compose_service_id,r.service_name,r.host,r.path_prefix,r.internal_path,r.strip_path,NOT r.enabled,r.redirect_regex,r.redirect_replacement,r.redirect_permanent,r.target_port,r.tls,r.certificate_resolver,r.custom_certificate_id,r.created_at,r.updated_at FROM routes r JOIN deployments d ON d.compose_service_id=r.compose_service_id WHERE d.id=$1`, id)
	if err != nil {
		return err
	}
	routes := []store.Route{}
	for rows.Next() {
		var r store.Route
		if err := rows.Scan(&r.ID, &r.ComposeServiceID, &r.ServiceName, &r.Host, &r.PathPrefix, &r.InternalPath, &r.StripPath, &r.Disabled, &r.RedirectRegex, &r.RedirectReplacement, &r.RedirectPermanent, &r.TargetPort, &r.TLS, &r.CertificateResolver, &r.CustomCertificateID, &r.CreatedAt, &r.UpdatedAt); err != nil {
			rows.Close()
			return err
		}
		r.Enabled = !r.Disabled
		routes = append(routes, r)
	}
	if err = rows.Err(); err != nil {
		rows.Close()
		return err
	}
	rows.Close()
	customCertificatesRequired := false
	for _, route := range routes {
		if !route.Disabled && route.CustomCertificateID != nil {
			customCertificatesRequired = true
			break
		}
	}
	if customCertificatesRequired {
		if err = w.waitForEdgeCertificates(ctx, clusterID, 90*time.Second); err != nil {
			w.markDeployment(ctx, j, id, "failed", "", err)
			return err
		}
	}
	authRows, err := w.Store.Pool.Query(ctx, `SELECT username,password_hash FROM route_basic_auth_users WHERE compose_service_id=$1 ORDER BY username,id`, serviceID)
	if err != nil {
		return err
	}
	authUsers := []string{}
	for authRows.Next() {
		var username, passwordHash string
		if err = authRows.Scan(&username, &passwordHash); err != nil {
			authRows.Close()
			return err
		}
		authUsers = append(authUsers, username+":"+passwordHash)
	}
	if err = authRows.Err(); err != nil {
		authRows.Close()
		return err
	}
	authRows.Close()
	for index := range routes {
		routes[index].BasicAuthUsers = authUsers
	}
	compiled := compose
	immutableReplay := trigger == "reconcile" || trigger == "rollback"
	if !immutableReplay {
		var managedNetworks []store.ManagedNetworkAttachment
		managedNetworks, err = w.Store.ListServiceNetworkAttachments(ctx, organizationID, serviceID)
		if err == nil {
			attachments := make([]ManagedNetworkAttachment, 0, len(managedNetworks))
			for _, network := range managedNetworks {
				if network.Status != "ready" {
					err = fmt.Errorf("managed network %s is %s", network.Name, network.Status)
					break
				}
				attachments = append(attachments, ManagedNetworkAttachment{Name: network.Name, ServiceNames: network.ServiceNames})
			}
			if err == nil {
				compiled, err = w.Compiler.CompileWithNetworkAttachments(compose, routes, attachments)
			}
		}
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
	if err == nil && !immutableReplay {
		var source store.ApplicationSource
		source.ComposeServiceID = uuid.Nil
		var gitCredentialID, registryCredentialID *uuid.UUID
		var gitKind, gitServer, gitUser, gitSecret, registryServer, registryUser, registrySecret string
		var encryptedArchive *string
		sourceErr := w.Store.Pool.QueryRow(ctx, `SELECT a.compose_service_id,a.source_type,a.repository_url,a.git_ref,a.context_directory,a.dockerfile,a.build_type,a.builder_image,a.output_directory,a.build_target,a.enable_submodules,a.encrypted_build_config,a.target_service,a.registry_image,a.updated_at,gc.id,COALESCE(gc.kind,''),COALESCE(gc.server,''),COALESCE(gc.username,''),COALESCE(gc.encrypted_secret,''),d.registry_credential_id,d.registry_credential_server,d.registry_credential_username,d.encrypted_registry_credential,x.encrypted_archive FROM application_sources a JOIN deployments d ON d.compose_service_id=a.compose_service_id LEFT JOIN source_credentials gc ON gc.id=a.git_credential_id LEFT JOIN application_artifacts x ON x.compose_service_id=a.compose_service_id WHERE d.id=$1`, id).Scan(&source.ComposeServiceID, &source.SourceType, &source.RepositoryURL, &source.GitRef, &source.ContextDirectory, &source.Dockerfile, &source.BuildType, &source.BuilderImage, &source.OutputDirectory, &source.BuildTarget, &source.EnableSubmodules, &source.EncryptedBuildConfig, &source.TargetService, &source.RegistryImage, &source.UpdatedAt, &gitCredentialID, &gitKind, &gitServer, &gitUser, &gitSecret, &registryCredentialID, &registryServer, &registryUser, &registrySecret, &encryptedArchive)
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
	if err == nil && immutableReplay {
		deploymentRegistryCredential, err = w.registryCredentialForDeployment(ctx, id)
	}
	if err == nil {
		compiled, err = w.pinPersistentStorage(ctx, serviceID, stack, compiled, clusterID)
	}
	if err == nil {
		var result DeploymentResult
		result, err = w.scheduler(clusterID).Deploy(ctx, stack, compiled, env, deploymentRegistryCredential)
		if err == nil {
			var effective string
			effective, err = ApplyResolvedImages(compiled, result.ResolvedImages)
			if err == nil {
				err = w.Store.SetDeploymentEffectiveComposeForJob(ctx, j.ID, j.LeaseID, id, effective)
			}
		}
		w.markDeployment(ctx, j, id, map[bool]string{true: "failed", false: "succeeded"}[err != nil], buildOutput+result.Output, err)
	} else {
		w.markDeployment(ctx, j, id, "failed", buildOutput, err)
	}
	return err
}

func (w *Worker) runServiceSchedule(ctx context.Context, j job) error {
	var payload struct {
		ExecutionID string `json:"executionId"`
	}
	if err := json.Unmarshal(j.Payload, &payload); err != nil {
		return err
	}
	executionID, err := uuid.Parse(payload.ExecutionID)
	if err != nil {
		return err
	}
	var stackName, targetService, shell, command string
	var timeoutSeconds int
	var clusterID *uuid.UUID
	err = w.Store.WithJobLease(ctx, j.ID, j.LeaseID, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `UPDATE service_schedule_executions execution SET status='running',started_at=now(),error='' FROM compose_services service,environments environment WHERE execution.id=$1 AND execution.compose_service_id=service.id AND environment.id=service.environment_id AND execution.status='queued' AND service.desired_state='running' AND service.deletion_requested_at IS NULL RETURNING service.stack_name,execution.target_service,execution.shell,execution.command,execution.timeout_seconds,environment.cluster_id`, executionID).Scan(&stackName, &targetService, &shell, &command, &timeoutSeconds, &clusterID)
	})
	if err != nil {
		return err
	}
	runner, ok := w.scheduler(clusterID).(ServiceCommandRunner)
	if !ok {
		err = errors.New("scheduler does not support service commands")
	} else {
		runCtx, cancel := context.WithTimeout(ctx, time.Duration(timeoutSeconds)*time.Second)
		output, runErr := runner.RunServiceCommand(runCtx, stackName, targetService, shell, command)
		cancel()
		status := "succeeded"
		message := ""
		if runErr != nil {
			status, message = "failed", runErr.Error()
		}
		finalizeCtx, finalizeCancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
		finishErr := w.updateResourceForJob(finalizeCtx, j, `UPDATE service_schedule_executions SET status=$2,output=$3,error=$4,finished_at=now() WHERE id=$1 AND status='running'`, executionID, status, truncate(output, MaxRemoteCommandOutputBytes), truncate(message, MaxRemoteCommandErrorBytes))
		finalizeCancel()
		if finishErr != nil {
			return errors.Join(runErr, finishErr)
		}
		return runErr
	}
	finalizeCtx, finalizeCancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
	finishErr := w.updateResourceForJob(finalizeCtx, j, `UPDATE service_schedule_executions SET status='failed',error=$2,finished_at=now() WHERE id=$1 AND status='running'`, executionID, truncate(err.Error(), MaxRemoteCommandErrorBytes))
	finalizeCancel()
	return errors.Join(err, finishErr)
}

func (w *Worker) stopComposeService(ctx context.Context, j job) error {
	var payload struct {
		ServiceID      string `json:"serviceId"`
		StackName      string `json:"stackName"`
		OrganizationID string `json:"organizationId"`
	}
	if err := json.Unmarshal(j.Payload, &payload); err != nil {
		return err
	}
	serviceID, err := uuid.Parse(payload.ServiceID)
	if err != nil {
		return err
	}
	organizationID, err := uuid.Parse(payload.OrganizationID)
	if err != nil {
		return err
	}
	var clusterID *uuid.UUID
	if err = w.Store.Pool.QueryRow(ctx, `SELECT e.cluster_id FROM compose_services s JOIN environments e ON e.id=s.environment_id WHERE s.id=$1`, serviceID).Scan(&clusterID); err != nil {
		return err
	}
	output, err := w.scheduler(clusterID).Remove(ctx, payload.StackName)
	if err != nil {
		return err
	}
	return w.Store.WithJobLease(ctx, j.ID, j.LeaseID, func(tx pgx.Tx) error {
		tag, updateErr := tx.Exec(ctx, `UPDATE compose_services SET updated_at=now() WHERE id=$1`, serviceID)
		if updateErr != nil {
			return updateErr
		}
		if tag.RowsAffected() != 1 {
			return store.ErrNotFound
		}
		if _, updateErr = tx.Exec(ctx, `UPDATE database_instances SET status='stopped',updated_at=now() WHERE compose_service_id=$1`, serviceID); updateErr != nil {
			return updateErr
		}
		_, updateErr = tx.Exec(ctx, `INSERT INTO audit_events(organization_id,action,resource_type,resource_id,metadata)
			SELECT $1,'service.stop.completed','compose_service',$2,jsonb_build_object('jobId',$3::text,'output',$4::text)
			WHERE NOT EXISTS(SELECT 1 FROM audit_events WHERE action='service.stop.completed' AND resource_type='compose_service' AND resource_id=$2 AND metadata->>'jobId'=$3::text)`, organizationID, serviceID.String(), j.ID, truncate(output, 8192))
		return updateErr
	})
}

func (w *Worker) registryCredentialForDeployment(ctx context.Context, deploymentID uuid.UUID) (*Credential, error) {
	var id *uuid.UUID
	var server, username, encrypted string
	err := w.Store.Pool.QueryRow(ctx, `SELECT registry_credential_id,registry_credential_server,registry_credential_username,encrypted_registry_credential FROM deployments WHERE id=$1`, deploymentID).Scan(&id, &server, &username, &encrypted)
	if err != nil {
		return nil, err
	}
	if id == nil {
		return nil, nil
	}
	plain, err := w.Box.DecryptResource(encrypted, "source-credential", id.String(), "source-credential")
	if err != nil {
		return nil, err
	}
	return &Credential{Kind: "registry", Server: server, Username: username, Secret: string(plain)}, nil
}

func (w *Worker) pinPersistentStorage(ctx context.Context, serviceID uuid.UUID, stack, compose string, clusterID *uuid.UUID) (string, error) {
	var databaseID *uuid.UUID
	var serviceNodeID, databaseNodeID string
	var protected bool
	err := w.Store.Pool.QueryRow(ctx, `SELECT s.storage_node_id,d.id,COALESCE(d.storage_node_id,''),d.id IS NOT NULL OR EXISTS(SELECT 1 FROM volume_backup_policies policy WHERE policy.compose_service_id=s.id) FROM compose_services s LEFT JOIN database_instances d ON d.compose_service_id=s.id WHERE s.id=$1`, serviceID).Scan(&serviceNodeID, &databaseID, &databaseNodeID, &protected)
	if err != nil {
		return "", err
	}
	if !protected {
		return compose, nil
	}
	hasVolumes, err := HasNamedVolumes(compose)
	if err != nil {
		return "", err
	}
	if !hasVolumes {
		return compose, nil
	}
	if serviceNodeID != "" && databaseNodeID != "" && serviceNodeID != databaseNodeID {
		return "", store.ErrStorageNodeMismatch
	}
	storageNodeID := serviceNodeID
	if storageNodeID == "" {
		storageNodeID = databaseNodeID
	}
	if storageNodeID == "" {
		resolver, ok := w.scheduler(clusterID).(StorageNodeResolver)
		if !ok {
			return "", errors.New("scheduler does not support durable database placement")
		}
		storageNodeID, err = resolver.ResolveStorageNode(ctx, stack)
		storageNodeID = strings.TrimSpace(storageNodeID)
		if err != nil {
			return "", fmt.Errorf("resolve database storage node: %w", err)
		}
		if err = w.Store.BindPersistentStorageNode(ctx, serviceID, databaseID, storageNodeID); err != nil {
			return "", fmt.Errorf("bind persistent storage node: %w", err)
		}
	}
	pinned, _, err := PinNamedVolumes(compose, storageNodeID)
	if err != nil {
		return "", fmt.Errorf("pin database storage: %w", err)
	}
	return pinned, nil
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
	rows, err := w.Store.Pool.Query(ctx, `SELECT b.id,'database',b.path,b.destination_id,b.object_key FROM database_backups b JOIN database_instances d ON d.id=b.database_instance_id WHERE d.compose_service_id=$1
		UNION ALL
		SELECT backup.id,'volume','',backup.destination_id,backup.object_key FROM volume_backups backup WHERE backup.compose_service_id=$1 AND backup.status='succeeded' AND backup.object_key<>''`, serviceID)
	if err != nil {
		return err
	}
	type backupArtifact struct {
		id, cleanupID   uuid.UUID
		sourceKind      string
		path, objectKey string
		destinationID   *uuid.UUID
	}
	artifacts := []backupArtifact{}
	for rows.Next() {
		var artifact backupArtifact
		if err = rows.Scan(&artifact.id, &artifact.sourceKind, &artifact.path, &artifact.destinationID, &artifact.objectKey); err != nil {
			rows.Close()
			return err
		}
		artifacts = append(artifacts, artifact)
	}
	rows.Close()
	tx, err := w.Store.Pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	for index := range artifacts {
		artifact := &artifacts[index]
		if artifact.destinationID == nil || artifact.objectKey == "" {
			continue
		}
		artifact.cleanupID = uuid.New()
		if err = tx.QueryRow(ctx, `INSERT INTO backup_artifact_deletions(id,destination_id,object_key,source_kind,source_id) VALUES($1,$2,$3,$4,$5) ON CONFLICT(destination_id,object_key) DO UPDATE SET updated_at=now() RETURNING id`, artifact.cleanupID, *artifact.destinationID, artifact.objectKey, artifact.sourceKind, artifact.id).Scan(&artifact.cleanupID); err != nil {
			return err
		}
	}
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
	for _, artifact := range artifacts {
		if artifact.destinationID != nil && artifact.objectKey != "" {
			queued := backupArtifactDeletion{id: artifact.cleanupID, destinationID: *artifact.destinationID, objectKey: artifact.objectKey}
			remote, cleanupErr := w.s3(ctx, queued.destinationID)
			if cleanupErr != nil {
				cleanupErr = w.deferBackupArtifactDeletion(ctx, queued, cleanupErr)
			} else {
				cleanupErr = w.deleteQueuedBackupArtifact(ctx, queued, remote)
			}
			if cleanupErr != nil {
				w.Logger.Error("delete service backup artifact", "service", serviceID, "backup", artifact.id, "error", cleanupErr)
			}
			continue
		}
		if artifact.path == "" {
			continue
		}
		directory, pathErr := validatedLocalBackupDirectory(w.BackupDirectory, artifact.id, artifact.path)
		if pathErr != nil {
			w.Logger.Error("refuse unsafe local backup cleanup", "service", serviceID, "backup", artifact.id, "error", pathErr)
			continue
		}
		if pathErr = os.RemoveAll(directory); pathErr != nil {
			w.Logger.Error("delete service local backup", "service", serviceID, "backup", artifact.id, "error", pathErr)
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

func (w *Worker) createManagedNetwork(ctx context.Context, j job) error {
	network, err := w.managedNetworkForJob(ctx, j)
	if err != nil {
		return err
	}
	if network.DeletionRequestedAt != nil {
		return nil
	}
	manager, ok := w.scheduler(network.ClusterID).(NetworkManager)
	if !ok {
		return errors.New("scheduler does not support managed networks")
	}
	result, err := manager.CreateManagedNetwork(ctx, managedNetworkSpec(network))
	if err != nil {
		_ = w.updateResourceForJob(context.WithoutCancel(ctx), j, `UPDATE managed_networks SET status=CASE WHEN $3 THEN 'error' ELSE 'provisioning' END,last_error=$2,updated_at=now() WHERE id=$1 AND deletion_requested_at IS NULL`, network.ID, truncate(err.Error(), 2048), j.Attempts+1 >= j.MaxAttempts)
		return err
	}
	return w.updateResourceForJob(ctx, j, `UPDATE managed_networks SET status='ready',docker_id=$2,last_error='',updated_at=now() WHERE id=$1 AND deletion_requested_at IS NULL`, network.ID, result.DockerID)
}

func (w *Worker) deleteManagedNetwork(ctx context.Context, j job) error {
	network, err := w.managedNetworkForJob(ctx, j)
	if errors.Is(err, store.ErrNotFound) {
		return nil
	}
	if err != nil {
		return err
	}
	if network.DeletionRequestedAt == nil {
		return errors.New("managed network deletion was not requested")
	}
	manager, ok := w.scheduler(network.ClusterID).(NetworkManager)
	if !ok {
		return errors.New("scheduler does not support managed networks")
	}
	if err = manager.RemoveManagedNetwork(ctx, managedNetworkSpec(network)); err != nil {
		_ = w.updateResourceForJob(context.WithoutCancel(ctx), j, `UPDATE managed_networks SET status=CASE WHEN $3 THEN 'error' ELSE 'deleting' END,last_error=$2,updated_at=now() WHERE id=$1`, network.ID, truncate(err.Error(), 2048), j.Attempts+1 >= j.MaxAttempts)
		return err
	}
	return w.Store.WithJobLease(ctx, j.ID, j.LeaseID, func(tx pgx.Tx) error {
		result, deleteErr := tx.Exec(ctx, `DELETE FROM managed_networks WHERE id=$1 AND deletion_requested_at IS NOT NULL AND NOT EXISTS(SELECT 1 FROM compose_service_networks WHERE network_id=$1)`, network.ID)
		if deleteErr != nil {
			return deleteErr
		}
		if result.RowsAffected() != 1 {
			return errors.New("managed network is still assigned")
		}
		return nil
	})
}

func (w *Worker) managedNetworkForJob(ctx context.Context, j job) (store.ManagedNetwork, error) {
	var payload struct {
		NetworkID string `json:"networkId"`
	}
	if err := json.Unmarshal(j.Payload, &payload); err != nil {
		return store.ManagedNetwork{}, err
	}
	id, err := uuid.Parse(payload.NetworkID)
	if err != nil {
		return store.ManagedNetwork{}, err
	}
	var organizationID uuid.UUID
	if err = w.Store.Pool.QueryRow(ctx, `SELECT organization_id FROM managed_networks WHERE id=$1`, id).Scan(&organizationID); errors.Is(err, pgx.ErrNoRows) {
		return store.ManagedNetwork{}, store.ErrNotFound
	} else if err != nil {
		return store.ManagedNetwork{}, err
	}
	return w.Store.GetManagedNetwork(ctx, organizationID, id)
}

func managedNetworkSpec(item store.ManagedNetwork) ManagedNetworkSpec {
	ipam := make([]NetworkIPAMConfig, 0, len(item.IPAM))
	for _, config := range item.IPAM {
		ipam = append(ipam, NetworkIPAMConfig{Subnet: config.Subnet, Gateway: config.Gateway, IPRange: config.IPRange})
	}
	return ManagedNetworkSpec{ID: item.ID.String(), Name: item.Name, Driver: item.Driver, Internal: item.Internal, Attachable: item.Attachable, EnableIPv4: item.EnableIPv4, EnableIPv6: item.EnableIPv6, MTU: item.MTU, IPAM: ipam}
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

func (w *Worker) ensureDatabaseDriver(ctx context.Context, databaseID uuid.UUID, engine, source, digest string) error {
	if w.Databases == nil {
		return errors.New("database registry is not configured")
	}
	current, exists := w.Databases.Engine(engine)
	if !exists {
		return fmt.Errorf("database engine %q is not registered on this worker", engine)
	}
	if source == "" || source == "unbound" {
		if err := w.Store.BindDatabaseDriverIdentity(ctx, databaseID, current.Source, current.ArtifactDigest); err != nil {
			return fmt.Errorf("bind database driver identity: %w", err)
		}
		return nil
	}
	if source != current.Source || digest != current.ArtifactDigest {
		return fmt.Errorf("database engine %q driver identity does not match this worker", engine)
	}
	return nil
}

func (w *Worker) backupVolume(ctx context.Context, j job) error {
	var payload struct {
		BackupID       string `json:"backupId"`
		RetentionCount int    `json:"retentionCount"`
	}
	if err := json.Unmarshal(j.Payload, &payload); err != nil {
		return err
	}
	backupID, err := uuid.Parse(payload.BackupID)
	if err != nil {
		return err
	}
	var serviceID, destinationID uuid.UUID
	var stackName, compose, volumeName, serviceNodeID, backupNodeID string
	var clusterID *uuid.UUID
	var quiesce bool
	err = w.Store.WithJobLease(ctx, j.ID, j.LeaseID, func(tx pgx.Tx) error {
		if err := tx.QueryRow(ctx, `UPDATE volume_backups backup SET status='running',started_at=now() FROM compose_services service,environments environment WHERE backup.id=$1 AND service.id=backup.compose_service_id AND environment.id=service.environment_id RETURNING service.id,service.stack_name,service.compose_yaml,service.storage_node_id,backup.destination_id,backup.volume_name,backup.storage_node_id,backup.quiesce,environment.cluster_id`, backupID).Scan(&serviceID, &stackName, &compose, &serviceNodeID, &destinationID, &volumeName, &backupNodeID, &quiesce, &clusterID); err != nil {
			return err
		}
		return store.LockBackupDestinationForOperation(ctx, tx, destinationID)
	})
	if err != nil {
		return err
	}
	if serviceNodeID == "" || serviceNodeID != backupNodeID {
		return w.failVolumeBackup(ctx, j, backupID, store.ErrStorageNodeMismatch)
	}
	logicalVolumes, err := NamedVolumes(compose)
	if err != nil || !containsString(logicalVolumes, volumeName) {
		if err == nil {
			err = fmt.Errorf("volume %q is no longer declared by the service", volumeName)
		}
		return w.failVolumeBackup(ctx, j, backupID, err)
	}
	actualVolume, err := StackVolumeName(stackName, volumeName)
	if err != nil {
		return w.failVolumeBackup(ctx, j, backupID, err)
	}
	storage, err := w.s3(ctx, destinationID)
	if err != nil {
		return w.failVolumeBackup(ctx, j, backupID, err)
	}
	objectKey := storage.ObjectKey("volumes/" + serviceID.String() + "/" + volumeName + "/" + backupID.String() + ".tar.gz.enc")
	putURL, err := storage.PresignedPut(ctx, objectKey, time.Hour)
	if err != nil {
		return w.failVolumeBackup(ctx, j, backupID, err)
	}
	dataKey := make([]byte, 32)
	if _, err = rand.Read(dataKey); err != nil {
		return w.failVolumeBackup(ctx, j, backupID, err)
	}
	wrapped, err := w.Box.Encrypt(dataKey, "volume-backup-data-key:"+backupID.String())
	if err != nil {
		clear(dataKey)
		return w.failVolumeBackup(ctx, j, backupID, err)
	}
	runner, ok := w.scheduler(clusterID).(VolumeArtifactRunner)
	if !ok {
		clear(dataKey)
		return w.failVolumeBackup(ctx, j, backupID, errors.New("scheduler does not support volume artifact jobs"))
	}
	result, err := runner.RunVolumeArtifact(ctx, VolumeArtifactJob{Job: volumeartifact.Job{Mode: "backup", TransferURL: putURL, EncryptionKey: base64.RawStdEncoding.EncodeToString(dataKey), EncryptionAAD: "volume-backup:" + backupID.String()}, VolumeName: actualVolume, NodeID: backupNodeID, StackName: stackName, Quiesce: quiesce})
	clear(dataKey)
	if err != nil {
		return w.failVolumeBackup(ctx, j, backupID, err)
	}
	if err = w.updateResourceForJob(ctx, j, `UPDATE volume_backups SET status='succeeded',object_key=$2,size_bytes=$3,sha256=$4,plaintext_sha256=$5,encrypted_data_key=$6,finished_at=now() WHERE id=$1`, backupID, objectKey, result.SizeBytes, result.SHA256, result.PlaintextSHA256, wrapped); err != nil {
		cleanupCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		_ = storage.Delete(cleanupCtx, objectKey)
		return err
	}
	if payload.RetentionCount > 0 {
		w.pruneVolumeBackups(ctx, backupID, payload.RetentionCount)
	}
	return nil
}

func (w *Worker) restoreVolume(ctx context.Context, j job) error {
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
	var backupID, destinationID uuid.UUID
	var stackName, compose, serviceNodeID, volumeName, backupNodeID, objectKey, expectedHash, plaintextHash, encryptedKey string
	var expectedSize int64
	var clusterID *uuid.UUID
	err = w.Store.WithJobLease(ctx, j.ID, j.LeaseID, func(tx pgx.Tx) error {
		if err := tx.QueryRow(ctx, `UPDATE volume_restores restore SET status='running',started_at=now() FROM volume_backups backup,compose_services service,environments environment WHERE restore.id=$1 AND backup.id=restore.volume_backup_id AND service.id=backup.compose_service_id AND environment.id=service.environment_id RETURNING backup.id,backup.destination_id,service.stack_name,service.compose_yaml,service.storage_node_id,backup.volume_name,backup.storage_node_id,backup.object_key,backup.sha256,backup.plaintext_sha256,backup.encrypted_data_key,backup.size_bytes,environment.cluster_id`, restoreID).Scan(&backupID, &destinationID, &stackName, &compose, &serviceNodeID, &volumeName, &backupNodeID, &objectKey, &expectedHash, &plaintextHash, &encryptedKey, &expectedSize, &clusterID); err != nil {
			return err
		}
		return store.LockBackupDestinationForOperation(ctx, tx, destinationID)
	})
	if err != nil {
		return err
	}
	fail := func(cause error) error { return w.failVolumeRestore(ctx, j, restoreID, cause) }
	if serviceNodeID == "" || serviceNodeID != backupNodeID {
		return fail(store.ErrStorageNodeMismatch)
	}
	logicalVolumes, err := NamedVolumes(compose)
	if err != nil || !containsString(logicalVolumes, volumeName) {
		if err == nil {
			err = fmt.Errorf("volume %q is no longer declared by the service", volumeName)
		}
		return fail(err)
	}
	actualVolume, err := StackVolumeName(stackName, volumeName)
	if err != nil {
		return fail(err)
	}
	storage, err := w.s3(ctx, destinationID)
	if err != nil {
		return fail(err)
	}
	getURL, err := storage.PresignedGet(ctx, objectKey, time.Hour)
	if err != nil {
		return fail(err)
	}
	dataKey, err := w.Box.Decrypt(encryptedKey, "volume-backup-data-key:"+backupID.String())
	if err != nil {
		return fail(err)
	}
	defer clear(dataKey)
	runner, ok := w.scheduler(clusterID).(VolumeArtifactRunner)
	if !ok {
		return fail(errors.New("scheduler does not support volume artifact jobs"))
	}
	_, err = runner.RunVolumeArtifact(ctx, VolumeArtifactJob{Job: volumeartifact.Job{Mode: "restore", TransferURL: getURL, EncryptionKey: base64.RawStdEncoding.EncodeToString(dataKey), EncryptionAAD: "volume-backup:" + backupID.String(), SHA256: expectedHash, PlaintextSHA256: plaintextHash, SizeBytes: expectedSize}, VolumeName: actualVolume, NodeID: backupNodeID, StackName: stackName, Quiesce: true})
	if err != nil {
		return fail(err)
	}
	return w.updateResourceForJob(ctx, j, `UPDATE volume_restores SET status='succeeded',finished_at=now() WHERE id=$1`, restoreID)
}

func (w *Worker) failVolumeBackup(ctx context.Context, j job, id uuid.UUID, cause error) error {
	query := `UPDATE volume_backups SET status='failed',error=$2,finished_at=now() WHERE id=$1`
	if j.Attempts+1 < j.MaxAttempts && !errors.Is(ctx.Err(), context.Canceled) {
		query = `UPDATE volume_backups SET status='running',error=$2,finished_at=NULL WHERE id=$1`
	}
	return errors.Join(cause, w.updateResourceForJob(ctx, j, query, id, truncate(cause.Error(), 8192)))
}

func (w *Worker) failVolumeRestore(ctx context.Context, j job, id uuid.UUID, cause error) error {
	query := `UPDATE volume_restores SET status='failed',error=$2,finished_at=now() WHERE id=$1`
	if j.Attempts+1 < j.MaxAttempts && !errors.Is(ctx.Err(), context.Canceled) {
		query = `UPDATE volume_restores SET status='running',error=$2,finished_at=NULL WHERE id=$1`
	}
	return errors.Join(cause, w.updateResourceForJob(ctx, j, query, id, truncate(cause.Error(), 8192)))
}

func (w *Worker) pruneVolumeBackups(ctx context.Context, newestID uuid.UUID, keep int) {
	rows, err := w.Store.Pool.Query(ctx, `SELECT old.id,old.destination_id,old.object_key FROM volume_backups old JOIN volume_backups newest ON newest.compose_service_id=old.compose_service_id AND newest.volume_name=old.volume_name WHERE newest.id=$1 AND old.status='succeeded' AND old.object_key<>'' AND NOT EXISTS(SELECT 1 FROM volume_restores restore WHERE restore.volume_backup_id=old.id) ORDER BY old.created_at DESC OFFSET $2`, newestID, keep)
	if err != nil {
		w.Logger.Error("list expired volume backups", "error", err)
		return
	}
	type candidate struct {
		id uuid.UUID
		expiredVolumeBackup
	}
	var candidates []candidate
	for rows.Next() {
		var item candidate
		if err = rows.Scan(&item.id, &item.destinationID, &item.objectKey); err != nil {
			break
		}
		candidates = append(candidates, item)
	}
	rows.Close()
	if err != nil {
		w.Logger.Error("scan expired volume backups", "error", err)
		return
	}
	for _, candidate := range candidates {
		// Resolve and decrypt the destination while the backup's foreign-key
		// reference still prevents destination deletion.
		storage, storageErr := w.s3(ctx, candidate.destinationID)
		if storageErr != nil {
			w.Logger.Error("open expired volume backup destination", "backup", candidate.id, "error", storageErr)
			continue
		}
		item, deleted, deleteErr := w.deleteExpiredVolumeBackupMetadata(ctx, candidate.id)
		if deleteErr != nil {
			w.Logger.Error("prune volume backup metadata", "backup", candidate.id, "error", deleteErr)
			continue
		}
		if !deleted {
			// A restore was queued after candidate selection. Its reference wins:
			// never remove an artifact that a restore can still consume.
			continue
		}
		storageErr = w.deleteQueuedBackupArtifact(ctx, backupArtifactDeletion{id: item.cleanupID, destinationID: item.destinationID, objectKey: item.objectKey}, storage)
		if storageErr != nil {
			// The durable deletion record remains queued for the cleanup leader.
			w.Logger.Error("delete expired volume backup object", "backup", candidate.id, "objectKey", item.objectKey, "error", storageErr)
		}
	}
}

type expiredVolumeBackup struct {
	destinationID uuid.UUID
	objectKey     string
	cleanupID     uuid.UUID
}

// deleteExpiredVolumeBackupMetadata is the retention admission boundary. It
// locks the backup row also locked by QueueVolumeRestore, then rechecks restore
// references before deleting. Exactly one operation wins, so no restore can
// retain metadata for an object that retention subsequently removes.
func (w *Worker) deleteExpiredVolumeBackupMetadata(ctx context.Context, id uuid.UUID) (expiredVolumeBackup, bool, error) {
	tx, err := w.Store.Pool.Begin(ctx)
	if err != nil {
		return expiredVolumeBackup{}, false, err
	}
	defer tx.Rollback(ctx)
	var item expiredVolumeBackup
	var status string
	err = tx.QueryRow(ctx, `SELECT destination_id,object_key,status FROM volume_backups WHERE id=$1 FOR UPDATE`, id).Scan(&item.destinationID, &item.objectKey, &status)
	if errors.Is(err, pgx.ErrNoRows) {
		return expiredVolumeBackup{}, false, nil
	}
	if err != nil {
		return expiredVolumeBackup{}, false, err
	}
	if status != "succeeded" {
		return expiredVolumeBackup{}, false, nil
	}
	if item.objectKey == "" {
		return expiredVolumeBackup{}, false, errors.New("succeeded volume backup has no object key")
	}
	item.cleanupID = uuid.New()
	if err = tx.QueryRow(ctx, `INSERT INTO backup_artifact_deletions(id,destination_id,object_key,source_kind,source_id) VALUES($1,$2,$3,'volume',$4) ON CONFLICT(destination_id,object_key) DO UPDATE SET updated_at=now() RETURNING id`, item.cleanupID, item.destinationID, item.objectKey, id).Scan(&item.cleanupID); err != nil {
		return expiredVolumeBackup{}, false, err
	}
	result, err := tx.Exec(ctx, `DELETE FROM volume_backups backup WHERE backup.id=$1 AND NOT EXISTS(SELECT 1 FROM volume_restores restore WHERE restore.volume_backup_id=backup.id)`, id)
	if err != nil {
		return expiredVolumeBackup{}, false, err
	}
	if result.RowsAffected() != 1 {
		return expiredVolumeBackup{}, false, nil
	}
	if err = tx.Commit(ctx); err != nil {
		return expiredVolumeBackup{}, false, err
	}
	return item, true, nil
}

func containsString(values []string, wanted string) bool {
	for _, value := range values {
		if value == wanted {
			return true
		}
	}
	return false
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
	var engine, version, driverSource, driverDigest, stackName, serviceName, encrypted string
	var destinationID *uuid.UUID
	var clusterID *uuid.UUID
	err = w.Store.WithJobLease(ctx, j.ID, j.LeaseID, func(tx pgx.Tx) error {
		if err := tx.QueryRow(ctx, `UPDATE database_backups b SET status='running',started_at=now() FROM database_instances d,compose_services s,environments e WHERE b.id=$1 AND d.id=b.database_instance_id AND s.id=d.compose_service_id AND e.id=s.environment_id RETURNING d.id,d.engine,d.version,d.driver_source,d.driver_artifact_digest,s.stack_name,d.slug,d.encrypted_credentials,b.destination_id,e.cluster_id`, backupID).Scan(&databaseID, &engine, &version, &driverSource, &driverDigest, &stackName, &serviceName, &encrypted, &destinationID, &clusterID); err != nil {
			return err
		}
		if destinationID == nil {
			return nil
		}
		return store.LockBackupDestinationForOperation(ctx, tx, *destinationID)
	})
	if err != nil {
		return err
	}
	if err = w.ensureDatabaseDriver(ctx, databaseID, engine, driverSource, driverDigest); err != nil {
		return w.failBackup(ctx, j, backupID, err)
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
	tx, err := w.Store.Pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	var databaseID uuid.UUID
	if err = tx.QueryRow(ctx, `SELECT database_instance_id FROM database_backups WHERE id=$1 AND status='succeeded' FOR UPDATE`, backupID).Scan(&databaseID); err != nil {
		return err
	}
	tag, err := tx.Exec(ctx, `INSERT INTO database_restores(id,database_backup_id,status,kind) VALUES($1,$2,'queued','drill') ON CONFLICT(database_backup_id) WHERE kind='drill' DO NOTHING`, restoreID, backupID)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return tx.Commit(ctx)
	}
	if _, err = tx.Exec(ctx, `INSERT INTO jobs(id,kind,payload,resource_key) VALUES($1,'restore.database',$2,$3)`, uuid.New(), payload, "database:"+databaseID.String()); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

func (w *Worker) pruneBackups(ctx context.Context, newestID uuid.UUID, keep int) {
	rows, err := w.Store.Pool.Query(ctx, `SELECT old.id,old.path,old.destination_id,old.object_key FROM database_backups old JOIN database_backups newest ON newest.database_instance_id=old.database_instance_id WHERE newest.id=$1 AND old.status='succeeded' AND NOT EXISTS (SELECT 1 FROM database_restores r WHERE r.database_backup_id=old.id AND (r.kind='manual' OR r.status IN ('queued','running') OR EXISTS(SELECT 1 FROM jobs job WHERE job.kind='restore.database' AND job.payload->>'restoreId'=r.id::text AND job.status IN ('pending','running')))) ORDER BY old.created_at DESC OFFSET $2`, newestID, keep)
	if err != nil {
		w.Logger.Error("select expired backups", "error", err)
		return
	}
	type candidate struct {
		id uuid.UUID
		expiredDatabaseBackup
	}
	items := []candidate{}
	for rows.Next() {
		var item candidate
		if err = rows.Scan(&item.id, &item.path, &item.destinationID, &item.objectKey); err != nil {
			break
		}
		items = append(items, item)
	}
	rows.Close()
	if err != nil {
		w.Logger.Error("scan expired backups", "error", err)
		return
	}
	for _, item := range items {
		var remote *backupstore.S3
		var artifactDirectory string
		if item.destinationID != nil {
			if item.objectKey == "" {
				w.Logger.Error("prune backup metadata", "backup", item.id, "error", "remote backup has no object key")
				continue
			}
			remote, err = w.s3(ctx, *item.destinationID)
		} else {
			artifactDirectory, err = validatedLocalBackupDirectory(w.BackupDirectory, item.id, item.path)
		}
		if err != nil {
			w.Logger.Error("open expired backup artifact", "backup", item.id, "error", err)
			continue
		}
		deletedItem, deleted, deleteErr := w.deleteExpiredDatabaseBackupMetadata(ctx, item.id)
		if deleteErr != nil {
			w.Logger.Error("prune backup metadata", "backup", item.id, "error", deleteErr)
			continue
		}
		if !deleted {
			continue
		}
		if remote != nil {
			remoteErr := w.deleteQueuedBackupArtifact(ctx, backupArtifactDeletion{id: deletedItem.cleanupID, destinationID: *deletedItem.destinationID, objectKey: deletedItem.objectKey}, remote)
			if remoteErr != nil {
				w.Logger.Error("delete expired remote backup", "backup", item.id, "error", remoteErr)
			}
		} else if removeErr := os.RemoveAll(artifactDirectory); removeErr != nil {
			w.Logger.Error("delete expired local backup", "backup", item.id, "error", removeErr)
		}
	}
}

type expiredDatabaseBackup struct {
	path          string
	destinationID *uuid.UUID
	objectKey     string
	cleanupID     uuid.UUID
}

func (w *Worker) deleteExpiredDatabaseBackupMetadata(ctx context.Context, id uuid.UUID) (expiredDatabaseBackup, bool, error) {
	tx, err := w.Store.Pool.Begin(ctx)
	if err != nil {
		return expiredDatabaseBackup{}, false, err
	}
	defer tx.Rollback(ctx)
	var item expiredDatabaseBackup
	var status string
	if err = tx.QueryRow(ctx, `SELECT path,destination_id,object_key,status FROM database_backups WHERE id=$1 FOR UPDATE`, id).Scan(&item.path, &item.destinationID, &item.objectKey, &status); errors.Is(err, pgx.ErrNoRows) {
		return expiredDatabaseBackup{}, false, nil
	} else if err != nil {
		return expiredDatabaseBackup{}, false, err
	}
	if status != "succeeded" {
		return expiredDatabaseBackup{}, false, nil
	}
	var protected bool
	if err = tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM database_restores restore WHERE restore.database_backup_id=$1 AND (restore.kind='manual' OR restore.status IN ('queued','running') OR EXISTS(SELECT 1 FROM jobs job WHERE job.kind='restore.database' AND job.payload->>'restoreId'=restore.id::text AND job.status IN ('pending','running'))))`, id).Scan(&protected); err != nil {
		return expiredDatabaseBackup{}, false, err
	}
	if protected {
		return expiredDatabaseBackup{}, false, nil
	}
	if item.destinationID != nil {
		if item.objectKey == "" {
			return expiredDatabaseBackup{}, false, errors.New("remote database backup has no object key")
		}
		item.cleanupID = uuid.New()
		if err = tx.QueryRow(ctx, `INSERT INTO backup_artifact_deletions(id,destination_id,object_key,source_kind,source_id) VALUES($1,$2,$3,'database',$4) ON CONFLICT(destination_id,object_key) DO UPDATE SET updated_at=now() RETURNING id`, item.cleanupID, *item.destinationID, item.objectKey, id).Scan(&item.cleanupID); err != nil {
			return expiredDatabaseBackup{}, false, err
		}
	}
	if _, err = tx.Exec(ctx, `DELETE FROM database_restores WHERE database_backup_id=$1 AND kind='drill'`, id); err != nil {
		return expiredDatabaseBackup{}, false, err
	}
	result, err := tx.Exec(ctx, `DELETE FROM database_backups WHERE id=$1 AND NOT EXISTS(SELECT 1 FROM database_restores WHERE database_backup_id=$1)`, id)
	if err != nil {
		return expiredDatabaseBackup{}, false, err
	}
	if result.RowsAffected() != 1 {
		return expiredDatabaseBackup{}, false, nil
	}
	if err = tx.Commit(ctx); err != nil {
		return expiredDatabaseBackup{}, false, err
	}
	return item, true, nil
}

func validatedLocalBackupDirectory(root string, backupID uuid.UUID, artifactPath string) (string, error) {
	cleanRoot := filepath.Clean(root)
	expectedDirectory := filepath.Join(cleanRoot, backupID.String())
	cleanArtifact := filepath.Clean(artifactPath)
	if !filepath.IsAbs(cleanRoot) || cleanRoot == string(filepath.Separator) || filepath.Dir(cleanArtifact) != expectedDirectory {
		return "", errors.New("local backup artifact is outside its expected directory")
	}
	if !strings.HasPrefix(filepath.Base(cleanArtifact), backupID.String()+".") {
		return "", errors.New("local backup artifact has an unexpected filename")
	}
	return expectedDirectory, nil
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
	var kind, engine, version, driverSource, driverDigest, stackName, serviceName, encryptedCredentials, path, expectedHash, plaintextHash, encryptedDataKey, objectKey string
	var artifactEncrypted bool
	var expectedSize *int64
	var destinationID *uuid.UUID
	var clusterID *uuid.UUID
	err = w.Store.WithJobLease(ctx, j.ID, j.LeaseID, func(tx pgx.Tx) error {
		if err := tx.QueryRow(ctx, `UPDATE database_restores r SET status='running',started_at=now() FROM database_backups b,database_instances d,compose_services s,environments e WHERE r.id=$1 AND b.id=r.database_backup_id AND d.id=b.database_instance_id AND s.id=d.compose_service_id AND e.id=s.environment_id RETURNING r.kind,b.id,d.id,d.engine,d.version,d.driver_source,d.driver_artifact_digest,s.stack_name,d.slug,d.encrypted_credentials,b.path,b.sha256,b.size_bytes,b.encrypted,b.plaintext_sha256,b.encrypted_data_key,b.destination_id,b.object_key,e.cluster_id`, restoreID).Scan(&kind, &backupID, &databaseID, &engine, &version, &driverSource, &driverDigest, &stackName, &serviceName, &encryptedCredentials, &path, &expectedHash, &expectedSize, &artifactEncrypted, &plaintextHash, &encryptedDataKey, &destinationID, &objectKey, &clusterID); err != nil {
			return err
		}
		if destinationID == nil {
			return nil
		}
		return store.LockBackupDestinationForOperation(ctx, tx, *destinationID)
	})
	if err != nil {
		return err
	}
	if err = validateBackupArtifactMetadata(expectedSize, expectedHash, plaintextHash, artifactEncrypted); err != nil {
		return w.failRestore(ctx, j, restoreID, err)
	}
	if err = w.ensureDatabaseDriver(ctx, databaseID, engine, driverSource, driverDigest); err != nil {
		return w.failRestore(ctx, j, restoreID, err)
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
		if remoteErr = remote.Get(ctx, objectKey, cleanPath, *expectedSize); remoteErr != nil {
			return w.failRestore(ctx, j, restoreID, remoteErr)
		}
	}
	relative, err := filepath.Rel(cleanRoot, cleanPath)
	if err != nil || strings.HasPrefix(relative, "..") {
		return w.failRestore(ctx, j, restoreID, errors.New("backup path escapes configured directory"))
	}
	actualHash, actualSize, err := checksumFile(cleanPath)
	if err != nil {
		return w.failRestore(ctx, j, restoreID, err)
	}
	if actualHash != expectedHash || actualSize != *expectedSize {
		return w.failRestore(ctx, j, restoreID, errors.New("backup checksum or size mismatch"))
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
		compiled, compileErr := w.Compiler.Compile(rendered.ComposeYAML, nil)
		if compileErr != nil {
			return w.failRestore(ctx, j, restoreID, errors.New("database driver returned an invalid compose document"))
		}
		drillStack := "drill-" + strings.Split(restoreID.String(), "-")[0]
		if _, err = w.Swarm.Deploy(ctx, drillStack, compiled, rendered.Environment, nil); err != nil {
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

func validateBackupArtifactMetadata(size *int64, checksum, plaintextChecksum string, encrypted bool) error {
	if size == nil || *size <= 0 {
		return errors.New("backup is missing a verified artifact size")
	}
	digest, err := hex.DecodeString(checksum)
	if err != nil || len(digest) != sha256.Size {
		return errors.New("backup is missing a valid SHA-256 checksum")
	}
	if encrypted {
		plaintextDigest, decodeErr := hex.DecodeString(plaintextChecksum)
		if decodeErr != nil || len(plaintextDigest) != sha256.Size {
			return errors.New("encrypted backup is missing a valid plaintext SHA-256 checksum")
		}
	}
	return nil
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
		compiled, compileErr := w.Compiler.Compile(rendered.ComposeYAML, nil)
		if compileErr != nil {
			return w.failRestore(ctx, j, restoreID, errors.New("database driver returned an invalid compose document"))
		}
		drillStack := "drill-" + strings.Split(restoreID.String(), "-")[0]
		if _, err = remote.Deploy(ctx, drillStack, compiled, rendered.Environment, nil); err != nil {
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
	var sourceEngine, sourceVersion, sourceHost, encryptedSource, targetEngine, targetVersion, driverSource, driverDigest, targetHost, encryptedTarget, stackName, databaseStatus string
	var clusterID *uuid.UUID
	err = w.Store.WithJobLease(ctx, j.ID, j.LeaseID, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `UPDATE database_migrations m SET status='running',started_at=COALESCE(started_at,now()),error='' FROM database_instances d,compose_services s,environments e WHERE m.id=$1 AND d.id=m.database_instance_id AND s.id=d.compose_service_id AND e.id=d.environment_id RETURNING d.id,m.source_engine,m.source_version,m.source_host,m.encrypted_source_config,d.engine,d.version,d.driver_source,d.driver_artifact_digest,d.slug,d.encrypted_credentials,s.stack_name,d.status,e.cluster_id`, migrationID).Scan(&databaseID, &sourceEngine, &sourceVersion, &sourceHost, &encryptedSource, &targetEngine, &targetVersion, &driverSource, &driverDigest, &targetHost, &encryptedTarget, &stackName, &databaseStatus, &clusterID)
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
	if err = w.ensureDatabaseDriver(ctx, databaseID, targetEngine, driverSource, driverDigest); err != nil {
		return fail(err)
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
	return backupstore.NewS3(backupstore.S3Config{Endpoint: endpoint, Region: region, Bucket: bucket, Prefix: prefix, UseTLS: useTLS, AccessKey: credentials["accessKey"], SecretKey: credentials["secretKey"], SessionToken: credentials["sessionToken"], Transport: w.EgressTransport})
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
		code, err = sendSMTPNotificationWithTLS(ctx, string(urlBytes), secret, delivery, w.notificationTLS, w.EgressPolicy)
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
