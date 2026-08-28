package deploy

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/bendahma/dokploy-go/internal/cryptox"
	"github.com/bendahma/dokploy-go/internal/database"
	"github.com/bendahma/dokploy-go/internal/store"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

type Worker struct {
	Store           *store.Store
	Box             *cryptox.Box
	Compiler        Compiler
	Swarm           Swarm
	Concurrency     int
	Logger          *slog.Logger
	ID              string
	Databases       *database.Registry
	BackupDirectory string
	Builder         Builder
}

type job struct {
	ID          uuid.UUID
	Kind        string
	Payload     []byte
	Attempts    int
	MaxAttempts int
}

func (w *Worker) Run(ctx context.Context) {
	w.recoverStale(ctx)
	var wg sync.WaitGroup
	wg.Add(1)
	go func() { defer wg.Done(); w.scheduleBackups(ctx) }()
	for i := 0; i < w.Concurrency; i++ {
		wg.Add(1)
		go func() { defer wg.Done(); w.loop(ctx) }()
	}
	<-ctx.Done()
	wg.Wait()
}

func (w *Worker) scheduleBackups(ctx context.Context) {
	ticker := time.NewTicker(time.Minute)
	defer ticker.Stop()
	for {
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
	var intervalSeconds, retentionCount int
	err = tx.QueryRow(ctx, `SELECT id,database_instance_id,interval_seconds,retention_count FROM backup_policies WHERE enabled AND next_run_at<=now() ORDER BY next_run_at FOR UPDATE SKIP LOCKED LIMIT 1`).Scan(&policyID, &databaseID, &intervalSeconds, &retentionCount)
	if errors.Is(err, pgx.ErrNoRows) {
		return store.ErrNotFound
	}
	if err != nil {
		return err
	}
	backupID := uuid.New()
	if _, err = tx.Exec(ctx, `INSERT INTO database_backups(id,database_instance_id,status,format) VALUES($1,$2,'queued','native')`, backupID, databaseID); err != nil {
		return err
	}
	payload, _ := json.Marshal(map[string]any{"backupId": backupID.String(), "retentionCount": retentionCount})
	if _, err = tx.Exec(ctx, `INSERT INTO jobs(id,kind,payload) VALUES($1,'backup.database',$2)`, uuid.New(), payload); err != nil {
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
			err = w.runClaimed(ctx, j)
			if finishErr := w.finish(ctx, j, err); finishErr != nil {
				w.Logger.Error("finish job", "error", finishErr)
			}
		}
	}
}

func (w *Worker) recoverStale(ctx context.Context) {
	// A worker may die after accepting a cancellation. Finalize those leases
	// instead of making a cancelled destructive operation eligible for retry.
	_, _ = w.Store.Pool.Exec(ctx, `UPDATE deployments d SET status='cancelled',error='cancelled by user',finished_at=now() FROM jobs j WHERE j.kind='deploy.compose' AND j.status='running' AND j.cancel_requested_at IS NOT NULL AND j.locked_at < now()-interval '1 minute' AND d.id=(j.payload->>'deploymentId')::uuid`)
	_, _ = w.Store.Pool.Exec(ctx, `UPDATE database_backups b SET status='cancelled',error='cancelled by user',finished_at=now() FROM jobs j WHERE j.kind='backup.database' AND j.status='running' AND j.cancel_requested_at IS NOT NULL AND j.locked_at < now()-interval '1 minute' AND b.id=(j.payload->>'backupId')::uuid`)
	_, _ = w.Store.Pool.Exec(ctx, `UPDATE database_restores r SET status='cancelled',error='cancelled by user',finished_at=now() FROM jobs j WHERE j.kind='restore.database' AND j.status='running' AND j.cancel_requested_at IS NOT NULL AND j.locked_at < now()-interval '1 minute' AND r.id=(j.payload->>'restoreId')::uuid`)
	_, _ = w.Store.Pool.Exec(ctx, `UPDATE jobs SET status='cancelled',finished_at=now(),locked_at=NULL,locked_by=NULL WHERE status='running' AND cancel_requested_at IS NOT NULL AND locked_at < now()-interval '1 minute'`)
	result, err := w.Store.Pool.Exec(ctx, `UPDATE jobs SET status='pending',locked_at=NULL,locked_by=NULL,run_after=now() WHERE status='running' AND cancel_requested_at IS NULL AND locked_at < now()-interval '1 minute'`)
	if err != nil {
		w.Logger.Error("recover stale jobs", "error", err)
		return
	}
	if result.RowsAffected() > 0 {
		w.Logger.Warn("recovered stale jobs", "count", result.RowsAffected())
	}
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
				result, err := w.Store.Pool.Exec(ctx, `UPDATE jobs SET locked_at=now() WHERE id=$1 AND status='running' AND cancel_requested_at IS NULL`, j.ID)
				if err != nil {
					w.Logger.Error("heartbeat job", "job", j.ID, "error", err)
					continue
				}
				if result.RowsAffected() == 0 {
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
	err = tx.QueryRow(ctx, `SELECT j.id,j.kind,j.payload,j.attempts,j.max_attempts FROM jobs j WHERE j.status='pending' AND j.run_after<=now() AND (j.kind<>'deploy.compose' OR NOT EXISTS (SELECT 1 FROM jobs older JOIN deployments old_deployment ON old_deployment.id=(older.payload->>'deploymentId')::uuid JOIN deployments this_deployment ON this_deployment.id=(j.payload->>'deploymentId')::uuid WHERE older.kind='deploy.compose' AND older.status IN ('pending','running') AND old_deployment.compose_service_id=this_deployment.compose_service_id AND older.created_at<j.created_at)) ORDER BY j.created_at FOR UPDATE OF j SKIP LOCKED LIMIT 1`).Scan(&j.ID, &j.Kind, &j.Payload, &j.Attempts, &j.MaxAttempts)
	if errors.Is(err, pgx.ErrNoRows) {
		return job{}, store.ErrNotFound
	}
	if err != nil {
		return job{}, err
	}
	_, err = tx.Exec(ctx, `UPDATE jobs SET status='running',attempts=attempts+1,locked_at=now(),locked_by=$2 WHERE id=$1`, j.ID, w.ID)
	if err != nil {
		return job{}, err
	}
	return j, tx.Commit(ctx)
}

func (w *Worker) execute(ctx context.Context, j job) error {
	if j.Kind == "delete.compose" {
		return w.deleteComposeService(ctx, j)
	}
	if j.Kind == "backup.database" {
		return w.backupDatabase(ctx, j)
	}
	if j.Kind == "restore.database" {
		return w.restoreDatabase(ctx, j)
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
	var stack, compose, encrypted string
	err = w.Store.Pool.QueryRow(ctx, `UPDATE deployments d SET status='running',started_at=now() FROM compose_services s WHERE d.id=$1 AND s.id=d.compose_service_id RETURNING s.stack_name,d.compose_snapshot,d.env_snapshot`, id).Scan(&stack, &compose, &encrypted)
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
	compiled, err := w.Compiler.Compile(compose, routes)
	if err != nil {
		w.markDeployment(ctx, id, "failed", "", err)
		return err
	}
	env := map[string]string{}
	if encrypted != "" {
		plain, e := w.Box.Decrypt(encrypted, "compose-env")
		if e != nil {
			err = e
		} else if e = json.Unmarshal(plain, &env); e != nil {
			err = e
		}
	}
	buildOutput := ""
	if err == nil {
		var source store.ApplicationSource
		source.ComposeServiceID = uuid.Nil
		sourceErr := w.Store.Pool.QueryRow(ctx, `SELECT a.compose_service_id,a.repository_url,a.git_ref,a.context_directory,a.dockerfile,a.target_service,a.registry_image,a.updated_at FROM application_sources a JOIN deployments d ON d.compose_service_id=a.compose_service_id WHERE d.id=$1`, id).Scan(&source.ComposeServiceID, &source.RepositoryURL, &source.GitRef, &source.ContextDirectory, &source.Dockerfile, &source.TargetService, &source.RegistryImage, &source.UpdatedAt)
		if sourceErr == nil {
			buildCtx, cancel := context.WithTimeout(ctx, 45*time.Minute)
			tag, output, buildErr := w.Builder.Build(buildCtx, source, id)
			cancel()
			buildOutput = output
			if buildErr != nil {
				err = buildErr
			} else {
				compiled, err = SetServiceImage(compiled, source.TargetService, tag)
			}
		} else if !errors.Is(sourceErr, pgx.ErrNoRows) {
			err = sourceErr
		}
	}
	if err == nil {
		var output string
		output, err = w.Swarm.Deploy(ctx, stack, compiled, env)
		w.markDeployment(ctx, id, map[bool]string{true: "failed", false: "succeeded"}[err != nil], buildOutput+output, err)
	} else {
		w.markDeployment(ctx, id, "failed", buildOutput, err)
	}
	return err
}

func (w *Worker) deleteComposeService(ctx context.Context, j job) error {
	var payload struct {
		ServiceID string `json:"serviceId"`
		StackName string `json:"stackName"`
	}
	if err := json.Unmarshal(j.Payload, &payload); err != nil {
		return err
	}
	serviceID, err := uuid.Parse(payload.ServiceID)
	if err != nil {
		return err
	}
	if _, err = w.Swarm.Remove(ctx, payload.StackName); err != nil {
		return err
	}
	rows, err := w.Store.Pool.Query(ctx, `SELECT b.path FROM database_backups b JOIN database_instances d ON d.id=b.database_instance_id WHERE d.compose_service_id=$1 AND b.path<>''`, serviceID)
	if err != nil {
		return err
	}
	paths := []string{}
	for rows.Next() {
		var path string
		if err = rows.Scan(&path); err != nil {
			rows.Close()
			return err
		}
		paths = append(paths, path)
	}
	rows.Close()
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
	for _, path := range paths {
		relative, relErr := filepath.Rel(root, filepath.Clean(path))
		if relErr == nil && relative != ".." && !strings.HasPrefix(relative, ".."+string(filepath.Separator)) {
			_ = os.RemoveAll(filepath.Dir(path))
		}
	}
	return nil
}

func (w *Worker) backupDatabase(ctx context.Context, j job) error {
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
	var engine, version, stackName, serviceName, encrypted string
	err = w.Store.Pool.QueryRow(ctx, `UPDATE database_backups b SET status='running',started_at=now() FROM database_instances d,compose_services s WHERE b.id=$1 AND d.id=b.database_instance_id AND s.id=d.compose_service_id RETURNING d.engine,d.version,s.stack_name,d.slug,d.encrypted_credentials`, backupID).Scan(&engine, &version, &stackName, &serviceName, &encrypted)
	if err != nil {
		return err
	}
	plain, err := w.Box.Decrypt(encrypted, "database-credentials")
	if err != nil {
		return w.failBackup(ctx, backupID, err)
	}
	credentials := map[string]string{}
	if err = json.Unmarshal(plain, &credentials); err != nil {
		return w.failBackup(ctx, backupID, err)
	}
	filename := backupID.String() + ".dump"
	plan, err := w.Databases.Backup(engine, version, serviceName, credentials, filename)
	if err != nil {
		return w.failBackup(ctx, backupID, err)
	}
	directory := filepath.Join(w.BackupDirectory, backupID.String())
	if err = os.MkdirAll(directory, 0700); err != nil {
		return w.failBackup(ctx, backupID, err)
	}
	jobCtx, cancel := context.WithTimeout(ctx, 30*time.Minute)
	defer cancel()
	_, err = w.Swarm.RunContainerJob(jobCtx, stackName+"_default", plan.Image, directory, plan.Environment, plan.Command)
	if err != nil {
		return w.failBackup(ctx, backupID, err)
	}
	path := filepath.Join(directory, filename)
	sum, size, err := checksumFile(path)
	if err != nil {
		return w.failBackup(ctx, backupID, err)
	}
	_, err = w.Store.Pool.Exec(ctx, `UPDATE database_backups SET status='succeeded',path=$2,size_bytes=$3,sha256=$4,finished_at=now() WHERE id=$1`, backupID, path, size, sum)
	if err == nil && payload.RetentionCount > 0 {
		w.pruneBackups(ctx, backupID, payload.RetentionCount)
	}
	return err
}

func (w *Worker) pruneBackups(ctx context.Context, newestID uuid.UUID, keep int) {
	rows, err := w.Store.Pool.Query(ctx, `SELECT old.id,old.path FROM database_backups old JOIN database_backups newest ON newest.database_instance_id=old.database_instance_id WHERE newest.id=$1 AND old.status='succeeded' AND NOT EXISTS (SELECT 1 FROM database_restores r WHERE r.database_backup_id=old.id) ORDER BY old.created_at DESC OFFSET $2`, newestID, keep)
	if err != nil {
		w.Logger.Error("select expired backups", "error", err)
		return
	}
	type expired struct {
		id   uuid.UUID
		path string
	}
	items := []expired{}
	for rows.Next() {
		var item expired
		if err = rows.Scan(&item.id, &item.path); err == nil {
			items = append(items, item)
		}
	}
	rows.Close()
	for _, item := range items {
		if item.path != "" {
			_ = os.RemoveAll(filepath.Dir(item.path))
		}
		_, _ = w.Store.Pool.Exec(ctx, `DELETE FROM database_backups WHERE id=$1 AND NOT EXISTS (SELECT 1 FROM database_restores WHERE database_backup_id=$1)`, item.id)
	}
}

func (w *Worker) failBackup(ctx context.Context, id uuid.UUID, backupErr error) error {
	_, _ = w.Store.Pool.Exec(ctx, `UPDATE database_backups SET status='failed',error=$2,finished_at=now() WHERE id=$1`, id, truncate(backupErr.Error(), 8192))
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
	var engine, version, stackName, serviceName, encrypted, path, expectedHash string
	err = w.Store.Pool.QueryRow(ctx, `UPDATE database_restores r SET status='running',started_at=now() FROM database_backups b,database_instances d,compose_services s WHERE r.id=$1 AND b.id=r.database_backup_id AND d.id=b.database_instance_id AND s.id=d.compose_service_id RETURNING d.engine,d.version,s.stack_name,d.slug,d.encrypted_credentials,b.path,b.sha256`, restoreID).Scan(&engine, &version, &stackName, &serviceName, &encrypted, &path, &expectedHash)
	if err != nil {
		return err
	}
	cleanRoot := filepath.Clean(w.BackupDirectory)
	cleanPath := filepath.Clean(path)
	relative, err := filepath.Rel(cleanRoot, cleanPath)
	if err != nil || strings.HasPrefix(relative, "..") {
		return w.failRestore(ctx, restoreID, errors.New("backup path escapes configured directory"))
	}
	actualHash, _, err := checksumFile(cleanPath)
	if err != nil {
		return w.failRestore(ctx, restoreID, err)
	}
	if actualHash != expectedHash {
		return w.failRestore(ctx, restoreID, errors.New("backup checksum mismatch"))
	}
	plain, err := w.Box.Decrypt(encrypted, "database-credentials")
	if err != nil {
		return w.failRestore(ctx, restoreID, err)
	}
	credentials := map[string]string{}
	if err = json.Unmarshal(plain, &credentials); err != nil {
		return w.failRestore(ctx, restoreID, err)
	}
	plan, err := w.Databases.Restore(engine, version, serviceName, credentials, filepath.Base(cleanPath))
	if err != nil {
		return w.failRestore(ctx, restoreID, err)
	}
	jobCtx, cancel := context.WithTimeout(ctx, 30*time.Minute)
	defer cancel()
	_, err = w.Swarm.RunContainerJob(jobCtx, stackName+"_default", plan.Image, filepath.Dir(cleanPath), plan.Environment, plan.Command)
	if err != nil {
		return w.failRestore(ctx, restoreID, err)
	}
	_, err = w.Store.Pool.Exec(ctx, `UPDATE database_restores SET status='succeeded',finished_at=now() WHERE id=$1`, restoreID)
	return err
}
func (w *Worker) failRestore(ctx context.Context, id uuid.UUID, restoreErr error) error {
	_, _ = w.Store.Pool.Exec(ctx, `UPDATE database_restores SET status='failed',error=$2,finished_at=now() WHERE id=$1`, id, truncate(restoreErr.Error(), 8192))
	return restoreErr
}

func (w *Worker) markDeployment(ctx context.Context, id uuid.UUID, status, output string, deployErr error) {
	message := ""
	if deployErr != nil {
		message = deployErr.Error()
	}
	_, _ = w.Store.Pool.Exec(ctx, `UPDATE deployments SET status=$2,output=$3,error=$4,finished_at=now() WHERE id=$1`, id, status, truncate(output, 65536), truncate(message, 8192))
	_, _ = w.Store.Pool.Exec(ctx, `UPDATE database_instances db SET status=$2,updated_at=now() FROM deployments d WHERE d.id=$1 AND db.compose_service_id=d.compose_service_id`, id, map[string]string{"succeeded": "running", "failed": "error"}[status])
}

func (w *Worker) finish(ctx context.Context, j job, jobErr error) error {
	var cancellationRequested bool
	if err := w.Store.Pool.QueryRow(ctx, `SELECT cancel_requested_at IS NOT NULL OR status='cancelled' FROM jobs WHERE id=$1`, j.ID).Scan(&cancellationRequested); err != nil {
		return err
	}
	if cancellationRequested {
		w.markJobResourceCancelled(ctx, j)
		_, err := w.Store.Pool.Exec(ctx, `UPDATE jobs SET status='cancelled',finished_at=now(),locked_at=NULL,locked_by=NULL WHERE id=$1`, j.ID)
		return err
	}
	if jobErr == nil {
		_, err := w.Store.Pool.Exec(ctx, `UPDATE jobs SET status='succeeded',finished_at=now(),locked_at=NULL,locked_by=NULL WHERE id=$1`, j.ID)
		return err
	}
	if j.Attempts+1 < j.MaxAttempts {
		_, err := w.Store.Pool.Exec(ctx, `UPDATE jobs SET status='pending',run_after=now()+($2::int * interval '15 seconds'),last_error=$3,locked_at=NULL,locked_by=NULL WHERE id=$1`, j.ID, j.Attempts+1, truncate(jobErr.Error(), 8192))
		return err
	}
	_, err := w.Store.Pool.Exec(ctx, `UPDATE jobs SET status='failed',last_error=$2,finished_at=now(),locked_at=NULL,locked_by=NULL WHERE id=$1`, j.ID, truncate(jobErr.Error(), 8192))
	return err
}

func (w *Worker) markJobResourceCancelled(ctx context.Context, j job) {
	var payload map[string]string
	if json.Unmarshal(j.Payload, &payload) != nil {
		return
	}
	switch j.Kind {
	case "deploy.compose":
		_, _ = w.Store.Pool.Exec(ctx, `UPDATE deployments SET status='cancelled',error='cancelled by user',finished_at=now() WHERE id=$1`, payload["deploymentId"])
	case "backup.database":
		_, _ = w.Store.Pool.Exec(ctx, `UPDATE database_backups SET status='cancelled',error='cancelled by user',finished_at=now() WHERE id=$1`, payload["backupId"])
	case "restore.database":
		_, _ = w.Store.Pool.Exec(ctx, `UPDATE database_restores SET status='cancelled',error='cancelled by user',finished_at=now() WHERE id=$1`, payload["restoreId"])
	}
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
