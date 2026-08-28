package deploy

import (
	"context"
	"crypto/rand"
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

	backupstore "github.com/bendahma/dokploy-go/internal/backup"
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
	wg.Add(2)
	go func() { defer wg.Done(); w.scheduleBackups(ctx) }()
	go func() { defer wg.Done(); w.pruneAuditEvents(ctx) }()
	for i := 0; i < w.Concurrency; i++ {
		wg.Add(1)
		go func() { defer wg.Done(); w.loop(ctx) }()
	}
	<-ctx.Done()
	wg.Wait()
}

func (w *Worker) pruneAuditEvents(ctx context.Context) {
	ticker := time.NewTicker(time.Hour)
	defer ticker.Stop()
	for {
		if _, err := w.Store.PruneAuditEvents(ctx); err != nil && ctx.Err() == nil {
			w.Logger.Error("prune audit events", "error", err)
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
	var destinationID *uuid.UUID
	var intervalSeconds, retentionCount int
	var verifyRestore bool
	err = tx.QueryRow(ctx, `SELECT id,database_instance_id,interval_seconds,retention_count,destination_id,verify_restore FROM backup_policies WHERE enabled AND next_run_at<=now() ORDER BY next_run_at FOR UPDATE SKIP LOCKED LIMIT 1`).Scan(&policyID, &databaseID, &intervalSeconds, &retentionCount, &destinationID, &verifyRestore)
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
		var gitServer, gitUser, gitSecret, registryServer, registryUser, registrySecret string
		sourceErr := w.Store.Pool.QueryRow(ctx, `SELECT a.compose_service_id,a.repository_url,a.git_ref,a.context_directory,a.dockerfile,a.target_service,a.registry_image,a.updated_at,COALESCE(gc.server,''),COALESCE(gc.username,''),COALESCE(gc.encrypted_secret,''),COALESCE(rc.server,''),COALESCE(rc.username,''),COALESCE(rc.encrypted_secret,'') FROM application_sources a JOIN deployments d ON d.compose_service_id=a.compose_service_id LEFT JOIN source_credentials gc ON gc.id=a.git_credential_id LEFT JOIN source_credentials rc ON rc.id=a.registry_credential_id WHERE d.id=$1`, id).Scan(&source.ComposeServiceID, &source.RepositoryURL, &source.GitRef, &source.ContextDirectory, &source.Dockerfile, &source.TargetService, &source.RegistryImage, &source.UpdatedAt, &gitServer, &gitUser, &gitSecret, &registryServer, &registryUser, &registrySecret)
		if sourceErr == nil {
			credentials := BuildCredentials{Git: Credential{Server: gitServer, Username: gitUser}, Registry: Credential{Server: registryServer, Username: registryUser}}
			if gitSecret != "" {
				plain, decryptErr := w.Box.Decrypt(gitSecret, "source-credential")
				if decryptErr != nil {
					err = decryptErr
				} else {
					credentials.Git.Secret = string(plain)
				}
			}
			if err == nil && registrySecret != "" {
				plain, decryptErr := w.Box.Decrypt(registrySecret, "source-credential")
				if decryptErr != nil {
					err = decryptErr
				} else {
					credentials.Registry.Secret = string(plain)
				}
			}
			if err == nil {
				buildCtx, cancel := context.WithTimeout(ctx, 45*time.Minute)
				tag, output, buildErr := w.Builder.Build(buildCtx, source, id, credentials)
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
	var engine, version, stackName, serviceName, encrypted string
	var destinationID *uuid.UUID
	err = w.Store.Pool.QueryRow(ctx, `UPDATE database_backups b SET status='running',started_at=now() FROM database_instances d,compose_services s WHERE b.id=$1 AND d.id=b.database_instance_id AND s.id=d.compose_service_id RETURNING d.engine,d.version,s.stack_name,d.slug,d.encrypted_credentials,b.destination_id`, backupID).Scan(&engine, &version, &stackName, &serviceName, &encrypted, &destinationID)
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
	extension, supported := w.Databases.BackupExtension(engine)
	if !supported {
		return w.failBackup(ctx, backupID, fmt.Errorf("verified backups are not implemented for database engine %q", engine))
	}
	filename := backupID.String() + "." + extension
	plan, err := w.Databases.Backup(engine, version, serviceName, credentials, filename)
	if err != nil {
		return w.failBackup(ctx, backupID, err)
	}
	directory := filepath.Join(w.BackupDirectory, backupID.String())
	if err = os.MkdirAll(directory, 0700); err != nil {
		return w.failBackup(ctx, backupID, err)
	}
	keepLocalArtifact := false
	defer func() {
		if !keepLocalArtifact {
			_ = os.RemoveAll(directory)
		}
	}()
	if err = writePlanFiles(directory, plan.Files); err != nil {
		return w.failBackup(ctx, backupID, err)
	}
	defer removePlanFiles(directory, plan.Files)
	jobCtx, cancel := context.WithTimeout(ctx, 30*time.Minute)
	defer cancel()
	_, err = w.Swarm.RunContainerJob(jobCtx, stackName+"_default", plan.Image, directory, plan.Environment, plan.Command)
	if err != nil {
		return w.failBackup(ctx, backupID, err)
	}
	plainPath := filepath.Join(directory, filename)
	defer os.Remove(plainPath)
	plainSum, _, err := checksumFile(plainPath)
	if err != nil {
		return w.failBackup(ctx, backupID, err)
	}
	encryptedPath := plainPath + ".enc"
	dataKey := make([]byte, 32)
	if _, err = rand.Read(dataKey); err != nil {
		return w.failBackup(ctx, backupID, err)
	}
	artifactBox, err := cryptox.New(dataKey)
	if err != nil {
		return w.failBackup(ctx, backupID, err)
	}
	wrappedDataKey, err := w.Box.Encrypt(dataKey, "backup-data-key:"+backupID.String())
	clear(dataKey)
	if err != nil {
		return w.failBackup(ctx, backupID, err)
	}
	if err = encryptBackupFile(artifactBox, plainPath, encryptedPath, backupID); err != nil {
		return w.failBackup(ctx, backupID, err)
	}
	if err = os.Remove(plainPath); err != nil {
		return w.failBackup(ctx, backupID, fmt.Errorf("remove plaintext backup: %w", err))
	}
	sum, size, err := checksumFile(encryptedPath)
	if err != nil {
		return w.failBackup(ctx, backupID, err)
	}
	storedPath, objectKey := encryptedPath, ""
	var remote *backupstore.S3
	if destinationID != nil {
		var remoteErr error
		remote, remoteErr = w.s3(ctx, *destinationID)
		if remoteErr != nil {
			return w.failBackup(ctx, backupID, remoteErr)
		}
		objectKey = remote.ObjectKey(serviceName + "/" + filename + ".enc")
		if remoteErr = remote.Put(ctx, objectKey, encryptedPath); remoteErr != nil {
			return w.failBackup(ctx, backupID, remoteErr)
		}
		storedPath = ""
	}
	_, err = w.Store.Pool.Exec(ctx, `UPDATE database_backups SET status='succeeded',path=$2,object_key=$3,size_bytes=$4,sha256=$5,encrypted=true,plaintext_sha256=$6,encrypted_data_key=$7,finished_at=now() WHERE id=$1`, backupID, storedPath, objectKey, size, sum, plainSum, wrappedDataKey)
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

func (w *Worker) queueRestoreDrill(ctx context.Context, backupID uuid.UUID) error {
	restoreID := uuid.New()
	payload, _ := json.Marshal(map[string]string{"restoreId": restoreID.String()})
	_, err := w.Store.Pool.Exec(ctx, `WITH inserted AS (INSERT INTO database_restores(id,database_backup_id,status,kind) VALUES($1,$2,'queued','drill') ON CONFLICT(database_backup_id) WHERE kind='drill' DO NOTHING RETURNING id) INSERT INTO jobs(id,kind,payload) SELECT $3,'restore.database',$4 FROM inserted`, restoreID, backupID, uuid.New(), payload)
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
	var backupID uuid.UUID
	var kind, engine, version, stackName, serviceName, encryptedCredentials, path, expectedHash, plaintextHash, encryptedDataKey, objectKey string
	var artifactEncrypted bool
	var destinationID *uuid.UUID
	err = w.Store.Pool.QueryRow(ctx, `UPDATE database_restores r SET status='running',started_at=now() FROM database_backups b,database_instances d,compose_services s WHERE r.id=$1 AND b.id=r.database_backup_id AND d.id=b.database_instance_id AND s.id=d.compose_service_id RETURNING r.kind,b.id,d.engine,d.version,s.stack_name,d.slug,d.encrypted_credentials,b.path,b.sha256,b.encrypted,b.plaintext_sha256,b.encrypted_data_key,b.destination_id,b.object_key`, restoreID).Scan(&kind, &backupID, &engine, &version, &stackName, &serviceName, &encryptedCredentials, &path, &expectedHash, &artifactEncrypted, &plaintextHash, &encryptedDataKey, &destinationID, &objectKey)
	if err != nil {
		return err
	}
	cleanRoot := filepath.Clean(w.BackupDirectory)
	cleanPath := filepath.Clean(path)
	if destinationID != nil {
		directory := filepath.Join(cleanRoot, "restore-"+restoreID.String())
		if err = os.MkdirAll(directory, 0700); err != nil {
			return w.failRestore(ctx, restoreID, err)
		}
		defer os.RemoveAll(directory)
		cleanPath = filepath.Join(directory, filepath.Base(objectKey))
		remote, remoteErr := w.s3(ctx, *destinationID)
		if remoteErr != nil {
			return w.failRestore(ctx, restoreID, remoteErr)
		}
		if remoteErr = remote.Get(ctx, objectKey, cleanPath); remoteErr != nil {
			return w.failRestore(ctx, restoreID, remoteErr)
		}
	}
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
	if artifactEncrypted {
		dataKey, keyErr := w.Box.Decrypt(encryptedDataKey, "backup-data-key:"+backupID.String())
		if keyErr != nil {
			return w.failRestore(ctx, restoreID, keyErr)
		}
		artifactBox, keyErr := cryptox.New(dataKey)
		clear(dataKey)
		if keyErr != nil {
			return w.failRestore(ctx, restoreID, keyErr)
		}
		decryptedPath := strings.TrimSuffix(cleanPath, ".enc")
		if decryptedPath == cleanPath {
			decryptedPath += ".plain"
		}
		if err = decryptBackupFile(artifactBox, cleanPath, decryptedPath, backupID); err != nil {
			return w.failRestore(ctx, restoreID, err)
		}
		defer os.Remove(decryptedPath)
		cleanPath = decryptedPath
		if actualPlainHash, _, hashErr := checksumFile(cleanPath); hashErr != nil || actualPlainHash != plaintextHash {
			if hashErr == nil {
				hashErr = errors.New("backup plaintext checksum mismatch")
			}
			return w.failRestore(ctx, restoreID, hashErr)
		}
	}
	credentials := map[string]string{}
	if kind == "drill" {
		drillName := "verify"
		rendered, renderErr := w.Databases.Render(engine, database.Request{Name: drillName, Version: version})
		if renderErr != nil {
			return w.failRestore(ctx, restoreID, renderErr)
		}
		drillStack := "drill-" + strings.Split(restoreID.String(), "-")[0]
		if _, err = w.Swarm.Deploy(ctx, drillStack, rendered.ComposeYAML, rendered.Environment); err != nil {
			return w.failRestore(ctx, restoreID, err)
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
			return w.failRestore(ctx, restoreID, readinessErr)
		}
		ready := false
		for attempt := 0; attempt < 12; attempt++ {
			if _, readinessErr = w.Swarm.RunContainerJob(ctx, stackName+"_default", readiness.Image, "", readiness.Environment, readiness.Command); readinessErr == nil {
				ready = true
				break
			}
			select {
			case <-ctx.Done():
				return w.failRestore(ctx, restoreID, ctx.Err())
			case <-time.After(5 * time.Second):
			}
		}
		if !ready {
			return w.failRestore(ctx, restoreID, fmt.Errorf("restore drill database did not become ready: %w", readinessErr))
		}
	} else {
		plain, decryptErr := w.Box.Decrypt(encryptedCredentials, "database-credentials")
		if decryptErr != nil {
			return w.failRestore(ctx, restoreID, decryptErr)
		}
		if err = json.Unmarshal(plain, &credentials); err != nil {
			return w.failRestore(ctx, restoreID, err)
		}
	}
	plan, err := w.Databases.Restore(engine, version, serviceName, credentials, filepath.Base(cleanPath))
	if err != nil {
		return w.failRestore(ctx, restoreID, err)
	}
	if err = writePlanFiles(filepath.Dir(cleanPath), plan.Files); err != nil {
		return w.failRestore(ctx, restoreID, err)
	}
	defer removePlanFiles(filepath.Dir(cleanPath), plan.Files)
	jobCtx, cancel := context.WithTimeout(ctx, 30*time.Minute)
	defer cancel()
	_, err = w.Swarm.RunContainerJob(jobCtx, stackName+"_default", plan.Image, filepath.Dir(cleanPath), plan.Environment, plan.Command)
	if err != nil {
		return w.failRestore(ctx, restoreID, err)
	}
	_, err = w.Store.Pool.Exec(ctx, `UPDATE database_restores SET status='succeeded',finished_at=now() WHERE id=$1`, restoreID)
	return err
}

func (w *Worker) s3(ctx context.Context, id uuid.UUID) (*backupstore.S3, error) {
	var endpoint, region, bucket, prefix, encrypted string
	var useTLS bool
	err := w.Store.Pool.QueryRow(ctx, `SELECT endpoint,region,bucket,prefix,use_tls,encrypted_credentials FROM backup_destinations WHERE id=$1`, id).Scan(&endpoint, &region, &bucket, &prefix, &useTLS, &encrypted)
	if err != nil {
		return nil, err
	}
	plain, err := w.Box.Decrypt(encrypted, "backup-destination")
	if err != nil {
		return nil, err
	}
	var credentials map[string]string
	if err = json.Unmarshal(plain, &credentials); err != nil {
		return nil, err
	}
	return backupstore.NewS3(backupstore.S3Config{Endpoint: endpoint, Region: region, Bucket: bucket, Prefix: prefix, UseTLS: useTLS, AccessKey: credentials["accessKey"], SecretKey: credentials["secretKey"], SessionToken: credentials["sessionToken"]})
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
	for name, content := range files {
		if filepath.Base(name) != name {
			return errors.New("invalid backup helper filename")
		}
		if err := os.WriteFile(filepath.Join(directory, name), []byte(content), 0600); err != nil {
			return err
		}
	}
	return nil
}

func removePlanFiles(directory string, files map[string]string) {
	for name := range files {
		_ = os.Remove(filepath.Join(directory, name))
	}
}
