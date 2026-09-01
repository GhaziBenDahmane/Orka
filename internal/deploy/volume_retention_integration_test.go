package deploy

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	backupstore "github.com/GhaziBenDahmane/Orka/internal/backup"
	"github.com/GhaziBenDahmane/Orka/internal/store"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

func TestVolumeRetentionNeverDeletesRestoreReferencedBackup(t *testing.T) {
	databaseURL := os.Getenv("DOCKYARD_TEST_DATABASE_URL")
	if databaseURL == "" {
		t.Skip("DOCKYARD_TEST_DATABASE_URL is not set")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	db, err := store.Open(ctx, databaseURL)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(db.Pool.Close)

	organizationID, projectID, environmentID := uuid.New(), uuid.New(), uuid.New()
	serviceID, destinationID, backupID := uuid.New(), uuid.New(), uuid.New()
	tx, err := db.Pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	statements := []struct {
		query string
		args  []any
	}{
		{`INSERT INTO organizations(id,name,slug) VALUES($1,'Volume retention',$2)`, []any{organizationID, "volume-retention-" + organizationID.String()}},
		{`INSERT INTO projects(id,organization_id,name,slug) VALUES($1,$2,'Project','project')`, []any{projectID, organizationID}},
		{`INSERT INTO environments(id,project_id,name,slug) VALUES($1,$2,'Production','production')`, []any{environmentID, projectID}},
		{`INSERT INTO compose_services(id,environment_id,name,slug,stack_name,compose_yaml,storage_node_id) VALUES($1,$2,'App','app',$3,'services: {}','node1')`, []any{serviceID, environmentID, "volume-retention-" + serviceID.String()}},
		{`INSERT INTO backup_destinations(id,organization_id,name,endpoint,bucket,encrypted_credentials) VALUES($1,$2,'archive','https://objects.example.test','backups','ciphertext')`, []any{destinationID, organizationID}},
		{`INSERT INTO volume_backups(id,compose_service_id,volume_name,storage_node_id,destination_id,quiesce,status,object_key,size_bytes,sha256,plaintext_sha256,encrypted_data_key,finished_at) VALUES($1,$2,'data','node1',$3,true,'succeeded','volumes/object.enc',42,$4,$5,'wrapped',now())`, []any{backupID, serviceID, destinationID, stringOf('a', 64), stringOf('b', 64)}},
	}
	for _, statement := range statements {
		if _, err = tx.Exec(ctx, statement.query, statement.args...); err != nil {
			_ = tx.Rollback(ctx)
			t.Fatal(err)
		}
	}
	if err = tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = db.Pool.Exec(context.Background(), `DELETE FROM jobs WHERE resource_key=$1`, "service:"+serviceID.String())
		_, _ = db.Pool.Exec(context.Background(), `DELETE FROM backup_artifact_deletions WHERE source_id=$1`, backupID)
		_, _ = db.Pool.Exec(context.Background(), `DELETE FROM volume_restores WHERE volume_backup_id=$1`, backupID)
		_, _ = db.Pool.Exec(context.Background(), `DELETE FROM organizations WHERE id=$1`, organizationID)
	})

	worker := &Worker{Store: db}
	restore, err := db.QueueVolumeRestore(ctx, organizationID, backupID, uuid.Nil, "app")
	if err != nil {
		t.Fatal(err)
	}
	if _, deleted, deleteErr := worker.deleteExpiredVolumeBackupMetadata(ctx, backupID); deleteErr != nil || deleted {
		t.Fatalf("referenced backup deleted=%v err=%v", deleted, deleteErr)
	}
	if err = db.Pool.QueryRow(ctx, `SELECT status FROM volume_backups WHERE id=$1`, backupID).Scan(new(string)); err != nil {
		t.Fatalf("restore-referenced backup disappeared: %v", err)
	}

	if _, err = db.Pool.Exec(ctx, `DELETE FROM jobs WHERE payload->>'restoreId'=$1`, restore.ID.String()); err != nil {
		t.Fatal(err)
	}
	if _, err = db.Pool.Exec(ctx, `DELETE FROM volume_restores WHERE id=$1`, restore.ID); err != nil {
		t.Fatal(err)
	}
	item, deleted, err := worker.deleteExpiredVolumeBackupMetadata(ctx, backupID)
	if err != nil || !deleted {
		t.Fatalf("unreferenced backup deleted=%v err=%v", deleted, err)
	}
	if item.destinationID != destinationID || item.objectKey != "volumes/object.enc" {
		t.Fatalf("deleted artifact=%+v", item)
	}
	var queuedDestination uuid.UUID
	var queuedKey, sourceKind string
	if err = db.Pool.QueryRow(ctx, `SELECT destination_id,object_key,source_kind FROM backup_artifact_deletions WHERE id=$1`, item.cleanupID).Scan(&queuedDestination, &queuedKey, &sourceKind); err != nil || queuedDestination != destinationID || queuedKey != item.objectKey || sourceKind != "volume" {
		t.Fatalf("queued cleanup destination=%s key=%q kind=%q err=%v", queuedDestination, queuedKey, sourceKind, err)
	}
	deleteFailure := errors.New("object store unavailable")
	if err = worker.deferBackupArtifactDeletion(ctx, backupArtifactDeletion{id: item.cleanupID, destinationID: destinationID, objectKey: item.objectKey}, deleteFailure); !errors.Is(err, deleteFailure) {
		t.Fatalf("deferred cleanup error=%v", err)
	}
	var attempts int
	var retryAt time.Time
	var lastError string
	if err = db.Pool.QueryRow(ctx, `SELECT attempts,next_attempt_at,last_error FROM backup_artifact_deletions WHERE id=$1`, item.cleanupID).Scan(&attempts, &retryAt, &lastError); err != nil || attempts != 1 || !retryAt.After(time.Now()) || lastError != deleteFailure.Error() {
		t.Fatalf("deferred cleanup attempts=%d retryAt=%s lastError=%q err=%v", attempts, retryAt, lastError, err)
	}
	deletedPath := ""
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		deletedPath = r.URL.Path
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()
	storage, err := backupstore.NewS3(backupstore.S3Config{Endpoint: server.URL, Region: "us-east-1", Bucket: "backups", AccessKey: "access", SecretKey: "secret", UseTLS: false})
	if err != nil {
		t.Fatal(err)
	}
	if err = worker.deleteQueuedBackupArtifact(ctx, backupArtifactDeletion{id: item.cleanupID, destinationID: destinationID, objectKey: item.objectKey, attempts: attempts}, storage); err != nil {
		t.Fatal(err)
	}
	if deletedPath != "/backups/volumes/object.enc" {
		t.Fatalf("deleted object path=%q", deletedPath)
	}
	if err = db.Pool.QueryRow(ctx, `SELECT id FROM backup_artifact_deletions WHERE id=$1`, item.cleanupID).Scan(new(uuid.UUID)); !errors.Is(err, pgx.ErrNoRows) {
		t.Fatalf("completed cleanup record lookup error=%v", err)
	}
	if err = db.Pool.QueryRow(ctx, `SELECT id FROM volume_backups WHERE id=$1`, backupID).Scan(new(uuid.UUID)); !errors.Is(err, pgx.ErrNoRows) {
		t.Fatalf("deleted backup lookup error=%v", err)
	}
}

func TestVolumeRetentionRestoreWinsAfterCandidateSelection(t *testing.T) {
	databaseURL := os.Getenv("DOCKYARD_TEST_DATABASE_URL")
	if databaseURL == "" {
		t.Skip("DOCKYARD_TEST_DATABASE_URL is not set")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	verifyVolumeRetentionRestoreWinsAfterCandidateSelection(t, ctx, databaseURL)
}

func verifyVolumeRetentionRestoreWinsAfterCandidateSelection(t *testing.T, ctx context.Context, databaseURL string) {
	t.Helper()
	db, err := store.Open(ctx, databaseURL)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(db.Pool.Close)

	organizationID, projectID, environmentID := uuid.New(), uuid.New(), uuid.New()
	serviceID, destinationID, expiredID, malformedID, newestID := uuid.New(), uuid.New(), uuid.New(), uuid.New(), uuid.New()
	tx, err := db.Pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	statements := []struct {
		query string
		args  []any
	}{
		{`INSERT INTO organizations(id,name,slug) VALUES($1,'Volume retention conformance',$2)`, []any{organizationID, "volume-retention-conformance-" + organizationID.String()}},
		{`INSERT INTO projects(id,organization_id,name,slug) VALUES($1,$2,'Project','project')`, []any{projectID, organizationID}},
		{`INSERT INTO environments(id,project_id,name,slug) VALUES($1,$2,'Production','production')`, []any{environmentID, projectID}},
		{`INSERT INTO compose_services(id,environment_id,name,slug,stack_name,compose_yaml,storage_node_id) VALUES($1,$2,'App','app',$3,'services: {}','node1')`, []any{serviceID, environmentID, "volume-retention-conformance-" + serviceID.String()}},
		{`INSERT INTO backup_destinations(id,organization_id,name,endpoint,bucket,encrypted_credentials) VALUES($1,$2,'archive','https://objects.example.test','backups','ciphertext')`, []any{destinationID, organizationID}},
		{`INSERT INTO volume_backups(id,compose_service_id,volume_name,storage_node_id,destination_id,quiesce,status,object_key,size_bytes,sha256,plaintext_sha256,encrypted_data_key,created_at,finished_at) VALUES($1,$2,'data','node1',$3,true,'succeeded','volumes/expired.enc',42,$4,$5,'wrapped',now()-interval '1 hour',now()-interval '1 hour')`, []any{expiredID, serviceID, destinationID, stringOf('a', 64), stringOf('b', 64)}},
		{`INSERT INTO volume_backups(id,compose_service_id,volume_name,storage_node_id,destination_id,quiesce,status,object_key,created_at,finished_at) VALUES($1,$2,'data','node1',$3,true,'succeeded','volumes/malformed.enc',now()-interval '30 minutes',now()-interval '30 minutes')`, []any{malformedID, serviceID, destinationID}},
		{`INSERT INTO volume_backups(id,compose_service_id,volume_name,storage_node_id,destination_id,quiesce,status,object_key,size_bytes,sha256,plaintext_sha256,encrypted_data_key,created_at,finished_at) VALUES($1,$2,'data','node1',$3,true,'succeeded','volumes/newest.enc',42,$4,$5,'wrapped',now(),now())`, []any{newestID, serviceID, destinationID, stringOf('c', 64), stringOf('d', 64)}},
	}
	for _, statement := range statements {
		if _, err = tx.Exec(ctx, statement.query, statement.args...); err != nil {
			_ = tx.Rollback(ctx)
			t.Fatal(err)
		}
	}
	if err = tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = db.Pool.Exec(context.Background(), `DELETE FROM jobs WHERE resource_key=$1`, "service:"+serviceID.String())
		_, _ = db.Pool.Exec(context.Background(), `DELETE FROM backup_artifact_deletions WHERE source_id=$1`, expiredID)
		_, _ = db.Pool.Exec(context.Background(), `DELETE FROM organizations WHERE id=$1`, organizationID)
	})

	worker := &Worker{Store: db}
	candidates, err := worker.expiredVolumeBackupCandidates(ctx, newestID, 2)
	if err != nil {
		t.Fatal(err)
	}
	if len(candidates) != 0 {
		t.Fatalf("malformed backup consumed a retention slot: candidates=%+v", candidates)
	}
	candidates, err = worker.expiredVolumeBackupCandidates(ctx, newestID, 1)
	if err != nil {
		t.Fatal(err)
	}
	if len(candidates) != 1 || candidates[0].id != expiredID || candidates[0].objectKey != "volumes/expired.enc" {
		t.Fatalf("retention candidates=%+v", candidates)
	}
	restore, err := db.QueueVolumeRestore(ctx, organizationID, expiredID, uuid.Nil, "app")
	if err != nil {
		t.Fatal(err)
	}
	if _, deleted, err := worker.deleteExpiredVolumeBackupMetadata(ctx, expiredID); err != nil || deleted {
		t.Fatalf("restore-referenced candidate deleted=%v err=%v", deleted, err)
	}
	var backupExists, restoreExists bool
	if err = db.Pool.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM volume_backups WHERE id=$1),EXISTS(SELECT 1 FROM volume_restores WHERE id=$2 AND volume_backup_id=$1 AND status='queued')`, expiredID, restore.ID).Scan(&backupExists, &restoreExists); err != nil {
		t.Fatal(err)
	}
	if !backupExists || !restoreExists {
		t.Fatalf("retention race result backupExists=%v restoreExists=%v", backupExists, restoreExists)
	}
}

func stringOf(value byte, count int) string {
	buffer := make([]byte, count)
	for index := range buffer {
		buffer[index] = value
	}
	return string(buffer)
}
