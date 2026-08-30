package deploy

import (
	"context"
	"errors"
	"os"
	"testing"
	"time"

	"github.com/bendahma/dokploy-go/internal/store"
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
	if err = db.Pool.QueryRow(ctx, `SELECT id FROM volume_backups WHERE id=$1`, backupID).Scan(new(uuid.UUID)); !errors.Is(err, pgx.ErrNoRows) {
		t.Fatalf("deleted backup lookup error=%v", err)
	}
}

func stringOf(value byte, count int) string {
	buffer := make([]byte, count)
	for index := range buffer {
		buffer[index] = value
	}
	return string(buffer)
}
