package deploy

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/bendahma/dokploy-go/internal/store"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

func TestDatabaseRetentionPreservesActiveRestoreDrill(t *testing.T) {
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
	serviceID, databaseID, backupID, manualBackupID := uuid.New(), uuid.New(), uuid.New(), uuid.New()
	backupRoot := t.TempDir()
	backupDirectory := filepath.Join(backupRoot, backupID.String())
	backupPath := filepath.Join(backupDirectory, backupID.String()+".dump.enc")
	if err = os.Mkdir(backupDirectory, 0700); err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(backupPath, []byte("encrypted backup"), 0600); err != nil {
		t.Fatal(err)
	}
	statements := []struct {
		query string
		args  []any
	}{
		{`INSERT INTO organizations(id,name,slug) VALUES($1,'Database retention',$2)`, []any{organizationID, "database-retention-" + organizationID.String()}},
		{`INSERT INTO projects(id,organization_id,name,slug) VALUES($1,$2,'Project','project')`, []any{projectID, organizationID}},
		{`INSERT INTO environments(id,project_id,name,slug) VALUES($1,$2,'Production','production')`, []any{environmentID, projectID}},
		{`INSERT INTO compose_services(id,environment_id,name,slug,stack_name,compose_yaml) VALUES($1,$2,'Database','database',$3,'services: {}')`, []any{serviceID, environmentID, "database-retention-" + serviceID.String()}},
		{`INSERT INTO database_instances(id,environment_id,name,slug,engine,version,compose_service_id,encrypted_credentials) VALUES($1,$2,'Database','database','postgres','17',$3,'ciphertext')`, []any{databaseID, environmentID, serviceID}},
		{`INSERT INTO database_backups(id,database_instance_id,status,format,path,size_bytes,sha256,encrypted,plaintext_sha256,encrypted_data_key,finished_at) VALUES($1,$2,'succeeded','native',$3,16,$4,true,$5,'wrapped',now())`, []any{backupID, databaseID, backupPath, strings.Repeat("a", 64), strings.Repeat("b", 64)}},
		{`INSERT INTO database_backups(id,database_instance_id,status,format,path,size_bytes,sha256,encrypted,plaintext_sha256,encrypted_data_key,finished_at) VALUES($1,$2,'succeeded','native',$3,16,$4,true,$5,'wrapped',now())`, []any{manualBackupID, databaseID, filepath.Join(backupRoot, manualBackupID.String(), manualBackupID.String()+".dump.enc"), strings.Repeat("c", 64), strings.Repeat("d", 64)}},
	}
	for _, statement := range statements {
		if _, err = db.Pool.Exec(ctx, statement.query, statement.args...); err != nil {
			t.Fatal(err)
		}
	}
	t.Cleanup(func() {
		_, _ = db.Pool.Exec(context.Background(), `DELETE FROM jobs WHERE resource_key=$1`, "database:"+databaseID.String())
		_, _ = db.Pool.Exec(context.Background(), `DELETE FROM database_restores WHERE database_backup_id=$1`, backupID)
		_, _ = db.Pool.Exec(context.Background(), `DELETE FROM organizations WHERE id=$1`, organizationID)
	})

	worker := &Worker{Store: db, BackupDirectory: backupRoot}
	if _, err = db.QueueDatabaseRestore(ctx, organizationID, manualBackupID, uuid.Nil, "database"); err != nil {
		t.Fatal(err)
	}
	if _, deleted, deleteErr := worker.deleteExpiredDatabaseBackupMetadata(ctx, manualBackupID); deleteErr != nil || deleted {
		t.Fatalf("backup with manual restore deleted=%v err=%v", deleted, deleteErr)
	}
	if err = worker.queueRestoreDrill(ctx, backupID); err != nil {
		t.Fatal(err)
	}
	var restoreID, jobID uuid.UUID
	if err = db.Pool.QueryRow(ctx, `SELECT restore.id,job.id FROM database_restores restore JOIN jobs job ON job.kind='restore.database' AND job.payload->>'restoreId'=restore.id::text WHERE restore.database_backup_id=$1`, backupID).Scan(&restoreID, &jobID); err != nil {
		t.Fatal(err)
	}
	if _, deleted, deleteErr := worker.deleteExpiredDatabaseBackupMetadata(ctx, backupID); deleteErr != nil || deleted {
		t.Fatalf("backup with active drill deleted=%v err=%v", deleted, deleteErr)
	}
	if _, err = db.Pool.Exec(ctx, `UPDATE database_restores SET status='succeeded',finished_at=now() WHERE id=$1`, restoreID); err != nil {
		t.Fatal(err)
	}
	if _, err = db.Pool.Exec(ctx, `UPDATE jobs SET status='succeeded',finished_at=now() WHERE id=$1`, jobID); err != nil {
		t.Fatal(err)
	}
	item, deleted, err := worker.deleteExpiredDatabaseBackupMetadata(ctx, backupID)
	if err != nil || !deleted {
		t.Fatalf("backup with completed drill deleted=%v err=%v", deleted, err)
	}
	if item.path != backupPath || item.destinationID != nil || item.objectKey != "" {
		t.Fatalf("deleted artifact=%+v", item)
	}
	if err = db.Pool.QueryRow(ctx, `SELECT id FROM database_backups WHERE id=$1`, backupID).Scan(new(uuid.UUID)); !errors.Is(err, pgx.ErrNoRows) {
		t.Fatalf("deleted backup lookup error=%v", err)
	}
}

func TestValidatedLocalBackupDirectory(t *testing.T) {
	root := t.TempDir()
	backupID := uuid.New()
	expected := filepath.Join(root, backupID.String())
	valid := filepath.Join(expected, backupID.String()+".dump.enc")
	if got, err := validatedLocalBackupDirectory(root, backupID, valid); err != nil || got != expected {
		t.Fatalf("validated directory=%q err=%v", got, err)
	}
	for _, unsafe := range []string{
		filepath.Join(root, "other", backupID.String()+".dump.enc"),
		filepath.Join(expected, "other.dump.enc"),
		filepath.Join(string(filepath.Separator), backupID.String()+".dump.enc"),
	} {
		if _, err := validatedLocalBackupDirectory(root, backupID, unsafe); err == nil {
			t.Fatalf("unsafe artifact path accepted: %s", unsafe)
		}
	}
}
