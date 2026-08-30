package deploy

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"testing"
	"time"

	"github.com/bendahma/dokploy-go/internal/store"
	"github.com/google/uuid"
)

func TestBackupSchedulersDoNotQueueBehindActiveBackups(t *testing.T) {
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
	databaseServiceID, databaseID, databasePolicyID, databaseBackupID := uuid.New(), uuid.New(), uuid.New(), uuid.New()
	volumeServiceID, volumePolicyID, volumeBackupID, destinationID := uuid.New(), uuid.New(), uuid.New(), uuid.New()
	databaseJobID, volumeJobID := uuid.New(), uuid.New()
	databasePayload, _ := json.Marshal(map[string]string{"backupId": databaseBackupID.String()})
	volumePayload, _ := json.Marshal(map[string]string{"backupId": volumeBackupID.String()})
	statements := []struct {
		query string
		args  []any
	}{
		{`INSERT INTO organizations(id,name,slug) VALUES($1,'Backup scheduler',$2)`, []any{organizationID, "backup-scheduler-" + organizationID.String()}},
		{`INSERT INTO projects(id,organization_id,name,slug) VALUES($1,$2,'Project','project')`, []any{projectID, organizationID}},
		{`INSERT INTO environments(id,project_id,name,slug) VALUES($1,$2,'Production','production')`, []any{environmentID, projectID}},
		{`INSERT INTO compose_services(id,environment_id,name,slug,stack_name,compose_yaml) VALUES($1,$2,'Database','database',$3,'services: {}')`, []any{databaseServiceID, environmentID, "backup-scheduler-db-" + databaseServiceID.String()}},
		{`INSERT INTO database_instances(id,environment_id,name,slug,engine,version,compose_service_id,encrypted_credentials) VALUES($1,$2,'Database','database','postgres','17',$3,'ciphertext')`, []any{databaseID, environmentID, databaseServiceID}},
		{`INSERT INTO compose_services(id,environment_id,name,slug,stack_name,storage_node_id,compose_yaml) VALUES($1,$2,'App','app',$3,'node1',$4)`, []any{volumeServiceID, environmentID, "backup-scheduler-volume-" + volumeServiceID.String(), "services:\n  app:\n    image: example/app:1\n    volumes:\n      - uploads:/data\nvolumes:\n  uploads: {}\n"}},
		{`INSERT INTO backup_destinations(id,organization_id,name,endpoint,bucket,use_tls,encrypted_credentials) VALUES($1,$2,'S3','https://s3.example.test','backups',true,'encrypted')`, []any{destinationID, organizationID}},
		{`INSERT INTO backup_policies(id,database_instance_id,interval_seconds,retention_count,enabled,next_run_at,destination_id) VALUES($1,$2,900,7,true,'2000-01-01',$3)`, []any{databasePolicyID, databaseID, destinationID}},
		{`INSERT INTO volume_backup_policies(id,compose_service_id,volume_name,destination_id,interval_seconds,retention_count,quiesce,enabled,next_run_at) VALUES($1,$2,'uploads',$3,900,7,true,true,'2000-01-01')`, []any{volumePolicyID, volumeServiceID, destinationID}},
		{`INSERT INTO database_backups(id,database_instance_id,status,format,destination_id) VALUES($1,$2,'queued','native',$3)`, []any{databaseBackupID, databaseID, destinationID}},
		{`INSERT INTO volume_backups(id,volume_backup_policy_id,compose_service_id,volume_name,storage_node_id,destination_id,quiesce,status) VALUES($1,$2,$3,'uploads','node1',$4,true,'queued')`, []any{volumeBackupID, volumePolicyID, volumeServiceID, destinationID}},
		{`INSERT INTO jobs(id,kind,payload,resource_key) VALUES($1,'backup.database',$2,$3)`, []any{databaseJobID, databasePayload, "database:" + databaseID.String()}},
		{`INSERT INTO jobs(id,kind,payload,resource_key) VALUES($1,'backup.volume',$2,$3)`, []any{volumeJobID, volumePayload, "service:" + volumeServiceID.String()}},
	}
	for _, statement := range statements {
		if _, err = db.Pool.Exec(ctx, statement.query, statement.args...); err != nil {
			t.Fatal(err)
		}
	}
	t.Cleanup(func() {
		_, _ = db.Pool.Exec(context.Background(), `DELETE FROM jobs WHERE resource_key=ANY($1) OR (kind='delete.compose' AND payload->>'serviceId'=ANY($2))`, []string{"database:" + databaseID.String(), "service:" + volumeServiceID.String()}, []string{databaseServiceID.String(), volumeServiceID.String()})
		_, _ = db.Pool.Exec(context.Background(), `DELETE FROM organizations WHERE id=$1`, organizationID)
	})

	worker := &Worker{Store: db}
	if err = worker.enqueueDueBackup(ctx); err != nil && !errors.Is(err, store.ErrNotFound) {
		t.Fatal(err)
	}
	if err = worker.enqueueDueVolumeBackup(ctx); err != nil && !errors.Is(err, store.ErrNotFound) {
		t.Fatal(err)
	}
	var databaseLastRun, volumeLastRun *time.Time
	if err = db.Pool.QueryRow(ctx, `SELECT last_run_at FROM backup_policies WHERE id=$1`, databasePolicyID).Scan(&databaseLastRun); err != nil || databaseLastRun != nil {
		t.Fatalf("database policy ran behind active backup: lastRun=%v err=%v", databaseLastRun, err)
	}
	if err = db.Pool.QueryRow(ctx, `SELECT last_run_at FROM volume_backup_policies WHERE id=$1`, volumePolicyID).Scan(&volumeLastRun); err != nil || volumeLastRun != nil {
		t.Fatalf("volume policy ran behind active backup: lastRun=%v err=%v", volumeLastRun, err)
	}
	if _, err = db.Pool.Exec(ctx, `UPDATE database_backups SET status='cancelled',finished_at=now() WHERE id=$1`, databaseBackupID); err != nil {
		t.Fatal(err)
	}
	if _, err = db.Pool.Exec(ctx, `UPDATE volume_backups SET status='cancelled',finished_at=now() WHERE id=$1`, volumeBackupID); err != nil {
		t.Fatal(err)
	}
	if err = worker.enqueueDueBackup(ctx); err != nil && !errors.Is(err, store.ErrNotFound) {
		t.Fatal(err)
	}
	if err = worker.enqueueDueVolumeBackup(ctx); err != nil && !errors.Is(err, store.ErrNotFound) {
		t.Fatal(err)
	}
	if err = db.Pool.QueryRow(ctx, `SELECT last_run_at FROM backup_policies WHERE id=$1`, databasePolicyID).Scan(&databaseLastRun); err != nil || databaseLastRun != nil {
		t.Fatalf("database policy ran while its durable job remained active: lastRun=%v err=%v", databaseLastRun, err)
	}
	if err = db.Pool.QueryRow(ctx, `SELECT last_run_at FROM volume_backup_policies WHERE id=$1`, volumePolicyID).Scan(&volumeLastRun); err != nil || volumeLastRun != nil {
		t.Fatalf("volume policy ran while its durable job remained active: lastRun=%v err=%v", volumeLastRun, err)
	}
	if _, err = db.Pool.Exec(ctx, `UPDATE jobs SET status='cancelled',finished_at=now() WHERE id=ANY($1)`, []uuid.UUID{databaseJobID, volumeJobID}); err != nil {
		t.Fatal(err)
	}
	if err = worker.enqueueDueBackup(ctx); err != nil {
		t.Fatalf("database scheduler did not resume: %v", err)
	}
	if err = worker.enqueueDueVolumeBackup(ctx); err != nil {
		t.Fatalf("volume scheduler did not resume: %v", err)
	}
	if _, err = db.Pool.Exec(ctx, `UPDATE backup_policies SET next_run_at=now()-interval '1 minute' WHERE id=$1`, databasePolicyID); err != nil {
		t.Fatal(err)
	}
	if _, err = db.Pool.Exec(ctx, `UPDATE volume_backup_policies SET next_run_at=now()-interval '1 minute' WHERE id=$1`, volumePolicyID); err != nil {
		t.Fatal(err)
	}
	if err = worker.enqueueDueBackup(ctx); err != nil && !errors.Is(err, store.ErrNotFound) {
		t.Fatal(err)
	}
	if err = worker.enqueueDueVolumeBackup(ctx); err != nil && !errors.Is(err, store.ErrNotFound) {
		t.Fatal(err)
	}
	var activeDatabaseBackups, activeVolumeBackups int
	if err = db.Pool.QueryRow(ctx, `SELECT count(*) FROM database_backups WHERE database_instance_id=$1 AND status IN ('queued','running')`, databaseID).Scan(&activeDatabaseBackups); err != nil {
		t.Fatal(err)
	}
	if err = db.Pool.QueryRow(ctx, `SELECT count(*) FROM volume_backups WHERE compose_service_id=$1 AND volume_name='uploads' AND status IN ('queued','running')`, volumeServiceID).Scan(&activeVolumeBackups); err != nil {
		t.Fatal(err)
	}
	if activeDatabaseBackups != 1 || activeVolumeBackups != 1 {
		t.Fatalf("active backups database=%d volume=%d, want one each", activeDatabaseBackups, activeVolumeBackups)
	}
	if _, err = db.Pool.Exec(ctx, `UPDATE database_backups SET status='cancelled',finished_at=now() WHERE database_instance_id=$1 AND status IN ('queued','running')`, databaseID); err != nil {
		t.Fatal(err)
	}
	if _, err = db.Pool.Exec(ctx, `UPDATE volume_backups SET status='cancelled',finished_at=now() WHERE compose_service_id=$1 AND status IN ('queued','running')`, volumeServiceID); err != nil {
		t.Fatal(err)
	}
	if _, err = db.Pool.Exec(ctx, `UPDATE jobs SET status='cancelled',finished_at=now() WHERE resource_key=ANY($1) AND status IN ('pending','running')`, []string{"database:" + databaseID.String(), "service:" + volumeServiceID.String()}); err != nil {
		t.Fatal(err)
	}
	if err = db.QueueServiceDeletion(ctx, organizationID, databaseServiceID); err != nil {
		t.Fatal(err)
	}
	if err = db.QueueServiceDeletion(ctx, organizationID, volumeServiceID); err != nil {
		t.Fatal(err)
	}
	if err = db.Pool.QueryRow(ctx, `UPDATE backup_policies SET next_run_at='2000-01-01' WHERE id=$1 RETURNING last_run_at`, databasePolicyID).Scan(&databaseLastRun); err != nil {
		t.Fatal(err)
	}
	if err = db.Pool.QueryRow(ctx, `UPDATE volume_backup_policies SET next_run_at='2000-01-01' WHERE id=$1 RETURNING last_run_at`, volumePolicyID).Scan(&volumeLastRun); err != nil {
		t.Fatal(err)
	}
	if err = worker.enqueueDueBackup(ctx); err != nil && !errors.Is(err, store.ErrNotFound) {
		t.Fatal(err)
	}
	if err = worker.enqueueDueVolumeBackup(ctx); err != nil && !errors.Is(err, store.ErrNotFound) {
		t.Fatal(err)
	}
	var databaseLastRunAfter, volumeLastRunAfter *time.Time
	if err = db.Pool.QueryRow(ctx, `SELECT last_run_at FROM backup_policies WHERE id=$1`, databasePolicyID).Scan(&databaseLastRunAfter); err != nil || !sameOptionalTime(databaseLastRun, databaseLastRunAfter) {
		t.Fatalf("database policy ran after service deletion: before=%v after=%v err=%v", databaseLastRun, databaseLastRunAfter, err)
	}
	if err = db.Pool.QueryRow(ctx, `SELECT last_run_at FROM volume_backup_policies WHERE id=$1`, volumePolicyID).Scan(&volumeLastRunAfter); err != nil || !sameOptionalTime(volumeLastRun, volumeLastRunAfter) {
		t.Fatalf("volume policy ran after service deletion: before=%v after=%v err=%v", volumeLastRun, volumeLastRunAfter, err)
	}
}

func sameOptionalTime(left, right *time.Time) bool {
	if left == nil || right == nil {
		return left == nil && right == nil
	}
	return left.Equal(*right)
}
