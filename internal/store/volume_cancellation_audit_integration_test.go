package store

import (
	"testing"

	"github.com/google/uuid"
)

func TestVolumeOperationCancellationCommitsWithAudit(t *testing.T) {
	pool, ctx := migrationTestPool(t)
	if err := Migrate(ctx, pool); err != nil {
		t.Fatal(err)
	}
	db := &Store{Pool: pool}
	organizationID, userID := uuid.New(), uuid.New()
	projectID, environmentID, serviceID, destinationID, policyID := uuid.New(), uuid.New(), uuid.New(), uuid.New(), uuid.New()
	for _, statement := range []struct {
		query string
		args  []any
	}{
		{`INSERT INTO organizations(id,name,slug) VALUES($1,'Volume cancellation audit',$2)`, []any{organizationID, "volume-cancellation-audit-" + organizationID.String()}},
		{`INSERT INTO users(id,email,password_hash) VALUES($1,$2,'!test')`, []any{userID, userID.String() + "@example.test"}},
		{`INSERT INTO projects(id,organization_id,name,slug) VALUES($1,$2,'Project','project')`, []any{projectID, organizationID}},
		{`INSERT INTO environments(id,project_id,name,slug) VALUES($1,$2,'Production','production')`, []any{environmentID, projectID}},
		{`INSERT INTO compose_services(id,environment_id,name,slug,stack_name,storage_node_id,compose_yaml) VALUES($1,$2,'App','app',$3,'node1',$4)`, []any{serviceID, environmentID, "volume-cancellation-audit-" + serviceID.String(), "services:\n  app:\n    image: nginx\n    volumes: [uploads:/data]\nvolumes:\n  uploads: {}\n"}},
		{`INSERT INTO backup_destinations(id,organization_id,name,endpoint,bucket,use_tls,encrypted_credentials) VALUES($1,$2,'S3','https://s3.example.test','backups',true,'encrypted')`, []any{destinationID, organizationID}},
		{`INSERT INTO volume_backup_policies(id,compose_service_id,volume_name,destination_id,interval_seconds,retention_count,quiesce,enabled,next_run_at) VALUES($1,$2,'uploads',$3,3600,7,true,true,now()+interval '1 hour')`, []any{policyID, serviceID, destinationID}},
	} {
		if _, err := pool.Exec(ctx, statement.query, statement.args...); err != nil {
			t.Fatal(err)
		}
	}
	principal := Principal{OrganizationID: organizationID, UserID: userID, Role: "owner"}
	invalidPrincipal := Principal{OrganizationID: organizationID, UserID: uuid.New(), Role: "owner"}

	backup, err := db.QueueVolumeBackup(ctx, organizationID, serviceID, "uploads", userID)
	if err != nil {
		t.Fatal(err)
	}
	if err = db.CancelVolumeBackupWithAudit(ctx, invalidPrincipal, backup.ID, "127.0.0.1:1234"); err == nil {
		t.Fatal("volume backup cancellation succeeded without valid audit evidence")
	}
	assertDatabaseCancellationState(t, pool, ctx, "volume_backups", "backup.volume", "backupId", backup.ID, "queued", "pending", false)
	if err = db.CancelVolumeBackupWithAudit(ctx, principal, backup.ID, "127.0.0.1:1234"); err != nil {
		t.Fatal(err)
	}
	assertDatabaseCancellationState(t, pool, ctx, "volume_backups", "backup.volume", "backupId", backup.ID, "cancelled", "cancelled", true)

	restorableBackupID := uuid.New()
	if _, err = pool.Exec(ctx, `INSERT INTO volume_backups(id,volume_backup_policy_id,compose_service_id,volume_name,storage_node_id,destination_id,quiesce,status,finished_at) VALUES($1,$2,$3,'uploads','node1',$4,true,'succeeded',now())`, restorableBackupID, policyID, serviceID, destinationID); err != nil {
		t.Fatal(err)
	}
	restore, err := db.QueueVolumeRestore(ctx, organizationID, restorableBackupID, userID, "app")
	if err != nil {
		t.Fatal(err)
	}
	if err = db.CancelVolumeRestoreWithAudit(ctx, invalidPrincipal, restore.ID, "127.0.0.1:1234"); err == nil {
		t.Fatal("volume restore cancellation succeeded without valid audit evidence")
	}
	assertDatabaseCancellationState(t, pool, ctx, "volume_restores", "restore.volume", "restoreId", restore.ID, "queued", "pending", false)
	if err = db.CancelVolumeRestoreWithAudit(ctx, principal, restore.ID, "127.0.0.1:1234"); err != nil {
		t.Fatal(err)
	}
	assertDatabaseCancellationState(t, pool, ctx, "volume_restores", "restore.volume", "restoreId", restore.ID, "cancelled", "cancelled", true)

	var auditCount int
	if err = pool.QueryRow(ctx, `SELECT count(*) FROM audit_events WHERE organization_id=$1 AND actor_user_id=$2 AND action IN ('volume_backup.cancel','volume_restore.cancel')`, organizationID, userID).Scan(&auditCount); err != nil || auditCount != 2 {
		t.Fatalf("volume cancellation audit count=%d err=%v", auditCount, err)
	}
}
