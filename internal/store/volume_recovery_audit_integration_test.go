package store

import (
	"context"
	"errors"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

func TestVolumeRecoveryMutationsCommitWithAudit(t *testing.T) {
	pool, ctx := migrationTestPool(t)
	if err := Migrate(ctx, pool); err != nil {
		t.Fatal(err)
	}
	db := &Store{Pool: pool}
	organizationID, userID, serviceAccountID := uuid.New(), uuid.New(), uuid.New()
	projectID, environmentID, serviceID, destinationID := uuid.New(), uuid.New(), uuid.New(), uuid.New()
	compose := "services:\n  app:\n    image: nginx\n    volumes: [uploads:/data]\nvolumes:\n  uploads: {}\n"
	for _, statement := range []struct {
		query string
		args  []any
	}{
		{`INSERT INTO organizations(id,name,slug) VALUES($1,'Volume recovery audit',$2)`, []any{organizationID, "volume-recovery-audit-" + organizationID.String()}},
		{`INSERT INTO users(id,email,password_hash) VALUES($1,$2,'!test')`, []any{userID, userID.String() + "@example.test"}},
		{`INSERT INTO service_accounts(id,organization_id,name,role) VALUES($1,$2,'volume-operator','admin')`, []any{serviceAccountID, organizationID}},
		{`INSERT INTO projects(id,organization_id,name,slug) VALUES($1,$2,'Project','project')`, []any{projectID, organizationID}},
		{`INSERT INTO environments(id,project_id,name,slug) VALUES($1,$2,'Production','production')`, []any{environmentID, projectID}},
		{`INSERT INTO compose_services(id,environment_id,name,slug,stack_name,storage_node_id,compose_yaml) VALUES($1,$2,'App','app',$3,'node1',$4)`, []any{serviceID, environmentID, "volume-recovery-audit-" + serviceID.String(), compose}},
		{`INSERT INTO backup_destinations(id,organization_id,name,endpoint,bucket,use_tls,encrypted_credentials) VALUES($1,$2,'S3','https://s3.example.test','backups',true,'encrypted')`, []any{destinationID, organizationID}},
	} {
		if _, err := pool.Exec(ctx, statement.query, statement.args...); err != nil {
			t.Fatal(err)
		}
	}
	initialPolicy, err := db.UpsertVolumeBackupPolicy(ctx, organizationID, serviceID, "uploads", "node1", destinationID, 1800, 3, false, true)
	if err != nil {
		t.Fatal(err)
	}
	restorableBackupID := uuid.New()
	if _, err = pool.Exec(ctx, `INSERT INTO volume_backups(id,volume_backup_policy_id,compose_service_id,volume_name,storage_node_id,destination_id,quiesce,status,object_key,size_bytes,sha256,plaintext_sha256,encrypted_data_key,finished_at) VALUES($1,$2,$3,'uploads','node1',$4,false,'succeeded','volumes/object.enc',42,repeat('a',64),repeat('b',64),'wrapped',now())`, restorableBackupID, initialPolicy.ID, serviceID, destinationID); err != nil {
		t.Fatal(err)
	}
	malformedBackupID := uuid.New()
	if _, err = pool.Exec(ctx, `INSERT INTO volume_backups(id,volume_backup_policy_id,compose_service_id,volume_name,storage_node_id,destination_id,quiesce,status,finished_at) VALUES($1,$2,$3,'uploads','node1',$4,false,'succeeded',now())`, malformedBackupID, initialPolicy.ID, serviceID, destinationID); err != nil {
		t.Fatal(err)
	}
	principal := Principal{OrganizationID: organizationID, UserID: userID, Role: "owner"}
	servicePrincipal := Principal{OrganizationID: organizationID, ServiceAccountID: &serviceAccountID, Role: "admin"}
	if _, err = db.QueueVolumeRestoreWithAudit(ctx, servicePrincipal, malformedBackupID, "app", "127.0.0.1:1234"); !errors.Is(err, ErrBackupNotRestorable) {
		t.Fatalf("malformed volume backup restore error=%v, want ErrBackupNotRestorable", err)
	}
	assertVolumeRecoveryCounts(t, pool, ctx, serviceID, malformedBackupID, 0, 0)
	if _, err = pool.Exec(ctx, `CREATE FUNCTION reject_volume_recovery_audit() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF NEW.action IN ('volume_backup_policy.update','volume_backup_policy.delete','volume_backup.create','volume_restore.create') THEN RAISE EXCEPTION 'forced audit failure'; END IF; RETURN NEW; END $$`); err != nil {
		t.Fatal(err)
	}
	if _, err = pool.Exec(ctx, `CREATE TRIGGER reject_volume_recovery_audit BEFORE INSERT ON audit_events FOR EACH ROW EXECUTE FUNCTION reject_volume_recovery_audit()`); err != nil {
		t.Fatal(err)
	}
	if _, err = db.UpsertVolumeBackupPolicyWithAudit(ctx, servicePrincipal, serviceID, "uploads", "node1", destinationID, 3600, 7, true, false, "127.0.0.1:1234"); err == nil {
		t.Fatal("volume policy update succeeded after audit rejection")
	}
	assertVolumePolicy(t, db, ctx, organizationID, serviceID, initialPolicy.ID, 1800, 3, false, true)
	if err = db.DeleteVolumeBackupPolicyWithAudit(ctx, principal, serviceID, "uploads", "127.0.0.1:1234"); err == nil {
		t.Fatal("volume policy deletion succeeded after audit rejection")
	}
	assertVolumePolicy(t, db, ctx, organizationID, serviceID, initialPolicy.ID, 1800, 3, false, true)
	if _, err = db.QueueVolumeBackupWithAudit(ctx, principal, serviceID, "uploads", "127.0.0.1:1234"); err == nil {
		t.Fatal("volume backup creation succeeded after audit rejection")
	}
	assertVolumeRecoveryCounts(t, pool, ctx, serviceID, restorableBackupID, 0, 0)
	if _, err = db.QueueVolumeRestoreWithAudit(ctx, servicePrincipal, restorableBackupID, "app", "127.0.0.1:1234"); err == nil {
		t.Fatal("volume restore creation succeeded after audit rejection")
	}
	assertVolumeRecoveryCounts(t, pool, ctx, serviceID, restorableBackupID, 0, 0)
	if _, err = pool.Exec(ctx, `DROP TRIGGER reject_volume_recovery_audit ON audit_events`); err != nil {
		t.Fatal(err)
	}
	if _, err = pool.Exec(ctx, `DROP FUNCTION reject_volume_recovery_audit()`); err != nil {
		t.Fatal(err)
	}

	if _, err = db.UpsertVolumeBackupPolicyWithAudit(ctx, servicePrincipal, serviceID, "uploads", "node1", destinationID, 3600, 7, true, false, "127.0.0.1:1234"); err != nil {
		t.Fatal(err)
	}
	backup, err := db.QueueVolumeBackupWithAudit(ctx, principal, serviceID, "uploads", "127.0.0.1:1234")
	if err != nil {
		t.Fatal(err)
	}
	if err = db.CancelVolumeBackup(ctx, organizationID, backup.ID); err != nil {
		t.Fatal(err)
	}
	if err = db.DeleteVolumeBackupPolicyWithAudit(ctx, principal, serviceID, "uploads", "127.0.0.1:1234"); err != nil {
		t.Fatal(err)
	}
	restore, err := db.QueueVolumeRestoreWithAudit(ctx, servicePrincipal, restorableBackupID, "app", "127.0.0.1:1234")
	if err != nil {
		t.Fatal(err)
	}
	var userAudits, serviceAudits, backupActors, restoreActors int
	if err = pool.QueryRow(ctx, `SELECT count(*) FROM audit_events WHERE organization_id=$1 AND actor_user_id=$2 AND actor_service_account_id IS NULL AND action IN ('volume_backup.create','volume_backup_policy.delete')`, organizationID, userID).Scan(&userAudits); err != nil {
		t.Fatal(err)
	}
	if err = pool.QueryRow(ctx, `SELECT count(*) FROM audit_events WHERE organization_id=$1 AND actor_user_id IS NULL AND actor_service_account_id=$2 AND action IN ('volume_backup_policy.update','volume_restore.create')`, organizationID, serviceAccountID).Scan(&serviceAudits); err != nil {
		t.Fatal(err)
	}
	if err = pool.QueryRow(ctx, `SELECT count(*) FROM volume_backups WHERE id=$1 AND actor_user_id=$2`, backup.ID, userID).Scan(&backupActors); err != nil {
		t.Fatal(err)
	}
	if err = pool.QueryRow(ctx, `SELECT count(*) FROM volume_restores WHERE id=$1 AND actor_user_id IS NULL`, restore.ID).Scan(&restoreActors); err != nil {
		t.Fatal(err)
	}
	if userAudits != 2 || serviceAudits != 2 || backupActors != 1 || restoreActors != 1 {
		t.Fatalf("volume recovery attribution: user audits=%d service audits=%d backup actors=%d restore actors=%d", userAudits, serviceAudits, backupActors, restoreActors)
	}
}

func assertVolumePolicy(t *testing.T, db *Store, ctx context.Context, organizationID, serviceID, policyID uuid.UUID, intervalSeconds, retentionCount int, quiesce, enabled bool) {
	t.Helper()
	items, err := db.ListVolumeBackupPolicies(ctx, organizationID, serviceID)
	if err != nil {
		t.Fatal(err)
	}
	if len(items) != 1 || items[0].ID != policyID || items[0].IntervalSeconds != intervalSeconds || items[0].RetentionCount != retentionCount || items[0].Quiesce != quiesce || items[0].Enabled != enabled {
		t.Fatalf("volume backup policy after audit rejection: %#v", items)
	}
}

func assertVolumeRecoveryCounts(t *testing.T, pool interface {
	QueryRow(ctx context.Context, sql string, args ...any) pgx.Row
}, ctx context.Context, serviceID, backupID uuid.UUID, queuedBackups, queuedRestores int) {
	t.Helper()
	var backupCount, backupJobCount, restoreCount, restoreJobCount int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM volume_backups WHERE compose_service_id=$1 AND status='queued'`, serviceID).Scan(&backupCount); err != nil {
		t.Fatal(err)
	}
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM jobs WHERE kind='backup.volume' AND resource_key=$1`, "service:"+serviceID.String()).Scan(&backupJobCount); err != nil {
		t.Fatal(err)
	}
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM volume_restores WHERE volume_backup_id=$1 AND status='queued'`, backupID).Scan(&restoreCount); err != nil {
		t.Fatal(err)
	}
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM jobs WHERE kind='restore.volume' AND resource_key=$1`, "service:"+serviceID.String()).Scan(&restoreJobCount); err != nil {
		t.Fatal(err)
	}
	if backupCount != queuedBackups || backupJobCount != queuedBackups || restoreCount != queuedRestores || restoreJobCount != queuedRestores {
		t.Fatalf("volume recovery state: backups=%d backup jobs=%d restores=%d restore jobs=%d", backupCount, backupJobCount, restoreCount, restoreJobCount)
	}
}
