package store

import (
	"context"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

func TestDatabaseRecoveryMutationsCommitWithAudit(t *testing.T) {
	pool, ctx := migrationTestPool(t)
	if err := Migrate(ctx, pool); err != nil {
		t.Fatal(err)
	}
	db := &Store{Pool: pool}
	organizationID, userID, serviceAccountID := uuid.New(), uuid.New(), uuid.New()
	projectID, environmentID, serviceID, databaseID, destinationID := uuid.New(), uuid.New(), uuid.New(), uuid.New(), uuid.New()
	for _, statement := range []struct {
		query string
		args  []any
	}{
		{`INSERT INTO organizations(id,name,slug) VALUES($1,'Database recovery audit',$2)`, []any{organizationID, "database-recovery-audit-" + organizationID.String()}},
		{`INSERT INTO users(id,email,password_hash) VALUES($1,$2,'!test')`, []any{userID, userID.String() + "@example.test"}},
		{`INSERT INTO service_accounts(id,organization_id,name,role) VALUES($1,$2,'recovery-operator','admin')`, []any{serviceAccountID, organizationID}},
		{`INSERT INTO projects(id,organization_id,name,slug) VALUES($1,$2,'Project','project')`, []any{projectID, organizationID}},
		{`INSERT INTO environments(id,project_id,name,slug) VALUES($1,$2,'Production','production')`, []any{environmentID, projectID}},
		{`INSERT INTO compose_services(id,environment_id,name,slug,stack_name,compose_yaml) VALUES($1,$2,'Database','database',$3,'services: {}')`, []any{serviceID, environmentID, "database-recovery-audit-" + serviceID.String()}},
		{`INSERT INTO database_instances(id,environment_id,name,slug,engine,version,compose_service_id,encrypted_credentials,status) VALUES($1,$2,'Database','database','postgres','17',$3,'encrypted','running')`, []any{databaseID, environmentID, serviceID}},
		{`INSERT INTO backup_destinations(id,organization_id,name,endpoint,bucket,use_tls,encrypted_credentials) VALUES($1,$2,'S3','https://s3.example.test','backups',true,'encrypted')`, []any{destinationID, organizationID}},
	} {
		if _, err := pool.Exec(ctx, statement.query, statement.args...); err != nil {
			t.Fatal(err)
		}
	}
	principal := Principal{OrganizationID: organizationID, UserID: userID, Role: "owner"}
	servicePrincipal := Principal{OrganizationID: organizationID, ServiceAccountID: &serviceAccountID, Role: "admin"}

	initialPolicy, err := db.UpsertBackupPolicy(ctx, organizationID, databaseID, 1800, 3, true, false, &destinationID)
	if err != nil {
		t.Fatal(err)
	}
	restorableBackupID := uuid.New()
	if _, err = pool.Exec(ctx, `INSERT INTO database_backups(id,database_instance_id,status,format,destination_id,finished_at) VALUES($1,$2,'succeeded','native',$3,now())`, restorableBackupID, databaseID, destinationID); err != nil {
		t.Fatal(err)
	}
	if _, err = pool.Exec(ctx, `CREATE FUNCTION reject_database_recovery_audit() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF NEW.action IN ('database.backup.create','backup_policy.update','backup_policy.delete','database.restore.create') THEN RAISE EXCEPTION 'forced audit failure'; END IF; RETURN NEW; END $$`); err != nil {
		t.Fatal(err)
	}
	if _, err = pool.Exec(ctx, `CREATE TRIGGER reject_database_recovery_audit BEFORE INSERT ON audit_events FOR EACH ROW EXECUTE FUNCTION reject_database_recovery_audit()`); err != nil {
		t.Fatal(err)
	}

	if _, err = db.QueueDatabaseBackupWithAudit(ctx, principal, databaseID, &destinationID, "127.0.0.1:1234"); err == nil {
		t.Fatal("database backup creation succeeded after audit rejection")
	}
	assertRecoveryCounts(t, pool, ctx, databaseID, restorableBackupID, 0, 0)
	if _, err = db.UpsertBackupPolicyWithAudit(ctx, principal, databaseID, 3600, 7, false, true, &destinationID, "127.0.0.1:1234"); err == nil {
		t.Fatal("backup policy update succeeded after audit rejection")
	}
	assertBackupPolicy(t, db, ctx, organizationID, databaseID, initialPolicy.ID, 1800, 3, true, false)
	if err = db.DeleteBackupPolicyWithAudit(ctx, principal, databaseID, "127.0.0.1:1234"); err == nil {
		t.Fatal("backup policy deletion succeeded after audit rejection")
	}
	assertBackupPolicy(t, db, ctx, organizationID, databaseID, initialPolicy.ID, 1800, 3, true, false)
	if _, err = db.QueueDatabaseRestoreWithAudit(ctx, principal, restorableBackupID, "database", "127.0.0.1:1234"); err == nil {
		t.Fatal("database restore creation succeeded after audit rejection")
	}
	assertRecoveryCounts(t, pool, ctx, databaseID, restorableBackupID, 0, 0)

	if _, err = pool.Exec(ctx, `DROP TRIGGER reject_database_recovery_audit ON audit_events`); err != nil {
		t.Fatal(err)
	}
	if _, err = pool.Exec(ctx, `DROP FUNCTION reject_database_recovery_audit()`); err != nil {
		t.Fatal(err)
	}
	backup, err := db.QueueDatabaseBackupWithAudit(ctx, principal, databaseID, &destinationID, "127.0.0.1:1234")
	if err != nil {
		t.Fatal(err)
	}
	if _, err = db.UpsertBackupPolicyWithAudit(ctx, servicePrincipal, databaseID, 3600, 7, false, true, &destinationID, "127.0.0.1:1234"); err != nil {
		t.Fatal(err)
	}
	if err = db.DeleteBackupPolicyWithAudit(ctx, principal, databaseID, "127.0.0.1:1234"); err != nil {
		t.Fatal(err)
	}
	restore, err := db.QueueDatabaseRestoreWithAudit(ctx, servicePrincipal, restorableBackupID, "database", "127.0.0.1:1234")
	if err != nil {
		t.Fatal(err)
	}
	assertRecoveryCounts(t, pool, ctx, databaseID, restorableBackupID, 1, 1)

	var userAuditCount, serviceAuditCount, backupActorCount, restoreActorCount int
	if err = pool.QueryRow(ctx, `SELECT count(*) FROM audit_events WHERE organization_id=$1 AND actor_user_id=$2 AND actor_service_account_id IS NULL AND action IN ('database.backup.create','backup_policy.delete')`, organizationID, userID).Scan(&userAuditCount); err != nil {
		t.Fatal(err)
	}
	if err = pool.QueryRow(ctx, `SELECT count(*) FROM audit_events WHERE organization_id=$1 AND actor_user_id IS NULL AND actor_service_account_id=$2 AND action IN ('backup_policy.update','database.restore.create')`, organizationID, serviceAccountID).Scan(&serviceAuditCount); err != nil {
		t.Fatal(err)
	}
	if err = pool.QueryRow(ctx, `SELECT count(*) FROM database_backups WHERE id=$1 AND actor_user_id=$2`, backup.ID, userID).Scan(&backupActorCount); err != nil {
		t.Fatal(err)
	}
	if err = pool.QueryRow(ctx, `SELECT count(*) FROM database_restores WHERE id=$1 AND actor_user_id IS NULL`, restore.ID).Scan(&restoreActorCount); err != nil {
		t.Fatal(err)
	}
	if userAuditCount != 2 || serviceAuditCount != 2 || backupActorCount != 1 || restoreActorCount != 1 {
		t.Fatalf("recovery attribution: user audits=%d service audits=%d backup actor=%d restore actor=%d", userAuditCount, serviceAuditCount, backupActorCount, restoreActorCount)
	}
}

func assertRecoveryCounts(t *testing.T, pool interface {
	QueryRow(ctx context.Context, sql string, args ...any) pgx.Row
}, ctx context.Context, databaseID, backupID uuid.UUID, queuedBackups, queuedRestores int) {
	t.Helper()
	var backupCount, backupJobCount, restoreCount, restoreJobCount int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM database_backups WHERE database_instance_id=$1 AND status='queued'`, databaseID).Scan(&backupCount); err != nil {
		t.Fatal(err)
	}
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM jobs WHERE kind='backup.database' AND resource_key=$1`, "database:"+databaseID.String()).Scan(&backupJobCount); err != nil {
		t.Fatal(err)
	}
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM database_restores WHERE database_backup_id=$1 AND status='queued'`, backupID).Scan(&restoreCount); err != nil {
		t.Fatal(err)
	}
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM jobs WHERE kind='restore.database' AND resource_key=$1`, "database:"+databaseID.String()).Scan(&restoreJobCount); err != nil {
		t.Fatal(err)
	}
	if backupCount != queuedBackups || backupJobCount != queuedBackups || restoreCount != queuedRestores || restoreJobCount != queuedRestores {
		t.Fatalf("recovery state: backups=%d backup jobs=%d restores=%d restore jobs=%d", backupCount, backupJobCount, restoreCount, restoreJobCount)
	}
}

func assertBackupPolicy(t *testing.T, db *Store, ctx context.Context, organizationID, databaseID, policyID uuid.UUID, intervalSeconds, retentionCount int, enabled, verifyRestore bool) {
	t.Helper()
	policy, err := db.GetBackupPolicy(ctx, organizationID, databaseID)
	if err != nil {
		t.Fatal(err)
	}
	if policy.ID != policyID || policy.IntervalSeconds != intervalSeconds || policy.RetentionCount != retentionCount || policy.Enabled != enabled || policy.VerifyRestore != verifyRestore {
		t.Fatalf("backup policy after audit rejection: %#v", policy)
	}
}
