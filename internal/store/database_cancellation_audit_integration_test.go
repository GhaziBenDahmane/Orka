package store

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

func TestDatabaseOperationCancellationCommitsWithAudit(t *testing.T) {
	pool, ctx := migrationTestPool(t)
	if err := Migrate(ctx, pool); err != nil {
		t.Fatal(err)
	}
	db := &Store{Pool: pool}
	organizationID, userID := uuid.New(), uuid.New()
	projectID, environmentID, serviceID, databaseID, destinationID := uuid.New(), uuid.New(), uuid.New(), uuid.New(), uuid.New()
	for _, statement := range []struct {
		query string
		args  []any
	}{
		{`INSERT INTO organizations(id,name,slug) VALUES($1,'Database cancellation audit',$2)`, []any{organizationID, "database-cancellation-audit-" + organizationID.String()}},
		{`INSERT INTO users(id,email,password_hash) VALUES($1,$2,'!test')`, []any{userID, userID.String() + "@example.test"}},
		{`INSERT INTO projects(id,organization_id,name,slug) VALUES($1,$2,'Project','project')`, []any{projectID, organizationID}},
		{`INSERT INTO environments(id,project_id,name,slug) VALUES($1,$2,'Production','production')`, []any{environmentID, projectID}},
		{`INSERT INTO compose_services(id,environment_id,name,slug,stack_name,compose_yaml) VALUES($1,$2,'Database','database',$3,'services: {}')`, []any{serviceID, environmentID, "database-cancellation-audit-" + serviceID.String()}},
		{`INSERT INTO database_instances(id,environment_id,name,slug,engine,version,compose_service_id,encrypted_credentials,status) VALUES($1,$2,'Database','database','postgres','17',$3,'encrypted','running')`, []any{databaseID, environmentID, serviceID}},
		{`INSERT INTO backup_destinations(id,organization_id,name,endpoint,bucket,use_tls,encrypted_credentials) VALUES($1,$2,'S3','https://s3.example.test','backups',true,'encrypted')`, []any{destinationID, organizationID}},
	} {
		if _, err := pool.Exec(ctx, statement.query, statement.args...); err != nil {
			t.Fatal(err)
		}
	}
	principal := Principal{OrganizationID: organizationID, UserID: userID, Role: "owner"}
	invalidPrincipal := Principal{OrganizationID: organizationID, UserID: uuid.New(), Role: "owner"}

	backup, err := db.QueueDatabaseBackup(ctx, organizationID, databaseID, userID, &destinationID)
	if err != nil {
		t.Fatal(err)
	}
	if err = db.CancelDatabaseBackupWithAudit(ctx, invalidPrincipal, backup.ID, "127.0.0.1:1234"); err == nil {
		t.Fatal("database backup cancellation succeeded without valid audit evidence")
	}
	assertDatabaseCancellationState(t, pool, ctx, "database_backups", "backup.database", "backupId", backup.ID, "queued", "pending", false)
	if err = db.CancelDatabaseBackupWithAudit(ctx, principal, backup.ID, "127.0.0.1:1234"); err != nil {
		t.Fatal(err)
	}
	assertDatabaseCancellationState(t, pool, ctx, "database_backups", "backup.database", "backupId", backup.ID, "cancelled", "cancelled", true)

	restorableBackupID := uuid.New()
	if _, err = pool.Exec(ctx, `INSERT INTO database_backups(id,database_instance_id,status,format,destination_id,finished_at) VALUES($1,$2,'succeeded','native',$3,now())`, restorableBackupID, databaseID, destinationID); err != nil {
		t.Fatal(err)
	}
	restore, err := db.QueueDatabaseRestore(ctx, organizationID, restorableBackupID, userID, "database")
	if err != nil {
		t.Fatal(err)
	}
	if err = db.CancelDatabaseRestoreWithAudit(ctx, invalidPrincipal, restore.ID, "127.0.0.1:1234"); err == nil {
		t.Fatal("database restore cancellation succeeded without valid audit evidence")
	}
	assertDatabaseCancellationState(t, pool, ctx, "database_restores", "restore.database", "restoreId", restore.ID, "queued", "pending", false)
	if err = db.CancelDatabaseRestoreWithAudit(ctx, principal, restore.ID, "127.0.0.1:1234"); err != nil {
		t.Fatal(err)
	}
	assertDatabaseCancellationState(t, pool, ctx, "database_restores", "restore.database", "restoreId", restore.ID, "cancelled", "cancelled", true)

	migration, err := db.QueueDatabaseMigration(ctx, organizationID, DatabaseMigration{DatabaseInstanceID: databaseID, SourceKind: "dokploy", SourceID: "source-db", SourceEngine: "postgres", SourceVersion: "16", SourceHost: "source.internal", EncryptedSourceConfig: "encrypted-source"})
	if err != nil {
		t.Fatal(err)
	}
	if err = db.CancelDatabaseMigrationWithAudit(ctx, invalidPrincipal, migration.ID, "127.0.0.1:1234"); err == nil {
		t.Fatal("database migration cancellation succeeded without valid audit evidence")
	}
	assertDatabaseCancellationState(t, pool, ctx, "database_migrations", "migrate.database", "migrationId", migration.ID, "queued", "pending", false)
	if err = db.CancelDatabaseMigrationWithAudit(ctx, principal, migration.ID, "127.0.0.1:1234"); err != nil {
		t.Fatal(err)
	}
	assertDatabaseCancellationState(t, pool, ctx, "database_migrations", "migrate.database", "migrationId", migration.ID, "cancelled", "cancelled", true)

	var auditCount int
	if err = pool.QueryRow(ctx, `SELECT count(*) FROM audit_events WHERE organization_id=$1 AND actor_user_id=$2 AND action IN ('database_backup.cancel','database_restore.cancel','database_migration.cancel')`, organizationID, userID).Scan(&auditCount); err != nil || auditCount != 3 {
		t.Fatalf("database cancellation audit count=%d err=%v", auditCount, err)
	}
}

func assertDatabaseCancellationState(t *testing.T, pool interface {
	QueryRow(ctx context.Context, sql string, args ...any) pgx.Row
}, ctx context.Context, table, jobKind, payloadKey string, resourceID uuid.UUID, wantResource, wantJob string, wantRequested bool) {
	t.Helper()
	var resourceStatus, jobStatus string
	var cancelRequestedAt *time.Time
	if err := pool.QueryRow(ctx, `SELECT status FROM `+table+` WHERE id=$1`, resourceID).Scan(&resourceStatus); err != nil {
		t.Fatal(err)
	}
	if err := pool.QueryRow(ctx, `SELECT status,cancel_requested_at FROM jobs WHERE kind=$1 AND payload->>$2=$3`, jobKind, payloadKey, resourceID.String()).Scan(&jobStatus, &cancelRequestedAt); err != nil {
		t.Fatal(err)
	}
	if resourceStatus != wantResource || jobStatus != wantJob || (cancelRequestedAt != nil) != wantRequested {
		t.Fatalf("cancellation state for %s: resource=%q job=%q requested=%v", table, resourceStatus, jobStatus, cancelRequestedAt)
	}
}
