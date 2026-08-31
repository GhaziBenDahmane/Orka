package store

import (
	"context"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

func TestDatabaseLifecycleCommitsWithAudit(t *testing.T) {
	pool, ctx := migrationTestPool(t)
	if err := Migrate(ctx, pool); err != nil {
		t.Fatal(err)
	}
	db := &Store{Pool: pool}
	organizationID, userID, serviceAccountID := uuid.New(), uuid.New(), uuid.New()
	projectID, environmentID := uuid.New(), uuid.New()
	for _, statement := range []struct {
		query string
		args  []any
	}{
		{`INSERT INTO organizations(id,name,slug) VALUES($1,'Database lifecycle audit',$2)`, []any{organizationID, "database-lifecycle-audit-" + organizationID.String()}},
		{`INSERT INTO users(id,email,password_hash) VALUES($1,$2,'!test')`, []any{userID, userID.String() + "@example.test"}},
		{`INSERT INTO service_accounts(id,organization_id,name,role) VALUES($1,$2,'lifecycle-operator','admin')`, []any{serviceAccountID, organizationID}},
		{`INSERT INTO projects(id,organization_id,name,slug) VALUES($1,$2,'Project','project')`, []any{projectID, organizationID}},
		{`INSERT INTO environments(id,project_id,name,slug) VALUES($1,$2,'Production','production')`, []any{environmentID, projectID}},
	} {
		if _, err := pool.Exec(ctx, statement.query, statement.args...); err != nil {
			t.Fatal(err)
		}
	}
	principal := Principal{OrganizationID: organizationID, UserID: userID, Role: "owner"}
	servicePrincipal := Principal{OrganizationID: organizationID, ServiceAccountID: &serviceAccountID, Role: "admin"}
	failedDatabaseID, failedServiceID := uuid.New(), uuid.New()
	createAuditFailureTrigger(t, pool, ctx)
	if _, err := db.CreateDatabaseWithAudit(ctx, principal,
		DatabaseInstance{ID: failedDatabaseID, EnvironmentID: environmentID, Name: "Failed", Slug: "failed", Engine: "postgres", Version: "17", DriverSource: "built-in"},
		ComposeService{ID: failedServiceID, Name: "Failed", Slug: "db-failed", StackName: "db-failed", ComposeYAML: "services: {}"},
		"encrypted", "127.0.0.1:1234"); err == nil {
		t.Fatal("database creation succeeded after audit rejection")
	}
	assertDatabaseLifecycleState(t, pool, ctx, failedDatabaseID, failedServiceID, false, false)
	dropAuditFailureTrigger(t, pool, ctx, false)

	databaseID, databaseServiceID := uuid.New(), uuid.New()
	instance, err := db.CreateDatabaseWithAudit(ctx, principal,
		DatabaseInstance{ID: databaseID, EnvironmentID: environmentID, Name: "Postgres", Slug: "postgres", Engine: "postgres", Version: "17", DriverSource: "built-in"},
		ComposeService{ID: databaseServiceID, Name: "Postgres", Slug: "db-postgres", StackName: "db-postgres", ComposeYAML: "services: {}"},
		"encrypted", "127.0.0.1:1234")
	if err != nil {
		t.Fatal(err)
	}
	plainServiceID := uuid.New()
	if _, err = db.CreateComposeService(ctx, organizationID, ComposeService{ID: plainServiceID, EnvironmentID: environmentID, Name: "Application", Slug: "application", StackName: "application", ComposeYAML: "services: {}"}); err != nil {
		t.Fatal(err)
	}

	createAuditFailureTrigger(t, pool, ctx)
	if err = db.QueueDatabaseDeletionWithAudit(ctx, servicePrincipal, instance.ID, "127.0.0.1:1234"); err == nil {
		t.Fatal("database deletion succeeded after audit rejection")
	}
	assertDatabaseLifecycleState(t, pool, ctx, instance.ID, databaseServiceID, true, false)
	if err = db.QueueServiceDeletionWithAudit(ctx, principal, plainServiceID, true, "127.0.0.1:1234"); err == nil {
		t.Fatal("service deletion succeeded after audit rejection")
	}
	assertServiceDeletionState(t, pool, ctx, plainServiceID, false, 0, false)
	dropAuditFailureTrigger(t, pool, ctx, true)

	if err = db.QueueDatabaseDeletionWithAudit(ctx, servicePrincipal, instance.ID, "127.0.0.1:1234"); err != nil {
		t.Fatal(err)
	}
	if err = db.QueueServiceDeletionWithAudit(ctx, principal, plainServiceID, true, "127.0.0.1:1234"); err != nil {
		t.Fatal(err)
	}
	assertDatabaseLifecycleState(t, pool, ctx, instance.ID, databaseServiceID, true, true)
	assertServiceDeletionState(t, pool, ctx, plainServiceID, true, 1, true)

	var createAudit, databaseDeleteAudit, serviceDeleteAudit int
	if err = pool.QueryRow(ctx, `SELECT count(*) FROM audit_events WHERE organization_id=$1 AND actor_user_id=$2 AND actor_service_account_id IS NULL AND action='database.create' AND resource_id=$3`, organizationID, userID, instance.ID.String()).Scan(&createAudit); err != nil {
		t.Fatal(err)
	}
	if err = pool.QueryRow(ctx, `SELECT count(*) FROM audit_events WHERE organization_id=$1 AND actor_user_id IS NULL AND actor_service_account_id=$2 AND action='database.delete' AND resource_id=$3`, organizationID, serviceAccountID, instance.ID.String()).Scan(&databaseDeleteAudit); err != nil {
		t.Fatal(err)
	}
	if err = pool.QueryRow(ctx, `SELECT count(*) FROM audit_events WHERE organization_id=$1 AND actor_user_id=$2 AND action='service.delete' AND resource_id=$3 AND metadata->>'deleteVolumes'='true'`, organizationID, userID, plainServiceID.String()).Scan(&serviceDeleteAudit); err != nil {
		t.Fatal(err)
	}
	if createAudit != 1 || databaseDeleteAudit != 1 || serviceDeleteAudit != 1 {
		t.Fatalf("lifecycle audit counts: create=%d database delete=%d service delete=%d", createAudit, databaseDeleteAudit, serviceDeleteAudit)
	}
}

func createAuditFailureTrigger(t *testing.T, pool interface {
	Exec(ctx context.Context, sql string, arguments ...any) (pgconn.CommandTag, error)
}, ctx context.Context) {
	t.Helper()
	if _, err := pool.Exec(ctx, `CREATE OR REPLACE FUNCTION reject_database_lifecycle_audit() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF NEW.action IN ('database.create','database.delete','service.delete') THEN RAISE EXCEPTION 'forced audit failure'; END IF; RETURN NEW; END $$`); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `CREATE TRIGGER reject_database_lifecycle_audit BEFORE INSERT ON audit_events FOR EACH ROW EXECUTE FUNCTION reject_database_lifecycle_audit()`); err != nil {
		t.Fatal(err)
	}
}

func dropAuditFailureTrigger(t *testing.T, pool interface {
	Exec(ctx context.Context, sql string, arguments ...any) (pgconn.CommandTag, error)
}, ctx context.Context, dropFunction bool) {
	t.Helper()
	if _, err := pool.Exec(ctx, `DROP TRIGGER reject_database_lifecycle_audit ON audit_events`); err != nil {
		t.Fatal(err)
	}
	if dropFunction {
		if _, err := pool.Exec(ctx, `DROP FUNCTION reject_database_lifecycle_audit()`); err != nil {
			t.Fatal(err)
		}
	}
}

func assertDatabaseLifecycleState(t *testing.T, pool interface {
	QueryRow(ctx context.Context, sql string, args ...any) pgx.Row
}, ctx context.Context, databaseID, serviceID uuid.UUID, exists, deleting bool) {
	t.Helper()
	var databaseCount, serviceCount, deletionCount, jobCount int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM database_instances WHERE id=$1`, databaseID).Scan(&databaseCount); err != nil {
		t.Fatal(err)
	}
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM compose_services WHERE id=$1`, serviceID).Scan(&serviceCount); err != nil {
		t.Fatal(err)
	}
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM compose_services WHERE id=$1 AND deletion_requested_at IS NOT NULL`, serviceID).Scan(&deletionCount); err != nil {
		t.Fatal(err)
	}
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM jobs WHERE kind='delete.compose' AND resource_key=$1`, "service:"+serviceID.String()).Scan(&jobCount); err != nil {
		t.Fatal(err)
	}
	wantCount, wantDeletion := 0, 0
	if exists {
		wantCount = 1
	}
	if deleting {
		wantDeletion = 1
	}
	if databaseCount != wantCount || serviceCount != wantCount || deletionCount != wantDeletion || jobCount != wantDeletion {
		t.Fatalf("database lifecycle state: database=%d service=%d deleting=%d jobs=%d", databaseCount, serviceCount, deletionCount, jobCount)
	}
}

func assertServiceDeletionState(t *testing.T, pool interface {
	QueryRow(ctx context.Context, sql string, args ...any) pgx.Row
}, ctx context.Context, serviceID uuid.UUID, deleting bool, jobs int, deleteVolumes bool) {
	t.Helper()
	var deletionCount, jobCount, volumeFlagCount int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM compose_services WHERE id=$1 AND deletion_requested_at IS NOT NULL`, serviceID).Scan(&deletionCount); err != nil {
		t.Fatal(err)
	}
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM jobs WHERE kind='delete.compose' AND resource_key=$1`, "service:"+serviceID.String()).Scan(&jobCount); err != nil {
		t.Fatal(err)
	}
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM jobs WHERE kind='delete.compose' AND resource_key=$1 AND (payload->>'deleteVolumes')::boolean=$2`, "service:"+serviceID.String(), deleteVolumes).Scan(&volumeFlagCount); err != nil {
		t.Fatal(err)
	}
	wantDeletion := 0
	if deleting {
		wantDeletion = 1
	}
	if deletionCount != wantDeletion || jobCount != jobs || volumeFlagCount != jobs {
		t.Fatalf("service deletion state: deleting=%d jobs=%d matching volume flag=%d", deletionCount, jobCount, volumeFlagCount)
	}
}
