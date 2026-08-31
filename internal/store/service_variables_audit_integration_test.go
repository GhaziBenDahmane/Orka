package store

import (
	"context"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

func TestServiceVariableMutationsCommitWithAudit(t *testing.T) {
	pool, ctx := migrationTestPool(t)
	if err := Migrate(ctx, pool); err != nil {
		t.Fatal(err)
	}
	db := &Store{Pool: pool}
	organizationID, userID, serviceAccountID := uuid.New(), uuid.New(), uuid.New()
	projectID, environmentID, serviceID := uuid.New(), uuid.New(), uuid.New()
	for _, statement := range []struct {
		query string
		args  []any
	}{
		{`INSERT INTO organizations(id,name,slug) VALUES($1,'Variable audit',$2)`, []any{organizationID, "variable-audit-" + organizationID.String()}},
		{`INSERT INTO users(id,email,password_hash) VALUES($1,$2,'!test')`, []any{userID, userID.String() + "@example.test"}},
		{`INSERT INTO service_accounts(id,organization_id,name,role) VALUES($1,$2,'variable-operator','admin')`, []any{serviceAccountID, organizationID}},
		{`INSERT INTO projects(id,organization_id,name,slug) VALUES($1,$2,'Project','project')`, []any{projectID, organizationID}},
		{`INSERT INTO environments(id,project_id,name,slug) VALUES($1,$2,'Production','production')`, []any{environmentID, projectID}},
		{`INSERT INTO compose_services(id,environment_id,name,slug,stack_name,compose_yaml,encrypted_env) VALUES($1,$2,'API','api',$3,'services: {}','original-environment')`, []any{serviceID, environmentID, "variable-audit-" + serviceID.String()}},
		{`INSERT INTO template_instances(compose_service_id,template_key,template_version,template_checksum,encrypted_variables,managed_environment_keys,environment_ownership_recorded) VALUES($1,'example/api','1','checksum','encrypted',$2,true)`, []any{serviceID, []string{"OTHER", "TEMPLATE"}}},
	} {
		if _, err := pool.Exec(ctx, statement.query, statement.args...); err != nil {
			t.Fatal(err)
		}
	}
	principal := Principal{OrganizationID: organizationID, UserID: userID, Role: "owner"}
	servicePrincipal := Principal{OrganizationID: organizationID, ServiceAccountID: &serviceAccountID, Role: "admin"}
	if _, err := pool.Exec(ctx, `CREATE FUNCTION reject_service_variable_audit() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF NEW.action IN ('service.variables.upsert','service.variables.delete') THEN RAISE EXCEPTION 'forced audit failure'; END IF; RETURN NEW; END $$`); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `CREATE TRIGGER reject_service_variable_audit BEFORE INSERT ON audit_events FOR EACH ROW EXECUTE FUNCTION reject_service_variable_audit()`); err != nil {
		t.Fatal(err)
	}
	managedKeys := []string{"OTHER"}
	if _, err := db.UpsertComposeServiceVariablesWithAudit(ctx, principal, serviceID, 1, "failed-upsert", &managedKeys, []string{"TEMPLATE"}, "127.0.0.1:1234"); err == nil {
		t.Fatal("variable upsert succeeded after audit rejection")
	}
	assertVariableState(t, pool, ctx, serviceID, "original-environment", 1, []string{"OTHER", "TEMPLATE"})
	if _, err := db.DeleteComposeServiceVariableWithAudit(ctx, servicePrincipal, serviceID, 1, "failed-delete", "OTHER", "127.0.0.1:1234"); err == nil {
		t.Fatal("variable deletion succeeded after audit rejection")
	}
	assertVariableState(t, pool, ctx, serviceID, "original-environment", 1, []string{"OTHER", "TEMPLATE"})
	if _, err := pool.Exec(ctx, `DROP TRIGGER reject_service_variable_audit ON audit_events`); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `DROP FUNCTION reject_service_variable_audit()`); err != nil {
		t.Fatal(err)
	}

	updated, err := db.UpsertComposeServiceVariablesWithAudit(ctx, principal, serviceID, 1, "upserted-environment", &managedKeys, []string{"TEMPLATE"}, "127.0.0.1:1234")
	if err != nil {
		t.Fatal(err)
	}
	if _, err = db.DeleteComposeServiceVariableWithAudit(ctx, servicePrincipal, serviceID, updated.Revision, "deleted-environment", "OTHER", "127.0.0.1:1234"); err != nil {
		t.Fatal(err)
	}
	assertVariableState(t, pool, ctx, serviceID, "deleted-environment", 3, []string{"OTHER"})
	var userAudits, serviceAudits int
	if err = pool.QueryRow(ctx, `SELECT count(*) FROM audit_events WHERE organization_id=$1 AND actor_user_id=$2 AND actor_service_account_id IS NULL AND action='service.variables.upsert' AND resource_id=$3 AND metadata->'names' ? 'TEMPLATE' AND metadata->>'revision'='2'`, organizationID, userID, serviceID.String()).Scan(&userAudits); err != nil {
		t.Fatal(err)
	}
	if err = pool.QueryRow(ctx, `SELECT count(*) FROM audit_events WHERE organization_id=$1 AND actor_user_id IS NULL AND actor_service_account_id=$2 AND action='service.variables.delete' AND resource_id=$3 AND metadata->>'name'='OTHER' AND metadata->>'revision'='3'`, organizationID, serviceAccountID, serviceID.String()).Scan(&serviceAudits); err != nil {
		t.Fatal(err)
	}
	if userAudits != 1 || serviceAudits != 1 {
		t.Fatalf("variable audit counts: user=%d service=%d", userAudits, serviceAudits)
	}
}

func assertVariableState(t *testing.T, pool interface {
	QueryRow(ctx context.Context, sql string, args ...any) pgx.Row
}, ctx context.Context, serviceID uuid.UUID, encryptedEnvironment string, revision int64, managedKeys []string) {
	t.Helper()
	var storedEnvironment string
	var storedRevision int64
	var storedKeys []string
	if err := pool.QueryRow(ctx, `SELECT service.encrypted_env,service.revision,instance.managed_environment_keys FROM compose_services service JOIN template_instances instance ON instance.compose_service_id=service.id WHERE service.id=$1`, serviceID).Scan(&storedEnvironment, &storedRevision, &storedKeys); err != nil {
		t.Fatal(err)
	}
	if storedEnvironment != encryptedEnvironment || storedRevision != revision || len(storedKeys) != len(managedKeys) {
		t.Fatalf("variable state: environment=%q revision=%d managed=%v", storedEnvironment, storedRevision, storedKeys)
	}
	for index := range managedKeys {
		if storedKeys[index] != managedKeys[index] {
			t.Fatalf("managed variable keys=%v want=%v", storedKeys, managedKeys)
		}
	}
}
