package store

import (
	"context"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgconn"
)

func TestFoundationalResourceCreationCommitsWithAudit(t *testing.T) {
	pool, ctx := migrationTestPool(t)
	if err := Migrate(ctx, pool); err != nil {
		t.Fatal(err)
	}
	db := &Store{Pool: pool}
	organizationID, userID, serviceAccountID := uuid.New(), uuid.New(), uuid.New()
	for _, statement := range []struct {
		query string
		args  []any
	}{
		{`INSERT INTO organizations(id,name,slug) VALUES($1,'Resource creation audit',$2)`, []any{organizationID, "resource-creation-audit-" + organizationID.String()}},
		{`INSERT INTO users(id,email,password_hash) VALUES($1,$2,'!test')`, []any{userID, userID.String() + "@example.test"}},
		{`INSERT INTO service_accounts(id,organization_id,name,role) VALUES($1,$2,'resource-creator','admin')`, []any{serviceAccountID, organizationID}},
	} {
		if _, err := pool.Exec(ctx, statement.query, statement.args...); err != nil {
			t.Fatal(err)
		}
	}
	principal := Principal{OrganizationID: organizationID, UserID: userID, Role: "owner"}
	servicePrincipal := Principal{OrganizationID: organizationID, ServiceAccountID: &serviceAccountID, Role: "admin"}
	baseProject, err := db.CreateProject(ctx, organizationID, "Base", "base", "")
	if err != nil {
		t.Fatal(err)
	}
	baseEnvironment, err := db.CreateEnvironment(ctx, organizationID, baseProject.ID, "Base", "base")
	if err != nil {
		t.Fatal(err)
	}
	createResourceCreationAuditTrigger(t, pool, ctx)

	if _, err = db.CreateProjectWithAudit(ctx, principal, "Failed", "failed-project", "", "127.0.0.1:1234"); err == nil {
		t.Fatal("project creation succeeded after audit rejection")
	}
	if _, err = db.CreateEnvironmentWithPlacementAndAudit(ctx, servicePrincipal, baseProject.ID, "Failed", "failed-environment", nil, nil, 0, 0, 0, "127.0.0.1:1234"); err == nil {
		t.Fatal("environment creation succeeded after audit rejection")
	}
	failedServiceID := uuid.New()
	if _, err = db.CreateComposeServiceWithAudit(ctx, principal, ComposeService{ID: failedServiceID, EnvironmentID: baseEnvironment.ID, Name: "Failed", Slug: "failed-service", StackName: "failed-service", ComposeYAML: "services: {}", EncryptedEnv: "failed-ciphertext"}, "127.0.0.1:1234"); err == nil {
		t.Fatal("service creation succeeded after audit rejection")
	}
	var failedProjects, failedEnvironments, failedServices int
	if err = pool.QueryRow(ctx, `SELECT count(*) FROM projects WHERE organization_id=$1 AND slug='failed-project'`, organizationID).Scan(&failedProjects); err != nil {
		t.Fatal(err)
	}
	if err = pool.QueryRow(ctx, `SELECT count(*) FROM environments WHERE project_id=$1 AND slug='failed-environment'`, baseProject.ID).Scan(&failedEnvironments); err != nil {
		t.Fatal(err)
	}
	if err = pool.QueryRow(ctx, `SELECT count(*) FROM compose_services WHERE id=$1`, failedServiceID).Scan(&failedServices); err != nil {
		t.Fatal(err)
	}
	if failedProjects != 0 || failedEnvironments != 0 || failedServices != 0 {
		t.Fatalf("failed audit retained resources: projects=%d environments=%d services=%d", failedProjects, failedEnvironments, failedServices)
	}
	dropResourceCreationAuditTrigger(t, pool, ctx)

	project, err := db.CreateProjectWithAudit(ctx, principal, "Application", "application", "", "127.0.0.1:1234")
	if err != nil {
		t.Fatal(err)
	}
	environment, err := db.CreateEnvironmentWithPlacementAndAudit(ctx, servicePrincipal, project.ID, "Production", "production", nil, nil, 0, 0, 0, "127.0.0.1:1234")
	if err != nil {
		t.Fatal(err)
	}
	service, err := db.CreateComposeServiceWithAudit(ctx, principal, ComposeService{EnvironmentID: environment.ID, Name: "API", Slug: "api", StackName: "api", ComposeYAML: "services: {}", EncryptedEnv: "ciphertext"}, "127.0.0.1:1234")
	if err != nil {
		t.Fatal(err)
	}
	var userAudits, serviceAudits, storedServices int
	if err = pool.QueryRow(ctx, `SELECT count(*) FROM audit_events WHERE organization_id=$1 AND actor_user_id=$2 AND actor_service_account_id IS NULL AND ((action='project.create' AND resource_id=$3) OR (action='service.create' AND resource_id=$4))`, organizationID, userID, project.ID.String(), service.ID.String()).Scan(&userAudits); err != nil {
		t.Fatal(err)
	}
	if err = pool.QueryRow(ctx, `SELECT count(*) FROM audit_events WHERE organization_id=$1 AND actor_user_id IS NULL AND actor_service_account_id=$2 AND action='environment.create' AND resource_id=$3`, organizationID, serviceAccountID, environment.ID.String()).Scan(&serviceAudits); err != nil {
		t.Fatal(err)
	}
	if err = pool.QueryRow(ctx, `SELECT count(*) FROM compose_services WHERE id=$1 AND encrypted_env='ciphertext' AND revision=1 AND desired_state='running'`, service.ID).Scan(&storedServices); err != nil {
		t.Fatal(err)
	}
	if userAudits != 2 || serviceAudits != 1 || storedServices != 1 {
		t.Fatalf("resource creation evidence: user audits=%d service audits=%d stored services=%d", userAudits, serviceAudits, storedServices)
	}
}

func createResourceCreationAuditTrigger(t *testing.T, pool interface {
	Exec(ctx context.Context, sql string, arguments ...any) (pgconn.CommandTag, error)
}, ctx context.Context) {
	t.Helper()
	if _, err := pool.Exec(ctx, `CREATE FUNCTION reject_resource_creation_audit() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF NEW.action IN ('project.create','environment.create','service.create') THEN RAISE EXCEPTION 'forced audit failure'; END IF; RETURN NEW; END $$`); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `CREATE TRIGGER reject_resource_creation_audit BEFORE INSERT ON audit_events FOR EACH ROW EXECUTE FUNCTION reject_resource_creation_audit()`); err != nil {
		t.Fatal(err)
	}
}

func dropResourceCreationAuditTrigger(t *testing.T, pool interface {
	Exec(ctx context.Context, sql string, arguments ...any) (pgconn.CommandTag, error)
}, ctx context.Context) {
	t.Helper()
	if _, err := pool.Exec(ctx, `DROP TRIGGER reject_resource_creation_audit ON audit_events`); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `DROP FUNCTION reject_resource_creation_audit()`); err != nil {
		t.Fatal(err)
	}
}
