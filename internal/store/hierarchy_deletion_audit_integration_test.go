package store

import (
	"context"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

func TestHierarchyDeletionCommitsWithAudit(t *testing.T) {
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
		{`INSERT INTO organizations(id,name,slug) VALUES($1,'Hierarchy deletion audit',$2)`, []any{organizationID, "hierarchy-deletion-audit-" + organizationID.String()}},
		{`INSERT INTO users(id,email,password_hash) VALUES($1,$2,'!test')`, []any{userID, userID.String() + "@example.test"}},
		{`INSERT INTO service_accounts(id,organization_id,name,role) VALUES($1,$2,'hierarchy-deleter','admin')`, []any{serviceAccountID, organizationID}},
	} {
		if _, err := pool.Exec(ctx, statement.query, statement.args...); err != nil {
			t.Fatal(err)
		}
	}
	projectTree := createDeletionTestHierarchy(t, db, ctx, organizationID, "project-tree")
	environmentTree := createDeletionTestHierarchy(t, db, ctx, organizationID, "environment-tree")
	principal := Principal{OrganizationID: organizationID, UserID: userID, Role: "owner"}
	servicePrincipal := Principal{OrganizationID: organizationID, ServiceAccountID: &serviceAccountID, Role: "admin"}

	if _, err := pool.Exec(ctx, `CREATE FUNCTION reject_hierarchy_deletion_audit() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF NEW.action IN ('project.delete','environment.delete') THEN RAISE EXCEPTION 'forced audit failure'; END IF; RETURN NEW; END $$`); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `CREATE TRIGGER reject_hierarchy_deletion_audit BEFORE INSERT ON audit_events FOR EACH ROW EXECUTE FUNCTION reject_hierarchy_deletion_audit()`); err != nil {
		t.Fatal(err)
	}
	if err := db.DeleteProjectWithAudit(ctx, principal, projectTree.projectID, "127.0.0.1:1234"); err == nil {
		t.Fatal("project deletion succeeded after audit rejection")
	}
	assertHierarchyDeletionState(t, pool, ctx, projectTree, false, false, false, 0, 0, 0)
	if err := db.DeleteEnvironmentWithAudit(ctx, servicePrincipal, environmentTree.environmentID, "127.0.0.1:1234"); err == nil {
		t.Fatal("environment deletion succeeded after audit rejection")
	}
	assertHierarchyDeletionState(t, pool, ctx, environmentTree, false, false, false, 0, 0, 0)
	if _, err := pool.Exec(ctx, `DROP TRIGGER reject_hierarchy_deletion_audit ON audit_events`); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `DROP FUNCTION reject_hierarchy_deletion_audit()`); err != nil {
		t.Fatal(err)
	}

	if err := db.DeleteProjectWithAudit(ctx, principal, projectTree.projectID, "127.0.0.1:1234"); err != nil {
		t.Fatal(err)
	}
	if err := db.DeleteEnvironmentWithAudit(ctx, servicePrincipal, environmentTree.environmentID, "127.0.0.1:1234"); err != nil {
		t.Fatal(err)
	}
	assertHierarchyDeletionState(t, pool, ctx, projectTree, true, true, true, 1, 1, 1)
	assertHierarchyDeletionState(t, pool, ctx, environmentTree, false, true, true, 0, 1, 1)
	var projectAudit, environmentAudit int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM audit_events WHERE organization_id=$1 AND actor_user_id=$2 AND actor_service_account_id IS NULL AND action='project.delete' AND resource_id=$3`, organizationID, userID, projectTree.projectID.String()).Scan(&projectAudit); err != nil {
		t.Fatal(err)
	}
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM audit_events WHERE organization_id=$1 AND actor_user_id IS NULL AND actor_service_account_id=$2 AND action='environment.delete' AND resource_id=$3`, organizationID, serviceAccountID, environmentTree.environmentID.String()).Scan(&environmentAudit); err != nil {
		t.Fatal(err)
	}
	if projectAudit != 1 || environmentAudit != 1 {
		t.Fatalf("hierarchy deletion audit counts: project=%d environment=%d", projectAudit, environmentAudit)
	}
}

type deletionTestHierarchy struct {
	projectID     uuid.UUID
	environmentID uuid.UUID
	serviceID     uuid.UUID
}

func createDeletionTestHierarchy(t *testing.T, db *Store, ctx context.Context, organizationID uuid.UUID, slug string) deletionTestHierarchy {
	t.Helper()
	project, err := db.CreateProject(ctx, organizationID, slug, slug, "")
	if err != nil {
		t.Fatal(err)
	}
	environment, err := db.CreateEnvironment(ctx, organizationID, project.ID, "Production", "production")
	if err != nil {
		t.Fatal(err)
	}
	service, err := db.CreateComposeService(ctx, organizationID, ComposeService{EnvironmentID: environment.ID, Name: "API", Slug: "api", StackName: slug + "-api", ComposeYAML: "services: {}"})
	if err != nil {
		t.Fatal(err)
	}
	return deletionTestHierarchy{projectID: project.ID, environmentID: environment.ID, serviceID: service.ID}
}

func assertHierarchyDeletionState(t *testing.T, pool interface {
	QueryRow(ctx context.Context, sql string, args ...any) pgx.Row
}, ctx context.Context, hierarchy deletionTestHierarchy, projectDeleting, environmentDeleting, serviceDeleting bool, projectJobs, environmentJobs, serviceJobs int) {
	t.Helper()
	var projectDeletionCount, environmentDeletionCount, serviceDeletionCount int
	var storedProjectJobs, storedEnvironmentJobs, storedServiceJobs int
	queries := []struct {
		query string
		args  []any
		out   *int
	}{
		{`SELECT count(*) FROM projects WHERE id=$1 AND deletion_requested_at IS NOT NULL`, []any{hierarchy.projectID}, &projectDeletionCount},
		{`SELECT count(*) FROM environments WHERE id=$1 AND deletion_requested_at IS NOT NULL`, []any{hierarchy.environmentID}, &environmentDeletionCount},
		{`SELECT count(*) FROM compose_services WHERE id=$1 AND deletion_requested_at IS NOT NULL`, []any{hierarchy.serviceID}, &serviceDeletionCount},
		{`SELECT count(*) FROM jobs WHERE kind='delete.project' AND payload->>'projectId'=$1`, []any{hierarchy.projectID.String()}, &storedProjectJobs},
		{`SELECT count(*) FROM jobs WHERE kind='delete.environment' AND payload->>'environmentId'=$1`, []any{hierarchy.environmentID.String()}, &storedEnvironmentJobs},
		{`SELECT count(*) FROM jobs WHERE kind='delete.compose' AND payload->>'serviceId'=$1`, []any{hierarchy.serviceID.String()}, &storedServiceJobs},
	}
	for _, query := range queries {
		if err := pool.QueryRow(ctx, query.query, query.args...).Scan(query.out); err != nil {
			t.Fatal(err)
		}
	}
	wantProject, wantEnvironment, wantService := 0, 0, 0
	if projectDeleting {
		wantProject = 1
	}
	if environmentDeleting {
		wantEnvironment = 1
	}
	if serviceDeleting {
		wantService = 1
	}
	if projectDeletionCount != wantProject || environmentDeletionCount != wantEnvironment || serviceDeletionCount != wantService || storedProjectJobs != projectJobs || storedEnvironmentJobs != environmentJobs || storedServiceJobs != serviceJobs {
		t.Fatalf("hierarchy deletion state: markers=%d/%d/%d jobs=%d/%d/%d", projectDeletionCount, environmentDeletionCount, serviceDeletionCount, storedProjectJobs, storedEnvironmentJobs, storedServiceJobs)
	}
}
