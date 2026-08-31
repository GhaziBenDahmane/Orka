package store

import (
	"context"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

func TestDeploymentLifecycleCommitsWithAudit(t *testing.T) {
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
		{`INSERT INTO organizations(id,name,slug) VALUES($1,'Deployment lifecycle audit',$2)`, []any{organizationID, "deployment-lifecycle-audit-" + organizationID.String()}},
		{`INSERT INTO users(id,email,password_hash) VALUES($1,$2,'!test')`, []any{userID, userID.String() + "@example.test"}},
		{`INSERT INTO service_accounts(id,organization_id,name,role) VALUES($1,$2,'deployment-operator','admin')`, []any{serviceAccountID, organizationID}},
		{`INSERT INTO projects(id,organization_id,name,slug) VALUES($1,$2,'Project','project')`, []any{projectID, organizationID}},
		{`INSERT INTO environments(id,project_id,name,slug) VALUES($1,$2,'Production','production')`, []any{environmentID, projectID}},
	} {
		if _, err := pool.Exec(ctx, statement.query, statement.args...); err != nil {
			t.Fatal(err)
		}
	}
	deploymentServiceID := createDeploymentAuditService(t, db, ctx, organizationID, environmentID, "deploy", "running")
	stopServiceID := createDeploymentAuditService(t, db, ctx, organizationID, environmentID, "stop", "running")
	startServiceID := createDeploymentAuditService(t, db, ctx, organizationID, environmentID, "start", "stopped")
	rollbackServiceID := createDeploymentAuditService(t, db, ctx, organizationID, environmentID, "rollback", "running")
	cancelServiceID := createDeploymentAuditService(t, db, ctx, organizationID, environmentID, "cancel", "running")
	succeededDeploymentID := uuid.New()
	if _, err := pool.Exec(ctx, `INSERT INTO deployments(id,compose_service_id,revision,compose_snapshot,effective_compose,env_snapshot,status,trigger,finished_at) VALUES($1,$2,1,'services: {old: {}}','services: {old: {}}','old-env','succeeded','manual',now())`, succeededDeploymentID, rollbackServiceID); err != nil {
		t.Fatal(err)
	}
	cancelDeployment, err := db.QueueDeployment(ctx, organizationID, cancelServiceID, userID, "manual")
	if err != nil {
		t.Fatal(err)
	}
	principal := Principal{OrganizationID: organizationID, UserID: userID, Role: "owner"}
	servicePrincipal := Principal{OrganizationID: organizationID, ServiceAccountID: &serviceAccountID, Role: "admin"}
	if _, err = pool.Exec(ctx, `CREATE FUNCTION reject_deployment_lifecycle_audit() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF NEW.action IN ('deployment.create','service.stop.requested','service.start.requested','deployment.rollback','deployment.cancel') THEN RAISE EXCEPTION 'forced audit failure'; END IF; RETURN NEW; END $$`); err != nil {
		t.Fatal(err)
	}
	if _, err = pool.Exec(ctx, `CREATE TRIGGER reject_deployment_lifecycle_audit BEFORE INSERT ON audit_events FOR EACH ROW EXECUTE FUNCTION reject_deployment_lifecycle_audit()`); err != nil {
		t.Fatal(err)
	}

	if _, err = db.QueueDeploymentWithAudit(ctx, principal, deploymentServiceID, "manual", "127.0.0.1:1234"); err == nil {
		t.Fatal("deployment creation succeeded after audit rejection")
	}
	assertDeploymentQueueState(t, pool, ctx, deploymentServiceID, "running", 0, 0)
	if _, _, err = db.QueueServiceStopWithAudit(ctx, servicePrincipal, stopServiceID, "127.0.0.1:1234"); err == nil {
		t.Fatal("service stop succeeded after audit rejection")
	}
	assertServiceJobState(t, pool, ctx, stopServiceID, "running", "stop.compose", 0)
	if _, err = db.QueueServiceStartWithAudit(ctx, servicePrincipal, startServiceID, "127.0.0.1:1234"); err == nil {
		t.Fatal("service start succeeded after audit rejection")
	}
	assertDeploymentQueueState(t, pool, ctx, startServiceID, "stopped", 0, 0)
	if _, err = db.QueueRollbackWithAudit(ctx, principal, rollbackServiceID, "127.0.0.1:1234"); err == nil {
		t.Fatal("deployment rollback succeeded after audit rejection")
	}
	var rollbackRevision int64
	var rollbackCompose, rollbackEnvironment, rollbackDesiredState string
	if err = pool.QueryRow(ctx, `SELECT revision,compose_yaml,encrypted_env,desired_state FROM compose_services WHERE id=$1`, rollbackServiceID).Scan(&rollbackRevision, &rollbackCompose, &rollbackEnvironment, &rollbackDesiredState); err != nil {
		t.Fatal(err)
	}
	if rollbackRevision != 1 || rollbackCompose != "services: {}" || rollbackEnvironment != "current-env" || rollbackDesiredState != "running" {
		t.Fatalf("failed rollback changed service: revision=%d compose=%q env=%q desired=%q", rollbackRevision, rollbackCompose, rollbackEnvironment, rollbackDesiredState)
	}
	assertDeploymentQueueState(t, pool, ctx, rollbackServiceID, "running", 0, 0)
	if err = db.CancelDeploymentWithAudit(ctx, servicePrincipal, cancelDeployment.ID, "127.0.0.1:1234"); err == nil {
		t.Fatal("deployment cancellation succeeded after audit rejection")
	}
	assertDeploymentCancellationState(t, pool, ctx, cancelDeployment.ID, "queued", "pending", false)

	if _, err = pool.Exec(ctx, `DROP TRIGGER reject_deployment_lifecycle_audit ON audit_events`); err != nil {
		t.Fatal(err)
	}
	if _, err = pool.Exec(ctx, `DROP FUNCTION reject_deployment_lifecycle_audit()`); err != nil {
		t.Fatal(err)
	}
	deployment, err := db.QueueDeploymentWithAudit(ctx, principal, deploymentServiceID, "manual", "127.0.0.1:1234")
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err = db.QueueServiceStopWithAudit(ctx, servicePrincipal, stopServiceID, "127.0.0.1:1234"); err != nil {
		t.Fatal(err)
	}
	started, err := db.QueueServiceStartWithAudit(ctx, servicePrincipal, startServiceID, "127.0.0.1:1234")
	if err != nil {
		t.Fatal(err)
	}
	rollback, err := db.QueueRollbackWithAudit(ctx, principal, rollbackServiceID, "127.0.0.1:1234")
	if err != nil {
		t.Fatal(err)
	}
	if err = db.CancelDeploymentWithAudit(ctx, servicePrincipal, cancelDeployment.ID, "127.0.0.1:1234"); err != nil {
		t.Fatal(err)
	}
	assertDeploymentCancellationState(t, pool, ctx, cancelDeployment.ID, "cancelled", "cancelled", true)
	var userAudits, serviceAudits, userDeploymentActors, serviceDeploymentActors int
	if err = pool.QueryRow(ctx, `SELECT count(*) FROM audit_events WHERE organization_id=$1 AND actor_user_id=$2 AND actor_service_account_id IS NULL AND action IN ('deployment.create','deployment.rollback')`, organizationID, userID).Scan(&userAudits); err != nil {
		t.Fatal(err)
	}
	if err = pool.QueryRow(ctx, `SELECT count(*) FROM audit_events WHERE organization_id=$1 AND actor_user_id IS NULL AND actor_service_account_id=$2 AND action IN ('service.stop.requested','service.start.requested','deployment.cancel')`, organizationID, serviceAccountID).Scan(&serviceAudits); err != nil {
		t.Fatal(err)
	}
	if err = pool.QueryRow(ctx, `SELECT count(*) FROM deployments WHERE id=ANY($1::uuid[]) AND actor_user_id=$2`, []uuid.UUID{deployment.ID, rollback.ID}, userID).Scan(&userDeploymentActors); err != nil {
		t.Fatal(err)
	}
	if err = pool.QueryRow(ctx, `SELECT count(*) FROM deployments WHERE id=$1 AND actor_user_id IS NULL`, started.ID).Scan(&serviceDeploymentActors); err != nil {
		t.Fatal(err)
	}
	if userAudits != 2 || serviceAudits != 3 || userDeploymentActors != 2 || serviceDeploymentActors != 1 {
		t.Fatalf("deployment attribution: user audits=%d service audits=%d user deployments=%d service deployments=%d", userAudits, serviceAudits, userDeploymentActors, serviceDeploymentActors)
	}
}

func createDeploymentAuditService(t *testing.T, db *Store, ctx context.Context, organizationID, environmentID uuid.UUID, slug, desiredState string) uuid.UUID {
	t.Helper()
	service, err := db.CreateComposeService(ctx, organizationID, ComposeService{EnvironmentID: environmentID, Name: slug, Slug: slug, StackName: slug, ComposeYAML: "services: {}", EncryptedEnv: "current-env"})
	if err != nil {
		t.Fatal(err)
	}
	if desiredState != "running" {
		if _, err = db.Pool.Exec(ctx, `UPDATE compose_services SET desired_state=$2 WHERE id=$1`, service.ID, desiredState); err != nil {
			t.Fatal(err)
		}
	}
	return service.ID
}

func assertDeploymentQueueState(t *testing.T, pool interface {
	QueryRow(ctx context.Context, sql string, args ...any) pgx.Row
}, ctx context.Context, serviceID uuid.UUID, desiredState string, deployments, jobs int) {
	t.Helper()
	var storedDesiredState string
	var deploymentCount, jobCount int
	if err := pool.QueryRow(ctx, `SELECT desired_state FROM compose_services WHERE id=$1`, serviceID).Scan(&storedDesiredState); err != nil {
		t.Fatal(err)
	}
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM deployments WHERE compose_service_id=$1 AND status='queued'`, serviceID).Scan(&deploymentCount); err != nil {
		t.Fatal(err)
	}
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM jobs WHERE kind='deploy.compose' AND resource_key=$1`, "service:"+serviceID.String()).Scan(&jobCount); err != nil {
		t.Fatal(err)
	}
	if storedDesiredState != desiredState || deploymentCount != deployments || jobCount != jobs {
		t.Fatalf("deployment queue state: desired=%q deployments=%d jobs=%d", storedDesiredState, deploymentCount, jobCount)
	}
}

func assertServiceJobState(t *testing.T, pool interface {
	QueryRow(ctx context.Context, sql string, args ...any) pgx.Row
}, ctx context.Context, serviceID uuid.UUID, desiredState, kind string, jobs int) {
	t.Helper()
	var storedDesiredState string
	var jobCount int
	if err := pool.QueryRow(ctx, `SELECT desired_state FROM compose_services WHERE id=$1`, serviceID).Scan(&storedDesiredState); err != nil {
		t.Fatal(err)
	}
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM jobs WHERE kind=$1 AND resource_key=$2`, kind, "service:"+serviceID.String()).Scan(&jobCount); err != nil {
		t.Fatal(err)
	}
	if storedDesiredState != desiredState || jobCount != jobs {
		t.Fatalf("service job state: desired=%q jobs=%d", storedDesiredState, jobCount)
	}
}

func assertDeploymentCancellationState(t *testing.T, pool interface {
	QueryRow(ctx context.Context, sql string, args ...any) pgx.Row
}, ctx context.Context, deploymentID uuid.UUID, deploymentStatus, jobStatus string, cancelled bool) {
	t.Helper()
	var storedDeploymentStatus, storedJobStatus string
	var cancellationRequested bool
	if err := pool.QueryRow(ctx, `SELECT status FROM deployments WHERE id=$1`, deploymentID).Scan(&storedDeploymentStatus); err != nil {
		t.Fatal(err)
	}
	if err := pool.QueryRow(ctx, `SELECT status,cancel_requested_at IS NOT NULL FROM jobs WHERE kind='deploy.compose' AND payload->>'deploymentId'=$1`, deploymentID.String()).Scan(&storedJobStatus, &cancellationRequested); err != nil {
		t.Fatal(err)
	}
	if storedDeploymentStatus != deploymentStatus || storedJobStatus != jobStatus || cancellationRequested != cancelled {
		t.Fatalf("deployment cancellation state: deployment=%q job=%q cancelled=%v", storedDeploymentStatus, storedJobStatus, cancellationRequested)
	}
}
