package store

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"
)

func TestDeployHookCommitsWithSystemAudit(t *testing.T) {
	pool, ctx := migrationTestPool(t)
	if err := Migrate(ctx, pool); err != nil {
		t.Fatal(err)
	}
	db := &Store{Pool: pool}
	organizationID, projectID, environmentID, serviceID, tokenID := uuid.New(), uuid.New(), uuid.New(), uuid.New(), uuid.New()
	tokenHash := []byte("audited-deploy-hook-token")
	for _, statement := range []struct {
		query string
		args  []any
	}{
		{`INSERT INTO organizations(id,name,slug) VALUES($1,'Deploy hook audit',$2)`, []any{organizationID, "deploy-hook-audit-" + organizationID.String()}},
		{`INSERT INTO projects(id,organization_id,name,slug) VALUES($1,$2,'Project','project')`, []any{projectID, organizationID}},
		{`INSERT INTO environments(id,project_id,name,slug) VALUES($1,$2,'Production','production')`, []any{environmentID, projectID}},
		{`INSERT INTO compose_services(id,environment_id,name,slug,stack_name,compose_yaml) VALUES($1,$2,'API','api',$3,'services: {}')`, []any{serviceID, environmentID, "deploy-hook-audit-" + serviceID.String()}},
		{`INSERT INTO deploy_tokens(id,compose_service_id,token_hash,name,expires_at) VALUES($1,$2,$3,'CI',now()+interval '1 hour')`, []any{tokenID, serviceID, tokenHash}},
	} {
		if _, err := pool.Exec(ctx, statement.query, statement.args...); err != nil {
			t.Fatal(err)
		}
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `DROP TRIGGER IF EXISTS reject_deploy_hook_audit ON audit_events`)
		_, _ = pool.Exec(context.Background(), `DROP FUNCTION IF EXISTS reject_deploy_hook_audit()`)
		_, _ = pool.Exec(context.Background(), `DELETE FROM organizations WHERE id=$1`, organizationID)
	})

	if _, err := pool.Exec(ctx, `CREATE FUNCTION reject_deploy_hook_audit() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF NEW.action='deployment.hook' THEN RAISE EXCEPTION 'forced audit failure'; END IF; RETURN NEW; END $$`); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `CREATE TRIGGER reject_deploy_hook_audit BEFORE INSERT ON audit_events FOR EACH ROW EXECUTE FUNCTION reject_deploy_hook_audit()`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.QueueDeploymentByTokenWithAudit(ctx, tokenHash, "127.0.0.1:1234"); err == nil {
		t.Fatal("deploy hook queued work without audit evidence")
	}
	var deployments, jobs int
	var lastUsedAt *time.Time
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM deployments WHERE compose_service_id=$1`, serviceID).Scan(&deployments); err != nil {
		t.Fatal(err)
	}
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM jobs WHERE resource_key=$1`, "service:"+serviceID.String()).Scan(&jobs); err != nil {
		t.Fatal(err)
	}
	if err := pool.QueryRow(ctx, `SELECT last_used_at FROM deploy_tokens WHERE id=$1`, tokenID).Scan(&lastUsedAt); err != nil {
		t.Fatal(err)
	}
	if deployments != 0 || jobs != 0 || lastUsedAt != nil {
		t.Fatalf("failed audit retained hook work: deployments=%d jobs=%d last_used_at=%v", deployments, jobs, lastUsedAt)
	}

	if _, err := pool.Exec(ctx, `DROP TRIGGER reject_deploy_hook_audit ON audit_events`); err != nil {
		t.Fatal(err)
	}
	deployment, err := db.QueueDeploymentByTokenWithAudit(ctx, tokenHash, "127.0.0.1:1234")
	if err != nil || deployment.Status != "queued" {
		t.Fatalf("audited deploy hook=%#v err=%v", deployment, err)
	}
	var audits, attributed int
	if err = pool.QueryRow(ctx, `SELECT count(*),count(*) FILTER (WHERE metadata->>'deployTokenId'=$3 AND metadata->>'composeServiceId'=$4 AND remote_addr='127.0.0.1:1234') FROM audit_events WHERE organization_id=$1 AND action='deployment.hook' AND resource_id=$2`, organizationID, deployment.ID.String(), tokenID.String(), serviceID.String()).Scan(&audits, &attributed); err != nil {
		t.Fatal(err)
	}
	if err = pool.QueryRow(ctx, `SELECT last_used_at FROM deploy_tokens WHERE id=$1`, tokenID).Scan(&lastUsedAt); err != nil {
		t.Fatal(err)
	}
	if audits != 1 || attributed != 1 || lastUsedAt == nil {
		t.Fatalf("deploy hook evidence: audits=%d attributed=%d last_used_at=%v", audits, attributed, lastUsedAt)
	}
}
