package store

import (
	"testing"
	"time"

	"github.com/google/uuid"
)

func TestDeployTokenLifecycleCommitsWithAudit(t *testing.T) {
	pool, ctx := migrationTestPool(t)
	if err := Migrate(ctx, pool); err != nil {
		t.Fatal(err)
	}
	db := &Store{Pool: pool}
	organizationID, userID := uuid.New(), uuid.New()
	projectID, environmentID, serviceID := uuid.New(), uuid.New(), uuid.New()
	statements := []struct {
		query string
		args  []any
	}{
		{`INSERT INTO organizations(id,name,slug) VALUES($1,'Deploy token audit',$2)`, []any{organizationID, "deploy-token-audit-" + organizationID.String()}},
		{`INSERT INTO users(id,email,password_hash) VALUES($1,$2,'!test')`, []any{userID, userID.String() + "@example.test"}},
		{`INSERT INTO projects(id,organization_id,name,slug) VALUES($1,$2,'Project','project')`, []any{projectID, organizationID}},
		{`INSERT INTO environments(id,project_id,name,slug) VALUES($1,$2,'Production','production')`, []any{environmentID, projectID}},
		{`INSERT INTO compose_services(id,environment_id,name,slug,stack_name,compose_yaml) VALUES($1,$2,'API','api',$3,'services: {}')`, []any{serviceID, environmentID, "deploy-token-audit-" + serviceID.String()}},
	}
	for _, statement := range statements {
		if _, err := pool.Exec(ctx, statement.query, statement.args...); err != nil {
			t.Fatal(err)
		}
	}
	principal := Principal{OrganizationID: organizationID, UserID: userID, Role: "owner"}
	invalidPrincipal := principal
	invalidServiceAccountID := uuid.New()
	invalidPrincipal.ServiceAccountID = &invalidServiceAccountID
	expiresAt := time.Now().Add(30 * 24 * time.Hour)
	failedHash := []byte("failed-deploy-token-hash")
	activeHash := []byte("active-deploy-token-hash")

	if _, err := db.CreateDeployTokenWithAudit(ctx, invalidPrincipal, serviceID, "failed", failedHash, expiresAt, "127.0.0.1:1234"); err == nil {
		t.Fatal("deploy token creation succeeded without valid audit evidence")
	}
	var failedCount int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM deploy_tokens WHERE token_hash=$1`, failedHash).Scan(&failedCount); err != nil || failedCount != 0 {
		t.Fatalf("failed evidence retained deploy token: count=%d err=%v", failedCount, err)
	}

	item, err := db.CreateDeployTokenWithAudit(ctx, principal, serviceID, "CI", activeHash, expiresAt, "127.0.0.1:1234")
	if err != nil {
		t.Fatal(err)
	}
	if err = db.RevokeDeployTokenWithAudit(ctx, invalidPrincipal, serviceID, item.ID, "127.0.0.1:1234"); err == nil {
		t.Fatal("deploy token revocation succeeded without valid audit evidence")
	}
	var revokedAt *time.Time
	if err = pool.QueryRow(ctx, `SELECT revoked_at FROM deploy_tokens WHERE id=$1`, item.ID).Scan(&revokedAt); err != nil || revokedAt != nil {
		t.Fatalf("failed evidence revoked deploy token: revokedAt=%v err=%v", revokedAt, err)
	}
	if err = db.RevokeDeployTokenWithAudit(ctx, principal, serviceID, item.ID, "127.0.0.1:1234"); err != nil {
		t.Fatal(err)
	}
	if err = pool.QueryRow(ctx, `SELECT revoked_at FROM deploy_tokens WHERE id=$1`, item.ID).Scan(&revokedAt); err != nil || revokedAt == nil {
		t.Fatalf("audited deploy-token revocation: revokedAt=%v err=%v", revokedAt, err)
	}

	var auditCount int
	if err = pool.QueryRow(ctx, `SELECT count(*) FROM audit_events WHERE organization_id=$1 AND actor_user_id=$2 AND actor_service_account_id IS NULL AND resource_id=$3 AND action IN ('deploy_token.create','deploy_token.revoke')`, organizationID, userID, item.ID.String()).Scan(&auditCount); err != nil || auditCount != 2 {
		t.Fatalf("deploy-token audit count=%d err=%v", auditCount, err)
	}
}
