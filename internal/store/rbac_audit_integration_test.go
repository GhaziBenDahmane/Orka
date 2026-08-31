package store

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

func TestRBACMutationsCommitWithAudit(t *testing.T) {
	pool, ctx := migrationTestPool(t)
	if err := Migrate(ctx, pool); err != nil {
		t.Fatal(err)
	}
	db := &Store{Pool: pool}
	organizationID, ownerID, memberID := uuid.New(), uuid.New(), uuid.New()
	projectID, environmentID, sessionID, localSessionID, providerID := uuid.New(), uuid.New(), uuid.New(), uuid.New(), uuid.New()
	for _, statement := range []struct {
		query string
		args  []any
	}{
		{`INSERT INTO organizations(id,name,slug) VALUES($1,'RBAC audit',$2)`, []any{organizationID, "rbac-audit-" + organizationID.String()}},
		{`INSERT INTO users(id,email,password_hash) VALUES($1,$2,'!test'),($3,$4,'!test')`, []any{ownerID, ownerID.String() + "@example.test", memberID, memberID.String() + "@example.test"}},
		{`INSERT INTO memberships(organization_id,user_id,role) VALUES($1,$2,'owner'),($1,$3,'viewer')`, []any{organizationID, ownerID, memberID}},
		{`INSERT INTO oidc_providers(id,organization_id,name,issuer,client_id,encrypted_client_secret,domains) VALUES($1,$2,'RBAC OIDC','https://identity.example.test','client','ciphertext','{example.test}')`, []any{providerID, organizationID}},
		{`INSERT INTO sessions(id,user_id,organization_id,oidc_provider_id,token_hash,expires_at,auth_method) VALUES($1,$2,$3,$4,$5,$6,'oidc')`, []any{sessionID, memberID, organizationID, providerID, []byte("member-session"), time.Now().Add(time.Hour)}},
		{`INSERT INTO sessions(id,user_id,token_hash,expires_at,auth_method) VALUES($1,$2,$3,$4,'local')`, []any{localSessionID, memberID, []byte("member-local-session"), time.Now().Add(time.Hour)}},
		{`INSERT INTO projects(id,organization_id,name,slug) VALUES($1,$2,'Project','project')`, []any{projectID, organizationID}},
		{`INSERT INTO environments(id,project_id,name,slug) VALUES($1,$2,'Production','production')`, []any{environmentID, projectID}},
	} {
		if _, err := pool.Exec(ctx, statement.query, statement.args...); err != nil {
			t.Fatal(err)
		}
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `DELETE FROM organizations WHERE id=$1`, organizationID)
		_, _ = pool.Exec(context.Background(), `DELETE FROM users WHERE id=ANY($1)`, []uuid.UUID{ownerID, memberID})
	})
	principal := Principal{OrganizationID: organizationID, UserID: ownerID, Role: "owner"}
	missingServiceAccountID := uuid.New()
	invalidAuditPrincipal := principal
	invalidAuditPrincipal.ServiceAccountID = &missingServiceAccountID

	if _, err := db.UpdateOrganizationMemberRoleWithAudit(ctx, invalidAuditPrincipal, memberID, "developer", "127.0.0.1:1234"); err == nil {
		t.Fatal("member role changed without valid audit evidence")
	}
	assertMembershipRole(t, pool, ctx, organizationID, memberID, "viewer")
	if _, err := db.UpdateOrganizationMemberRoleWithAudit(ctx, principal, memberID, "developer", "127.0.0.1:1234"); err != nil {
		t.Fatal(err)
	}

	if _, err := db.UpsertResourceGrantWithAudit(ctx, invalidAuditPrincipal, "project", projectID, memberID, "admin", "127.0.0.1:1234"); err == nil {
		t.Fatal("project grant created without valid audit evidence")
	}
	assertGrantCount(t, pool, ctx, "project_grants", "project_id", projectID, memberID, 0)
	if _, err := db.UpsertResourceGrantWithAudit(ctx, principal, "project", projectID, memberID, "developer", "127.0.0.1:1234"); err != nil {
		t.Fatal(err)
	}
	if _, err := db.UpsertResourceGrantWithAudit(ctx, invalidAuditPrincipal, "project", projectID, memberID, "admin", "127.0.0.1:1234"); err == nil {
		t.Fatal("project grant updated without valid audit evidence")
	}
	var projectRole string
	if err := pool.QueryRow(ctx, `SELECT role FROM project_grants WHERE project_id=$1 AND user_id=$2`, projectID, memberID).Scan(&projectRole); err != nil || projectRole != "developer" {
		t.Fatalf("failed evidence changed project grant role=%q err=%v", projectRole, err)
	}

	if _, err := db.UpsertResourceGrantWithAudit(ctx, principal, "environment", environmentID, memberID, "admin", "127.0.0.1:1234"); err != nil {
		t.Fatal(err)
	}
	if err := db.DeleteResourceGrantWithAudit(ctx, invalidAuditPrincipal, "environment", environmentID, memberID, "127.0.0.1:1234"); err == nil {
		t.Fatal("environment grant deleted without valid audit evidence")
	}
	assertGrantCount(t, pool, ctx, "environment_grants", "environment_id", environmentID, memberID, 1)
	if err := db.DeleteResourceGrantWithAudit(ctx, principal, "environment", environmentID, memberID, "127.0.0.1:1234"); err != nil {
		t.Fatal(err)
	}

	if err := db.DeleteOrganizationMemberWithAudit(ctx, invalidAuditPrincipal, memberID, "127.0.0.1:1234"); err == nil {
		t.Fatal("member removed without valid audit evidence")
	}
	assertMembershipRole(t, pool, ctx, organizationID, memberID, "developer")
	assertGrantCount(t, pool, ctx, "project_grants", "project_id", projectID, memberID, 1)
	var sessionCount int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM sessions WHERE id=$1`, sessionID).Scan(&sessionCount); err != nil || sessionCount != 1 {
		t.Fatalf("failed evidence removed member session: count=%d err=%v", sessionCount, err)
	}
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM sessions WHERE id=$1`, localSessionID).Scan(&sessionCount); err != nil || sessionCount != 1 {
		t.Fatalf("failed evidence removed member local session: count=%d err=%v", sessionCount, err)
	}
	if err := db.DeleteOrganizationMemberWithAudit(ctx, principal, memberID, "127.0.0.1:1234"); err != nil {
		t.Fatal(err)
	}
	var membershipCount int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM memberships WHERE organization_id=$1 AND user_id=$2`, organizationID, memberID).Scan(&membershipCount); err != nil || membershipCount != 0 {
		t.Fatalf("member removal count=%d err=%v", membershipCount, err)
	}
	assertGrantCount(t, pool, ctx, "project_grants", "project_id", projectID, memberID, 0)
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM sessions WHERE id=ANY($1)`, []uuid.UUID{sessionID, localSessionID}).Scan(&sessionCount); err != nil || sessionCount != 0 {
		t.Fatalf("member session removal count=%d err=%v", sessionCount, err)
	}

	var membershipAudits, grantAudits int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM audit_events WHERE organization_id=$1 AND actor_user_id=$2 AND resource_id=$3 AND action IN ('membership.role.update','membership.remove')`, organizationID, ownerID, memberID.String()).Scan(&membershipAudits); err != nil || membershipAudits != 2 {
		t.Fatalf("membership audit count=%d err=%v", membershipAudits, err)
	}
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM audit_events WHERE organization_id=$1 AND actor_user_id=$2 AND action IN ('grant.update','grant.delete')`, organizationID, ownerID).Scan(&grantAudits); err != nil || grantAudits != 3 {
		t.Fatalf("grant audit count=%d err=%v", grantAudits, err)
	}
}

func assertMembershipRole(t *testing.T, pool interface {
	QueryRow(context.Context, string, ...any) pgx.Row
}, ctx context.Context, organizationID, userID uuid.UUID, want string) {
	t.Helper()
	var role string
	if err := pool.QueryRow(ctx, `SELECT role FROM memberships WHERE organization_id=$1 AND user_id=$2`, organizationID, userID).Scan(&role); err != nil || role != want {
		t.Fatalf("membership role=%q err=%v, want %q", role, err, want)
	}
}

func assertGrantCount(t *testing.T, pool interface {
	QueryRow(context.Context, string, ...any) pgx.Row
}, ctx context.Context, table, idColumn string, scopeID, userID uuid.UUID, want int) {
	t.Helper()
	var count int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM `+table+` WHERE `+idColumn+`=$1 AND user_id=$2`, scopeID, userID).Scan(&count); err != nil || count != want {
		t.Fatalf("%s count=%d err=%v, want %d", table, count, err, want)
	}
}
