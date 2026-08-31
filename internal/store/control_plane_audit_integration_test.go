package store

import (
	"testing"

	"github.com/google/uuid"
)

func TestBootstrapAndPolicyMutationsCommitWithAudit(t *testing.T) {
	pool, ctx := migrationTestPool(t)
	if err := Migrate(ctx, pool); err != nil {
		t.Fatal(err)
	}
	db := &Store{Pool: pool}
	if _, err := pool.Exec(ctx, `CREATE FUNCTION reject_bootstrap_audit() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF NEW.action='auth.bootstrap' THEN RAISE EXCEPTION 'forced audit failure'; END IF; RETURN NEW; END $$`); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `CREATE TRIGGER reject_bootstrap_audit BEFORE INSERT ON audit_events FOR EACH ROW EXECUTE FUNCTION reject_bootstrap_audit()`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.BootstrapWithAudit(ctx, "owner@example.test", "password-hash", "Organization", "organization", "127.0.0.1:1234"); err == nil {
		t.Fatal("bootstrap succeeded after audit rejection")
	}
	var users, organizations, memberships int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM users`).Scan(&users); err != nil {
		t.Fatal(err)
	}
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM organizations`).Scan(&organizations); err != nil {
		t.Fatal(err)
	}
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM memberships`).Scan(&memberships); err != nil {
		t.Fatal(err)
	}
	if users != 0 || organizations != 0 || memberships != 0 {
		t.Fatalf("failed bootstrap retained state: users=%d organizations=%d memberships=%d", users, organizations, memberships)
	}
	if _, err := pool.Exec(ctx, `DROP TRIGGER reject_bootstrap_audit ON audit_events`); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `DROP FUNCTION reject_bootstrap_audit()`); err != nil {
		t.Fatal(err)
	}
	principal, err := db.BootstrapWithAudit(ctx, "owner@example.test", "password-hash", "Organization", "organization", "127.0.0.1:1234")
	if err != nil {
		t.Fatal(err)
	}
	serviceAccountID := uuid.New()
	if _, err = pool.Exec(ctx, `INSERT INTO service_accounts(id,organization_id,name,role) VALUES($1,$2,'policy-operator','admin')`, serviceAccountID, principal.OrganizationID); err != nil {
		t.Fatal(err)
	}
	initialLimit := 10
	initial, err := db.PutResourcePolicy(ctx, ResourcePolicy{OrganizationID: principal.OrganizationID, ScopeType: "organization", ScopeID: principal.OrganizationID, MaxProjects: &initialLimit})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = pool.Exec(ctx, `CREATE FUNCTION reject_policy_audit() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF NEW.action='policy.update' THEN RAISE EXCEPTION 'forced audit failure'; END IF; RETURN NEW; END $$`); err != nil {
		t.Fatal(err)
	}
	if _, err = pool.Exec(ctx, `CREATE TRIGGER reject_policy_audit BEFORE INSERT ON audit_events FOR EACH ROW EXECUTE FUNCTION reject_policy_audit()`); err != nil {
		t.Fatal(err)
	}
	replacementLimit := 20
	servicePrincipal := Principal{OrganizationID: principal.OrganizationID, ServiceAccountID: &serviceAccountID, Role: "admin"}
	if _, err = db.PutResourcePolicyWithAudit(ctx, servicePrincipal, ResourcePolicy{ScopeType: "organization", ScopeID: principal.OrganizationID, Maintenance: true, MaintenanceReason: "failed", MaxProjects: &replacementLimit}, "127.0.0.1:1234"); err == nil {
		t.Fatal("policy update succeeded after audit rejection")
	}
	stored, err := db.GetResourcePolicy(ctx, principal.OrganizationID, "organization", principal.OrganizationID)
	if err != nil {
		t.Fatal(err)
	}
	if stored.Maintenance || stored.MaintenanceReason != "" || stored.MaxProjects == nil || *stored.MaxProjects != initialLimit || !stored.UpdatedAt.Equal(initial.UpdatedAt) {
		t.Fatalf("failed audit changed policy: %#v", stored)
	}
	if _, err = pool.Exec(ctx, `DROP TRIGGER reject_policy_audit ON audit_events`); err != nil {
		t.Fatal(err)
	}
	if _, err = pool.Exec(ctx, `DROP FUNCTION reject_policy_audit()`); err != nil {
		t.Fatal(err)
	}
	updated, err := db.PutResourcePolicyWithAudit(ctx, servicePrincipal, ResourcePolicy{ScopeType: "organization", ScopeID: principal.OrganizationID, Maintenance: true, MaintenanceReason: "upgrade", MaxProjects: &replacementLimit}, "127.0.0.1:1234")
	if err != nil {
		t.Fatal(err)
	}
	if !updated.Maintenance || updated.MaintenanceReason != "upgrade" || updated.MaxProjects == nil || *updated.MaxProjects != replacementLimit {
		t.Fatalf("audited policy update=%#v", updated)
	}
	var bootstrapAudits, policyAudits int
	if err = pool.QueryRow(ctx, `SELECT count(*) FROM audit_events WHERE organization_id=$1 AND actor_user_id=$2 AND action='auth.bootstrap' AND resource_id=$3`, principal.OrganizationID, principal.UserID, principal.OrganizationID.String()).Scan(&bootstrapAudits); err != nil {
		t.Fatal(err)
	}
	if err = pool.QueryRow(ctx, `SELECT count(*) FROM audit_events WHERE organization_id=$1 AND actor_user_id IS NULL AND actor_service_account_id=$2 AND action='policy.update' AND resource_id=$3`, principal.OrganizationID, serviceAccountID, principal.OrganizationID.String()).Scan(&policyAudits); err != nil {
		t.Fatal(err)
	}
	if bootstrapAudits != 1 || policyAudits != 1 {
		t.Fatalf("control-plane audit counts: bootstrap=%d policy=%d", bootstrapAudits, policyAudits)
	}
}
