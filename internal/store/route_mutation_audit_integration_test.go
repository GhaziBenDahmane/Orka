package store

import (
	"testing"

	"github.com/google/uuid"
)

func TestRouteMutationsCommitWithAudit(t *testing.T) {
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
		{`INSERT INTO organizations(id,name,slug) VALUES($1,'Route mutation audit',$2)`, []any{organizationID, "route-mutation-audit-" + organizationID.String()}},
		{`INSERT INTO users(id,email,password_hash) VALUES($1,$2,'!test')`, []any{userID, userID.String() + "@example.test"}},
		{`INSERT INTO service_accounts(id,organization_id,name,role) VALUES($1,$2,'route-operator','admin')`, []any{serviceAccountID, organizationID}},
		{`INSERT INTO projects(id,organization_id,name,slug) VALUES($1,$2,'Project','project')`, []any{projectID, organizationID}},
		{`INSERT INTO environments(id,project_id,name,slug) VALUES($1,$2,'Production','production')`, []any{environmentID, projectID}},
		{`INSERT INTO compose_services(id,environment_id,name,slug,stack_name,compose_yaml) VALUES($1,$2,'API','api',$3,'services: {}')`, []any{serviceID, environmentID, "route-mutation-audit-" + serviceID.String()}},
	} {
		if _, err := pool.Exec(ctx, statement.query, statement.args...); err != nil {
			t.Fatal(err)
		}
	}
	existing, err := db.AddRoute(ctx, organizationID, Route{ComposeServiceID: serviceID, ServiceName: "api", Host: "existing.example.test", PathPrefix: "/", TargetPort: 8080, TLS: true, CertificateResolver: "letsencrypt"})
	if err != nil {
		t.Fatal(err)
	}
	principal := Principal{OrganizationID: organizationID, UserID: userID, Role: "owner"}
	servicePrincipal := Principal{OrganizationID: organizationID, ServiceAccountID: &serviceAccountID, Role: "admin"}
	if _, err = pool.Exec(ctx, `CREATE FUNCTION reject_route_mutation_audit() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF NEW.action IN ('route.create','route.update','route.delete') THEN RAISE EXCEPTION 'forced audit failure'; END IF; RETURN NEW; END $$`); err != nil {
		t.Fatal(err)
	}
	if _, err = pool.Exec(ctx, `CREATE TRIGGER reject_route_mutation_audit BEFORE INSERT ON audit_events FOR EACH ROW EXECUTE FUNCTION reject_route_mutation_audit()`); err != nil {
		t.Fatal(err)
	}
	failedCreate := Route{ComposeServiceID: serviceID, ServiceName: "api", Host: "failed.example.test", PathPrefix: "/", TargetPort: 8080, TLS: true, CertificateResolver: "letsencrypt"}
	if _, err = db.AddRouteWithAudit(ctx, principal, failedCreate, "127.0.0.1:1234"); err == nil {
		t.Fatal("route creation succeeded after audit rejection")
	}
	var failedCreateCount int
	if err = pool.QueryRow(ctx, `SELECT count(*) FROM routes WHERE compose_service_id=$1 AND host=$2`, serviceID, failedCreate.Host).Scan(&failedCreateCount); err != nil || failedCreateCount != 0 {
		t.Fatalf("failed route creation count=%d err=%v", failedCreateCount, err)
	}
	updated := existing
	updated.Host = "updated.example.test"
	updated.TargetPort = 9090
	if _, err = db.UpdateRouteWithAudit(ctx, servicePrincipal, updated, "127.0.0.1:1234"); err == nil {
		t.Fatal("route update succeeded after audit rejection")
	}
	stored, err := db.GetRoute(ctx, organizationID, existing.ID)
	if err != nil || stored.Host != existing.Host || stored.TargetPort != existing.TargetPort {
		t.Fatalf("failed audit changed route: route=%#v err=%v", stored, err)
	}
	if err = db.DeleteRouteWithAudit(ctx, principal, existing.ID, "127.0.0.1:1234"); err == nil {
		t.Fatal("route deletion succeeded after audit rejection")
	}
	if _, err = db.GetRoute(ctx, organizationID, existing.ID); err != nil {
		t.Fatalf("failed audit removed route: %v", err)
	}
	if _, err = pool.Exec(ctx, `DROP TRIGGER reject_route_mutation_audit ON audit_events`); err != nil {
		t.Fatal(err)
	}
	if _, err = pool.Exec(ctx, `DROP FUNCTION reject_route_mutation_audit()`); err != nil {
		t.Fatal(err)
	}

	created, err := db.AddRouteWithAudit(ctx, principal, Route{ComposeServiceID: serviceID, ServiceName: "api", Host: "created.example.test", PathPrefix: "/", TargetPort: 8080, TLS: true, CertificateResolver: "letsencrypt"}, "127.0.0.1:1234")
	if err != nil {
		t.Fatal(err)
	}
	updated, err = db.UpdateRouteWithAudit(ctx, servicePrincipal, updated, "127.0.0.1:1234")
	if err != nil || updated.Host != "updated.example.test" || updated.TargetPort != 9090 {
		t.Fatalf("audited route update=%#v err=%v", updated, err)
	}
	if err = db.DeleteRouteWithAudit(ctx, principal, created.ID, "127.0.0.1:1234"); err != nil {
		t.Fatal(err)
	}
	var userAudits, serviceAudits, deletedCount int
	if err = pool.QueryRow(ctx, `SELECT count(*) FROM audit_events WHERE organization_id=$1 AND actor_user_id=$2 AND actor_service_account_id IS NULL AND resource_id=ANY($3::text[]) AND action IN ('route.create','route.delete')`, organizationID, userID, []string{created.ID.String()}).Scan(&userAudits); err != nil {
		t.Fatal(err)
	}
	if err = pool.QueryRow(ctx, `SELECT count(*) FROM audit_events WHERE organization_id=$1 AND actor_user_id IS NULL AND actor_service_account_id=$2 AND action='route.update' AND resource_id=$3`, organizationID, serviceAccountID, existing.ID.String()).Scan(&serviceAudits); err != nil {
		t.Fatal(err)
	}
	if err = pool.QueryRow(ctx, `SELECT count(*) FROM routes WHERE id=$1`, created.ID).Scan(&deletedCount); err != nil {
		t.Fatal(err)
	}
	if userAudits != 2 || serviceAudits != 1 || deletedCount != 0 {
		t.Fatalf("route mutation evidence: user audits=%d service audits=%d deleted route count=%d", userAudits, serviceAudits, deletedCount)
	}
}
