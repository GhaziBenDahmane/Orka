package store

import (
	"testing"

	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"
)

func TestRouteBasicAuthLifecycleCommitsWithAudit(t *testing.T) {
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
		{`INSERT INTO organizations(id,name,slug) VALUES($1,'Route auth audit',$2)`, []any{organizationID, "route-auth-audit-" + organizationID.String()}},
		{`INSERT INTO users(id,email,password_hash) VALUES($1,$2,'!test')`, []any{userID, userID.String() + "@example.test"}},
		{`INSERT INTO projects(id,organization_id,name,slug) VALUES($1,$2,'Project','project')`, []any{projectID, organizationID}},
		{`INSERT INTO environments(id,project_id,name,slug) VALUES($1,$2,'Production','production')`, []any{environmentID, projectID}},
		{`INSERT INTO compose_services(id,environment_id,name,slug,stack_name,compose_yaml) VALUES($1,$2,'API','api',$3,'services: {}')`, []any{serviceID, environmentID, "route-auth-audit-" + serviceID.String()}},
	}
	for _, statement := range statements {
		if _, err := pool.Exec(ctx, statement.query, statement.args...); err != nil {
			t.Fatal(err)
		}
	}
	principal := Principal{OrganizationID: organizationID, UserID: userID, Role: "owner"}
	invalidPrincipal := Principal{OrganizationID: organizationID, UserID: uuid.New(), Role: "owner"}

	if _, err := db.CreateRouteBasicAuthUserWithAudit(ctx, invalidPrincipal, serviceID, "failed", "failed-secret", "127.0.0.1:1234"); err == nil {
		t.Fatal("route basic-auth creation succeeded without valid audit evidence")
	}
	users, err := db.ListRouteBasicAuthUsers(ctx, organizationID, serviceID)
	if err != nil || len(users) != 0 {
		t.Fatalf("failed evidence retained route basic-auth user: users=%#v err=%v", users, err)
	}

	item, err := db.CreateRouteBasicAuthUserWithAudit(ctx, principal, serviceID, "operator", "initial-secret", "127.0.0.1:1234")
	if err != nil {
		t.Fatal(err)
	}
	initialHash := item.PasswordHash
	if bcrypt.CompareHashAndPassword([]byte(initialHash), []byte("initial-secret")) != nil {
		t.Fatal("created route basic-auth password hash does not verify")
	}
	if _, err = db.UpdateRouteBasicAuthUserWithAudit(ctx, invalidPrincipal, serviceID, item.ID, "failed-update", "failed-rotation", "127.0.0.1:1234"); err == nil {
		t.Fatal("route basic-auth update succeeded without valid audit evidence")
	}
	users, err = db.ListRouteBasicAuthUsers(ctx, organizationID, serviceID)
	if err != nil || len(users) != 1 || users[0].Username != "operator" || users[0].PasswordHash != initialHash {
		t.Fatalf("failed evidence changed route basic-auth user: users=%#v err=%v", users, err)
	}

	item, err = db.UpdateRouteBasicAuthUserWithAudit(ctx, principal, serviceID, item.ID, "admin", "rotated-secret", "127.0.0.1:1234")
	if err != nil || item.Username != "admin" || item.PasswordHash == initialHash || bcrypt.CompareHashAndPassword([]byte(item.PasswordHash), []byte("rotated-secret")) != nil {
		t.Fatalf("audited route basic-auth update=%#v err=%v", item, err)
	}
	if err = db.DeleteRouteBasicAuthUserWithAudit(ctx, invalidPrincipal, serviceID, item.ID, "127.0.0.1:1234"); err == nil {
		t.Fatal("route basic-auth deletion succeeded without valid audit evidence")
	}
	users, err = db.ListRouteBasicAuthUsers(ctx, organizationID, serviceID)
	if err != nil || len(users) != 1 {
		t.Fatalf("failed evidence deleted route basic-auth user: users=%#v err=%v", users, err)
	}
	if err = db.DeleteRouteBasicAuthUserWithAudit(ctx, principal, serviceID, item.ID, "127.0.0.1:1234"); err != nil {
		t.Fatal(err)
	}
	users, err = db.ListRouteBasicAuthUsers(ctx, organizationID, serviceID)
	if err != nil || len(users) != 0 {
		t.Fatalf("audited route basic-auth deletion: users=%#v err=%v", users, err)
	}

	var auditCount, leakedSecretCount int
	if err = pool.QueryRow(ctx, `SELECT count(*),count(*) FILTER (WHERE metadata::text LIKE '%initial-secret%' OR metadata::text LIKE '%rotated-secret%' OR metadata::text LIKE '%$2a$%') FROM audit_events WHERE organization_id=$1 AND actor_user_id=$2 AND resource_type='service' AND resource_id=$3 AND action IN ('route_basic_auth.create','route_basic_auth.update','route_basic_auth.delete')`, organizationID, userID, serviceID.String()).Scan(&auditCount, &leakedSecretCount); err != nil {
		t.Fatal(err)
	}
	if auditCount != 3 || leakedSecretCount != 0 {
		t.Fatalf("route basic-auth evidence: count=%d leakedSecrets=%d", auditCount, leakedSecretCount)
	}
}
