package store

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"
)

func TestRouteBasicAuthUserNeverSerializesPasswordHash(t *testing.T) {
	encoded, err := json.Marshal(RouteBasicAuthUser{Username: "operator", PasswordHash: "secret-hash"})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(encoded), "secret-hash") || strings.Contains(string(encoded), "password") {
		t.Fatalf("serialized basic-auth user leaked password hash: %s", encoded)
	}
}

func TestRouteControlsLifecycle(t *testing.T) {
	pool, ctx := migrationTestPool(t)
	if err := Migrate(ctx, pool); err != nil {
		t.Fatal(err)
	}
	db := &Store{Pool: pool}
	organizationID, projectID, environmentID, serviceID := uuid.New(), uuid.New(), uuid.New(), uuid.New()
	for _, statement := range []struct {
		query string
		args  []any
	}{
		{`INSERT INTO organizations(id,name,slug) VALUES($1,'Routes',$2)`, []any{organizationID, "routes-" + organizationID.String()}},
		{`INSERT INTO projects(id,organization_id,name,slug) VALUES($1,$2,'Project','project')`, []any{projectID, organizationID}},
		{`INSERT INTO environments(id,project_id,name,slug) VALUES($1,$2,'Production','production')`, []any{environmentID, projectID}},
		{`INSERT INTO compose_services(id,environment_id,name,slug,stack_name,compose_yaml) VALUES($1,$2,'App','app',$3,'services: {web: {image: nginx}}')`, []any{serviceID, environmentID, "routes-" + serviceID.String()}},
	} {
		if _, err := pool.Exec(ctx, statement.query, statement.args...); err != nil {
			t.Fatal(err)
		}
	}
	created, err := db.AddRoute(ctx, organizationID, Route{ComposeServiceID: serviceID, ServiceName: "web", Host: "app.example.test", PathPrefix: "/public", InternalPath: "/internal", StripPath: true, RedirectRegex: `^https://app\.example\.test/old/(.*)`, RedirectReplacement: `https://app.example.test/new/${1}`, RedirectPermanent: true, TargetPort: 8080, TLS: true, CertificateResolver: "letsencrypt"})
	if err != nil {
		t.Fatal(err)
	}
	if !created.Enabled || created.InternalPath != "/internal" || !created.StripPath || created.CreatedAt.IsZero() || created.UpdatedAt.IsZero() {
		t.Fatalf("created route=%#v", created)
	}
	created.Disabled = true
	created.Enabled = false
	created.RedirectPermanent = false
	updated, err := db.UpdateRoute(ctx, organizationID, created)
	if err != nil {
		t.Fatal(err)
	}
	if updated.Enabled || !updated.Disabled || updated.RedirectPermanent {
		t.Fatalf("updated route=%#v", updated)
	}
	loaded, err := db.GetRoute(ctx, organizationID, created.ID)
	if err != nil {
		t.Fatal(err)
	}
	if loaded.Enabled || !loaded.Disabled || loaded.RedirectReplacement != created.RedirectReplacement || loaded.InternalPath != "/internal" {
		t.Fatalf("loaded route=%#v", loaded)
	}
	_, routes, err := db.GetComposeService(ctx, organizationID, serviceID)
	if err != nil || len(routes) != 1 || routes[0].Enabled || !routes[0].Disabled {
		t.Fatalf("service routes=%#v err=%v", routes, err)
	}
	auth, err := db.CreateRouteBasicAuthUser(ctx, organizationID, serviceID, "operator", "initial-secret")
	if err != nil || auth.PasswordHash == "" || auth.PasswordHash == "initial-secret" || bcrypt.CompareHashAndPassword([]byte(auth.PasswordHash), []byte("initial-secret")) != nil {
		t.Fatalf("created basic-auth user=%#v err=%v", auth, err)
	}
	users, err := db.ListRouteBasicAuthUsers(ctx, organizationID, serviceID)
	if err != nil || len(users) != 1 || users[0].Username != "operator" {
		t.Fatalf("basic-auth users=%#v err=%v", users, err)
	}
	previousHash := users[0].PasswordHash
	updatedAuth, err := db.UpdateRouteBasicAuthUser(ctx, organizationID, serviceID, auth.ID, "admin", "")
	if err != nil || updatedAuth.Username != "admin" || updatedAuth.PasswordHash != previousHash {
		t.Fatalf("updated basic-auth user=%#v err=%v", updatedAuth, err)
	}
	if err = db.DeleteRouteBasicAuthUser(ctx, organizationID, serviceID, auth.ID); err != nil {
		t.Fatal(err)
	}
	users, err = db.ListRouteBasicAuthUsers(ctx, organizationID, serviceID)
	if err != nil || len(users) != 0 {
		t.Fatalf("basic-auth users after deletion=%#v err=%v", users, err)
	}
}
