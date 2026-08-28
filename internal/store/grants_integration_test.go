package store

import (
	"context"
	"errors"
	"os"
	"testing"
	"time"

	"github.com/google/uuid"
)

func TestScopedGrantInheritanceAndTenantIsolation(t *testing.T) {
	databaseURL := os.Getenv("DOCKYARD_TEST_DATABASE_URL")
	if databaseURL == "" {
		t.Skip("DOCKYARD_TEST_DATABASE_URL is not set")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	db, err := Open(ctx, databaseURL)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(db.Pool.Close)
	orgID, otherOrgID, userID := uuid.New(), uuid.New(), uuid.New()
	projectID, otherProjectID, environmentID := uuid.New(), uuid.New(), uuid.New()
	statements := []struct {
		query string
		args  []any
	}{
		{`INSERT INTO users(id,email,password_hash) VALUES($1,$2,'x')`, []any{userID, "scope-" + userID.String() + "@example.test"}},
		{`INSERT INTO organizations(id,name,slug) VALUES($1,'Scoped',$2),($3,'Other',$4)`, []any{orgID, "scope-" + orgID.String(), otherOrgID, "other-" + otherOrgID.String()}},
		{`INSERT INTO memberships(organization_id,user_id,role) VALUES($1,$2,'viewer')`, []any{orgID, userID}},
		{`INSERT INTO projects(id,organization_id,name,slug) VALUES($1,$2,'Project','project'),($3,$4,'Other','other')`, []any{projectID, orgID, otherProjectID, otherOrgID}},
		{`INSERT INTO environments(id,project_id,name,slug) VALUES($1,$2,'Production','production')`, []any{environmentID, projectID}},
	}
	for _, statement := range statements {
		if _, err = db.Pool.Exec(ctx, statement.query, statement.args...); err != nil {
			t.Fatal(err)
		}
	}
	t.Cleanup(func() {
		_, _ = db.Pool.Exec(context.Background(), `DELETE FROM organizations WHERE id IN ($1,$2)`, orgID, otherOrgID)
		_, _ = db.Pool.Exec(context.Background(), `DELETE FROM users WHERE id=$1`, userID)
	})
	p := Principal{UserID: userID, OrganizationID: orgID, Role: "viewer"}
	if role, err := db.EffectiveResourceRole(ctx, p, "environment", environmentID); err != nil || role != "viewer" {
		t.Fatalf("baseline role = %q, err = %v", role, err)
	}
	if _, err = db.UpsertResourceGrant(ctx, orgID, "project", projectID, userID, "developer"); err != nil {
		t.Fatal(err)
	}
	if role, err := db.EffectiveResourceRole(ctx, p, "environment", environmentID); err != nil || role != "developer" {
		t.Fatalf("inherited role = %q, err = %v", role, err)
	}
	if _, err = db.UpsertResourceGrant(ctx, orgID, "environment", environmentID, userID, "admin"); err != nil {
		t.Fatal(err)
	}
	if role, err := db.EffectiveResourceRole(ctx, p, "environment", environmentID); err != nil || role != "admin" {
		t.Fatalf("environment role = %q, err = %v", role, err)
	}
	items, err := db.ListResourceGrants(ctx, orgID, "environment", environmentID)
	if err != nil || len(items) != 1 || items[0].Email == "" {
		t.Fatalf("grants = %#v, err = %v", items, err)
	}
	if _, err = db.UpsertResourceGrant(ctx, orgID, "project", otherProjectID, userID, "admin"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("cross-tenant grant error = %v", err)
	}
	owner := Principal{UserID: uuid.New(), OrganizationID: orgID, Role: "owner"}
	if _, err = db.EffectiveResourceRole(ctx, owner, "project", otherProjectID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("cross-tenant owner lookup error = %v", err)
	}
	if err = db.DeleteResourceGrant(ctx, orgID, "environment", environmentID, userID); err != nil {
		t.Fatal(err)
	}
	if role, err := db.EffectiveResourceRole(ctx, p, "environment", environmentID); err != nil || role != "developer" {
		t.Fatalf("role after delete = %q, err = %v", role, err)
	}
}
