package store

import (
	"context"
	"errors"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
)

func TestResourcePoliciesEnforceHierarchy(t *testing.T) {
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
	orgID, projectID, environmentID := uuid.New(), uuid.New(), uuid.New()
	if _, err = db.Pool.Exec(ctx, `INSERT INTO organizations(id,name,slug) VALUES($1,'Policy',$2)`, orgID, "policy-"+orgID.String()); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _ = db.Pool.Exec(context.Background(), `DELETE FROM organizations WHERE id=$1`, orgID) })
	if _, err = db.Pool.Exec(ctx, `INSERT INTO projects(id,organization_id,name,slug) VALUES($1,$2,'Project','project')`, projectID, orgID); err != nil {
		t.Fatal(err)
	}
	if _, err = db.Pool.Exec(ctx, `INSERT INTO environments(id,project_id,name,slug) VALUES($1,$2,'Production','production')`, environmentID, projectID); err != nil {
		t.Fatal(err)
	}

	one := 1
	if _, err = db.PutResourcePolicy(ctx, ResourcePolicy{OrganizationID: orgID, ScopeType: "organization", ScopeID: orgID, MaxProjects: &one}); err != nil {
		t.Fatal(err)
	}
	if _, err = db.CreateProject(ctx, orgID, "Second", "second", ""); err == nil {
		t.Fatal("expected organization project quota")
	} else {
		var quota *QuotaExceededError
		if !errors.As(err, &quota) || quota.Scope != "organization" || quota.Resource != "projects" {
			t.Fatalf("unexpected project quota error: %v", err)
		}
	}
	two := 2
	if _, err = db.PutResourcePolicy(ctx, ResourcePolicy{OrganizationID: orgID, ScopeType: "organization", ScopeID: orgID, MaxProjects: &two}); err != nil {
		t.Fatal(err)
	}
	var wait sync.WaitGroup
	results := make(chan error, 2)
	for _, slug := range []string{"concurrent-a", "concurrent-b"} {
		wait.Add(1)
		go func() {
			defer wait.Done()
			_, createErr := db.CreateProject(ctx, orgID, slug, slug, "")
			results <- createErr
		}()
	}
	wait.Wait()
	close(results)
	succeeded, rejected := 0, 0
	for result := range results {
		if result == nil {
			succeeded++
			continue
		}
		var quota *QuotaExceededError
		if errors.As(result, &quota) {
			rejected++
		} else {
			t.Fatalf("unexpected concurrent create error: %v", result)
		}
	}
	if succeeded != 1 || rejected != 1 {
		t.Fatalf("concurrent quota results: succeeded=%d rejected=%d", succeeded, rejected)
	}
	if _, err = db.PutResourcePolicy(ctx, ResourcePolicy{OrganizationID: orgID, ScopeType: "project", ScopeID: projectID, MaxEnvironments: &one}); err != nil {
		t.Fatal(err)
	}
	if _, err = db.CreateEnvironment(ctx, orgID, projectID, "Second", "second"); err == nil {
		t.Fatal("expected project environment quota")
	}

	service, err := db.CreateComposeService(ctx, orgID, ComposeService{EnvironmentID: environmentID, Name: "One", Slug: "one", StackName: "policy-" + uuid.NewString(), ComposeYAML: "services: {}"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = db.PutResourcePolicy(ctx, ResourcePolicy{OrganizationID: orgID, ScopeType: "environment", ScopeID: environmentID, MaxServices: &one}); err != nil {
		t.Fatal(err)
	}
	if _, err = db.CreateComposeService(ctx, orgID, ComposeService{EnvironmentID: environmentID, Name: "Two", Slug: "two", StackName: "policy-" + uuid.NewString(), ComposeYAML: "services: {}"}); err == nil {
		t.Fatal("expected environment service quota")
	}
	policy, err := db.PutResourcePolicy(ctx, ResourcePolicy{OrganizationID: orgID, ScopeType: "project", ScopeID: projectID, Maintenance: true, MaintenanceReason: "planned upgrade", MaxEnvironments: &one})
	if err != nil || !policy.Maintenance {
		t.Fatalf("maintenance policy = %#v, err = %v", policy, err)
	}
	if _, err = db.QueueDeployment(ctx, orgID, service.ID, uuid.Nil, "manual"); !errors.Is(err, ErrMaintenance) {
		t.Fatalf("deployment during maintenance error = %v", err)
	}
}
