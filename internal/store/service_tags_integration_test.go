package store

import (
	"errors"
	"testing"

	"github.com/google/uuid"
)

func TestServiceTagsLifecycleAndTenantIsolation(t *testing.T) {
	pool, ctx := migrationTestPool(t)
	if err := Migrate(ctx, pool); err != nil {
		t.Fatal(err)
	}
	db := &Store{Pool: pool}
	organizationID, otherOrganizationID := uuid.New(), uuid.New()
	projectID, environmentID, serviceID := uuid.New(), uuid.New(), uuid.New()
	for _, statement := range []struct {
		query string
		args  []any
	}{
		{`INSERT INTO organizations(id,name,slug) VALUES($1,'Tags',$2),($3,'Other',$4)`, []any{organizationID, "tags-" + organizationID.String(), otherOrganizationID, "tags-" + otherOrganizationID.String()}},
		{`INSERT INTO projects(id,organization_id,name,slug) VALUES($1,$2,'Project','project')`, []any{projectID, organizationID}},
		{`INSERT INTO environments(id,project_id,name,slug) VALUES($1,$2,'Production','production')`, []any{environmentID, projectID}},
		{`INSERT INTO compose_services(id,environment_id,name,slug,stack_name,compose_yaml) VALUES($1,$2,'App','app',$3,'services: {web: {image: nginx}}')`, []any{serviceID, environmentID, "tags-" + serviceID.String()}},
	} {
		if _, err := pool.Exec(ctx, statement.query, statement.args...); err != nil {
			t.Fatal(err)
		}
	}
	production, err := db.CreateTag(ctx, organizationID, Tag{Name: "Production", Color: "#DC2626"})
	if err != nil {
		t.Fatal(err)
	}
	frontend, err := db.CreateTag(ctx, organizationID, Tag{Name: "Frontend", Color: "#2563EB"})
	if err != nil {
		t.Fatal(err)
	}
	foreign, err := db.CreateTag(ctx, otherOrganizationID, Tag{Name: "Foreign", Color: "#64748B"})
	if err != nil {
		t.Fatal(err)
	}
	assigned, err := db.ReplaceServiceTags(ctx, organizationID, serviceID, []uuid.UUID{production.ID, frontend.ID})
	if err != nil || len(assigned) != 2 || assigned[0].Name != "Frontend" || assigned[1].Name != "Production" {
		t.Fatalf("assigned=%#v err=%v", assigned, err)
	}
	service, _, err := db.GetComposeService(ctx, organizationID, serviceID)
	if err != nil || len(service.Tags) != 2 {
		t.Fatalf("service tags=%#v err=%v", service.Tags, err)
	}
	services, err := db.ListComposeServices(ctx, organizationID, environmentID)
	if err != nil || len(services) != 1 || len(services[0].Tags) != 2 {
		t.Fatalf("listed services=%#v err=%v", services, err)
	}
	projectTags, err := db.ReplaceProjectTags(ctx, organizationID, projectID, []uuid.UUID{production.ID})
	if err != nil || len(projectTags) != 1 || projectTags[0].ID != production.ID {
		t.Fatalf("project tags=%#v err=%v", projectTags, err)
	}
	projects, err := db.ListProjects(ctx, organizationID)
	if err != nil || len(projects) != 1 || len(projects[0].Tags) != 1 || projects[0].Tags[0].ID != production.ID {
		t.Fatalf("listed projects=%#v err=%v", projects, err)
	}
	loadedProject, err := db.GetProject(ctx, organizationID, projectID)
	if err != nil || len(loadedProject.Tags) != 1 || loadedProject.Tags[0].ID != production.ID {
		t.Fatalf("loaded project=%#v err=%v", loadedProject, err)
	}
	if _, err = db.ReplaceProjectTags(ctx, organizationID, projectID, []uuid.UUID{foreign.ID}); !errors.Is(err, ErrNotFound) {
		t.Fatalf("cross-tenant project assignment error=%v", err)
	}
	tagCatalog, err := db.ListTags(ctx, organizationID)
	if err != nil || len(tagCatalog) != 2 || tagCatalog[1].ProjectCount != 1 || tagCatalog[1].ServiceCount != 1 {
		t.Fatalf("tag catalog=%#v err=%v", tagCatalog, err)
	}
	snapshot, err := db.BuildAIAuditSnapshot(ctx, organizationID)
	if err != nil || len(snapshot.Services) != 1 || len(snapshot.Services[0].Tags) != 2 || snapshot.Services[0].Tags[0] != "Frontend" || snapshot.Services[0].Tags[1] != "Production" || len(snapshot.Projects) != 1 || len(snapshot.Projects[0].Tags) != 1 || snapshot.Projects[0].Tags[0] != "Production" {
		t.Fatalf("audit tags projects=%#v services=%#v err=%v", snapshot.Projects, snapshot.Services, err)
	}
	if _, err = db.ReplaceServiceTags(ctx, organizationID, serviceID, []uuid.UUID{foreign.ID}); !errors.Is(err, ErrNotFound) {
		t.Fatalf("cross-tenant assignment error=%v", err)
	}
	assigned, err = db.ListServiceTags(ctx, organizationID, serviceID)
	if err != nil || len(assigned) != 2 {
		t.Fatalf("failed replacement changed tags=%#v err=%v", assigned, err)
	}
	if err = db.DeleteTag(ctx, organizationID, production.ID); err != nil {
		t.Fatal(err)
	}
	assigned, err = db.ListServiceTags(ctx, organizationID, serviceID)
	if err != nil || len(assigned) != 1 || assigned[0].ID != frontend.ID {
		t.Fatalf("tags after deletion=%#v err=%v", assigned, err)
	}
	projectTags, err = db.ListProjectTags(ctx, organizationID, projectID)
	if err != nil || len(projectTags) != 0 {
		t.Fatalf("project tags after deletion=%#v err=%v", projectTags, err)
	}
}
