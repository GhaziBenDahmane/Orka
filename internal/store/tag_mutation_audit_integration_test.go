package store

import (
	"context"
	"testing"

	"github.com/google/uuid"
)

func TestTagMutationsCommitWithAudit(t *testing.T) {
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
		{`INSERT INTO organizations(id,name,slug) VALUES($1,'Tag audit',$2)`, []any{organizationID, "tag-audit-" + organizationID.String()}},
		{`INSERT INTO users(id,email,password_hash) VALUES($1,$2,'!test')`, []any{userID, userID.String() + "@example.test"}},
		{`INSERT INTO service_accounts(id,organization_id,name,role,created_by) VALUES($1,$2,'automation','admin',$3)`, []any{serviceAccountID, organizationID, userID}},
		{`INSERT INTO projects(id,organization_id,name,slug) VALUES($1,$2,'Project','project')`, []any{projectID, organizationID}},
		{`INSERT INTO environments(id,project_id,name,slug) VALUES($1,$2,'Production','production')`, []any{environmentID, projectID}},
		{`INSERT INTO compose_services(id,environment_id,name,slug,stack_name,compose_yaml) VALUES($1,$2,'App','app',$3,'services: {web: {image: nginx}}')`, []any{serviceID, environmentID, "tag-audit-" + serviceID.String()}},
	} {
		if _, err := pool.Exec(ctx, statement.query, statement.args...); err != nil {
			t.Fatal(err)
		}
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `DELETE FROM organizations WHERE id=$1`, organizationID)
		_, _ = pool.Exec(context.Background(), `DELETE FROM users WHERE id=$1`, userID)
	})
	principal := Principal{OrganizationID: organizationID, UserID: userID}
	servicePrincipal := Principal{OrganizationID: organizationID, ServiceAccountID: &serviceAccountID}
	missingServiceAccountID := uuid.New()
	invalidPrincipal := principal
	invalidPrincipal.ServiceAccountID = &missingServiceAccountID

	discardedID := uuid.New()
	if _, err := db.CreateTagWithAudit(ctx, invalidPrincipal, Tag{ID: discardedID, Name: "discarded", Color: "#000000"}, "127.0.0.1:1234"); err == nil {
		t.Fatal("tag created without valid audit evidence")
	}
	var count int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM tags WHERE id=$1`, discardedID).Scan(&count); err != nil || count != 0 {
		t.Fatalf("failed evidence retained tag: count=%d err=%v", count, err)
	}

	tag, err := db.CreateTagWithAudit(ctx, principal, Tag{Name: "production", Color: "#112233"}, "127.0.0.1:1234")
	if err != nil {
		t.Fatal(err)
	}
	secondary, err := db.CreateTagWithAudit(ctx, servicePrincipal, Tag{Name: "secondary", Color: "#445566"}, "127.0.0.1:1234")
	if err != nil {
		t.Fatal(err)
	}
	if _, err = db.UpdateTagWithAudit(ctx, invalidPrincipal, tag.ID, "changed", "#FFFFFF", "127.0.0.1:1234"); err == nil {
		t.Fatal("tag updated without valid audit evidence")
	}
	stored, err := db.GetTag(ctx, organizationID, tag.ID)
	if err != nil || stored.Name != "production" || stored.Color != "#112233" {
		t.Fatalf("failed evidence changed tag: tag=%#v err=%v", stored, err)
	}
	if _, err = db.UpdateTagWithAudit(ctx, principal, tag.ID, "critical", "#AA0000", "127.0.0.1:1234"); err != nil {
		t.Fatal(err)
	}
	if _, err = db.ReplaceProjectTagsWithAudit(ctx, principal, projectID, []uuid.UUID{tag.ID}, "127.0.0.1:1234"); err != nil {
		t.Fatal(err)
	}
	if _, err = db.ReplaceServiceTagsWithAudit(ctx, principal, serviceID, []uuid.UUID{tag.ID}, "127.0.0.1:1234"); err != nil {
		t.Fatal(err)
	}
	if _, err = db.ReplaceProjectTagsWithAudit(ctx, invalidPrincipal, projectID, []uuid.UUID{secondary.ID}, "127.0.0.1:1234"); err == nil {
		t.Fatal("project tags replaced without valid audit evidence")
	}
	if _, err = db.ReplaceServiceTagsWithAudit(ctx, invalidPrincipal, serviceID, []uuid.UUID{secondary.ID}, "127.0.0.1:1234"); err == nil {
		t.Fatal("service tags replaced without valid audit evidence")
	}
	projectTags, err := db.ListProjectTags(ctx, organizationID, projectID)
	if err != nil || len(projectTags) != 1 || projectTags[0].ID != tag.ID {
		t.Fatalf("failed evidence changed project tags: tags=%#v err=%v", projectTags, err)
	}
	serviceTags, err := db.ListServiceTags(ctx, organizationID, serviceID)
	if err != nil || len(serviceTags) != 1 || serviceTags[0].ID != tag.ID {
		t.Fatalf("failed evidence changed service tags: tags=%#v err=%v", serviceTags, err)
	}
	if err = db.DeleteTagWithAudit(ctx, invalidPrincipal, tag.ID, "127.0.0.1:1234"); err == nil {
		t.Fatal("tag deleted without valid audit evidence")
	}
	stored, err = db.GetTag(ctx, organizationID, tag.ID)
	if err != nil || stored.ProjectCount != 1 || stored.ServiceCount != 1 {
		t.Fatalf("failed evidence removed tag or assignments: tag=%#v err=%v", stored, err)
	}
	if err = db.DeleteTagWithAudit(ctx, principal, tag.ID, "127.0.0.1:1234"); err != nil {
		t.Fatal(err)
	}
	if err = pool.QueryRow(ctx, `SELECT count(*) FROM audit_events WHERE organization_id=$1 AND actor_user_id=$2 AND action IN ('tag.create','tag.update','tag.delete','project.tags.replace','service.tags.replace')`, organizationID, userID).Scan(&count); err != nil || count != 5 {
		t.Fatalf("user tag audit count=%d err=%v", count, err)
	}
	if err = pool.QueryRow(ctx, `SELECT count(*) FROM audit_events WHERE organization_id=$1 AND actor_user_id IS NULL AND actor_service_account_id=$2 AND action='tag.create' AND resource_id=$3`, organizationID, serviceAccountID, secondary.ID.String()).Scan(&count); err != nil || count != 1 {
		t.Fatalf("service-account tag audit count=%d err=%v", count, err)
	}
}
