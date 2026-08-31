package store

import (
	"errors"
	"testing"

	"github.com/google/uuid"
)

func TestWebhookIntegrationLifecycleCommitsWithAudit(t *testing.T) {
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
		{`INSERT INTO organizations(id,name,slug) VALUES($1,'Webhook audit',$2)`, []any{organizationID, "webhook-audit-" + organizationID.String()}},
		{`INSERT INTO users(id,email,password_hash) VALUES($1,$2,'!test')`, []any{userID, userID.String() + "@example.test"}},
		{`INSERT INTO projects(id,organization_id,name,slug) VALUES($1,$2,'Project','project')`, []any{projectID, organizationID}},
		{`INSERT INTO environments(id,project_id,name,slug) VALUES($1,$2,'Production','production')`, []any{environmentID, projectID}},
		{`INSERT INTO compose_services(id,environment_id,name,slug,stack_name,compose_yaml) VALUES($1,$2,'API','api',$3,'services: {}')`, []any{serviceID, environmentID, "webhook-audit-" + serviceID.String()}},
	}
	for _, statement := range statements {
		if _, err := pool.Exec(ctx, statement.query, statement.args...); err != nil {
			t.Fatal(err)
		}
	}
	principal := Principal{OrganizationID: organizationID, UserID: userID, Role: "owner"}
	invalidPrincipal := Principal{OrganizationID: organizationID, UserID: uuid.New(), Role: "owner"}
	failed := WebhookIntegration{ID: uuid.New(), ComposeServiceID: serviceID, Name: "failed", Provider: "github", Branch: "main", EncryptedSecret: "failed-encrypted-secret"}

	if _, err := db.CreateWebhookIntegrationWithAudit(ctx, invalidPrincipal, failed, "127.0.0.1:1234"); err == nil {
		t.Fatal("webhook creation succeeded without valid audit evidence")
	}
	if _, err := db.GetWebhookIntegration(ctx, failed.ID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("failed evidence retained webhook integration: %v", err)
	}

	input := WebhookIntegration{ID: uuid.New(), ComposeServiceID: serviceID, Name: "GitHub", Provider: "github", Branch: "main", EncryptedSecret: "active-encrypted-secret"}
	item, err := db.CreateWebhookIntegrationWithAudit(ctx, principal, input, "127.0.0.1:1234")
	if err != nil {
		t.Fatal(err)
	}
	if err = db.DisableWebhookIntegrationWithAudit(ctx, invalidPrincipal, item.ID, "127.0.0.1:1234"); err == nil {
		t.Fatal("webhook disablement succeeded without valid audit evidence")
	}
	loaded, err := db.GetWebhookIntegration(ctx, item.ID)
	if err != nil || !loaded.Enabled || loaded.EncryptedSecret != input.EncryptedSecret {
		t.Fatalf("failed evidence disabled webhook: item=%#v err=%v", loaded, err)
	}
	if err = db.DisableWebhookIntegrationWithAudit(ctx, principal, item.ID, "127.0.0.1:1234"); err != nil {
		t.Fatal(err)
	}
	if _, err = db.GetWebhookIntegration(ctx, item.ID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("disabled webhook lookup error=%v, want not found", err)
	}

	var auditCount, leakedSecretCount int
	if err = pool.QueryRow(ctx, `SELECT count(*),count(*) FILTER (WHERE metadata::text LIKE '%encrypted-secret%') FROM audit_events WHERE organization_id=$1 AND actor_user_id=$2 AND resource_id=$3 AND action IN ('webhook.create','webhook.disable')`, organizationID, userID, item.ID.String()).Scan(&auditCount, &leakedSecretCount); err != nil {
		t.Fatal(err)
	}
	if auditCount != 2 || leakedSecretCount != 0 {
		t.Fatalf("webhook evidence: count=%d leakedSecrets=%d", auditCount, leakedSecretCount)
	}
}
