package store

import (
	"errors"
	"testing"

	"github.com/google/uuid"
)

func TestTemplateRepositoryLifecycleCommitsWithAudit(t *testing.T) {
	pool, ctx := migrationTestPool(t)
	if err := Migrate(ctx, pool); err != nil {
		t.Fatal(err)
	}
	db := &Store{Pool: pool}
	organizationID, userID := uuid.New(), uuid.New()
	if _, err := pool.Exec(ctx, `INSERT INTO organizations(id,name,slug) VALUES($1,'Template repository audit',$2)`, organizationID, "template-repository-audit-"+organizationID.String()); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO users(id,email,password_hash) VALUES($1,$2,'!test')`, userID, userID.String()+"@example.test"); err != nil {
		t.Fatal(err)
	}
	principal := Principal{OrganizationID: organizationID, UserID: userID, Role: "owner"}
	invalidPrincipal := Principal{OrganizationID: organizationID, UserID: uuid.New(), Role: "owner"}
	failedInput := TemplateRepository{Name: "Failed", Slug: "failed", RepositoryURL: "https://github.com/example/templates", GitRef: "main"}

	if _, err := db.CreateTemplateRepositoryWithAudit(ctx, invalidPrincipal, failedInput, "127.0.0.1:1234", nil); err == nil {
		t.Fatal("template repository creation succeeded without valid audit evidence")
	}
	var repositoryCount int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM template_repositories WHERE organization_id=$1`, organizationID).Scan(&repositoryCount); err != nil || repositoryCount != 0 {
		t.Fatalf("failed evidence retained template repository: count=%d err=%v", repositoryCount, err)
	}

	input := TemplateRepository{Name: "Community", Slug: "community", RepositoryURL: "https://github.com/example/templates", GitRef: "main"}
	repository, err := db.CreateTemplateRepositoryWithAudit(ctx, principal, input, "127.0.0.1:1234", map[string]any{"repositoryUrl": input.RepositoryURL, "gitRef": input.GitRef})
	if err != nil {
		t.Fatal(err)
	}
	if err = db.UpdateTemplateRepositorySettingsWithAudit(ctx, invalidPrincipal, repository.ID, "new-trusted-key", true, nil, 300, "127.0.0.1:1234", nil); err == nil {
		t.Fatal("template repository settings update succeeded without valid audit evidence")
	}
	loaded, err := db.GetTemplateRepository(ctx, organizationID, repository.ID)
	if err != nil || loaded.TrustedPublicKey != "" || loaded.RequireSignature || loaded.SyncIntervalSeconds != 0 || loaded.SyncRequestedAt != nil {
		t.Fatalf("failed evidence changed repository settings: repository=%#v err=%v", loaded, err)
	}
	if err = db.UpdateTemplateRepositorySettingsWithAudit(ctx, principal, repository.ID, "trusted-key", true, nil, 300, "127.0.0.1:1234", map[string]any{"requireSignature": true}); err != nil {
		t.Fatal(err)
	}

	if err = db.SetTemplateRepositoryWebhookSecretWithAudit(ctx, invalidPrincipal, repository.ID, "failed-encrypted-secret", "127.0.0.1:1234"); err == nil {
		t.Fatal("template repository webhook rotation succeeded without valid audit evidence")
	}
	loaded, err = db.GetTemplateRepository(ctx, organizationID, repository.ID)
	if err != nil || loaded.EncryptedWebhookSecret != "" {
		t.Fatalf("failed evidence retained template webhook secret: repository=%#v err=%v", loaded, err)
	}
	if err = db.SetTemplateRepositoryWebhookSecretWithAudit(ctx, principal, repository.ID, "active-encrypted-secret", "127.0.0.1:1234"); err != nil {
		t.Fatal(err)
	}
	if err = db.ClearTemplateRepositoryWebhookSecretWithAudit(ctx, invalidPrincipal, repository.ID, "127.0.0.1:1234"); err == nil {
		t.Fatal("template repository webhook disablement succeeded without valid audit evidence")
	}
	loaded, err = db.GetTemplateRepository(ctx, organizationID, repository.ID)
	if err != nil || loaded.EncryptedWebhookSecret != "active-encrypted-secret" {
		t.Fatalf("failed evidence cleared template webhook secret: repository=%#v err=%v", loaded, err)
	}
	if err = db.ClearTemplateRepositoryWebhookSecretWithAudit(ctx, principal, repository.ID, "127.0.0.1:1234"); err != nil {
		t.Fatal(err)
	}
	if err = db.SetTemplateRepositoryWebhookSecretWithAudit(ctx, principal, repository.ID, "active-encrypted-secret-2", "127.0.0.1:1234"); err != nil {
		t.Fatal(err)
	}

	if _, err = db.QueueTemplateRepositorySyncWithAudit(ctx, invalidPrincipal, repository.ID, "127.0.0.1:1234"); err == nil {
		t.Fatal("template repository sync queued without valid audit evidence")
	}
	loaded, err = db.GetTemplateRepository(ctx, organizationID, repository.ID)
	if err != nil || loaded.SyncRequestedAt != nil {
		t.Fatalf("failed evidence queued template sync: repository=%#v err=%v", loaded, err)
	}
	if _, err = db.QueueTemplateRepositorySyncWithAudit(ctx, principal, repository.ID, "127.0.0.1:1234"); err != nil {
		t.Fatal(err)
	}

	if _, err = pool.Exec(ctx, `CREATE FUNCTION reject_template_repository_webhook_audit() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF NEW.action='template_repository.webhook' THEN RAISE EXCEPTION 'forced audit failure'; END IF; RETURN NEW; END $$`); err != nil {
		t.Fatal(err)
	}
	if _, err = pool.Exec(ctx, `CREATE TRIGGER reject_template_repository_webhook_audit BEFORE INSERT ON audit_events FOR EACH ROW EXECUTE FUNCTION reject_template_repository_webhook_audit()`); err != nil {
		t.Fatal(err)
	}
	loaded, err = db.GetTemplateRepository(ctx, organizationID, repository.ID)
	if err != nil {
		t.Fatal(err)
	}
	if err = db.RequestTemplateRepositorySyncWithAudit(ctx, organizationID, repository.ID, "stale-secret-delivery", loaded.GitRef, "stale-encrypted-secret", "127.0.0.1:1234"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("stale template webhook secret error=%v, want not found", err)
	}
	if err = db.RequestTemplateRepositorySyncWithAudit(ctx, organizationID, repository.ID, "failed-delivery", loaded.GitRef, loaded.EncryptedWebhookSecret, "127.0.0.1:1234"); err == nil {
		t.Fatal("template repository webhook sync succeeded without valid audit evidence")
	}
	var failedDeliveryCount int
	if err = pool.QueryRow(ctx, `SELECT count(*) FROM template_repository_webhook_deliveries WHERE repository_id=$1 AND delivery_id='failed-delivery'`, repository.ID).Scan(&failedDeliveryCount); err != nil || failedDeliveryCount != 0 {
		t.Fatalf("failed evidence consumed webhook delivery: count=%d err=%v", failedDeliveryCount, err)
	}
	if _, err = pool.Exec(ctx, `DROP TRIGGER reject_template_repository_webhook_audit ON audit_events`); err != nil {
		t.Fatal(err)
	}
	if err = db.RequestTemplateRepositorySyncWithAudit(ctx, organizationID, repository.ID, "delivery-1", loaded.GitRef, loaded.EncryptedWebhookSecret, "127.0.0.1:1234"); err != nil {
		t.Fatal(err)
	}

	if err = db.DeleteTemplateRepositoryWithAudit(ctx, invalidPrincipal, repository.ID, "127.0.0.1:1234"); err == nil {
		t.Fatal("template repository deletion succeeded without valid audit evidence")
	}
	if _, err = db.GetTemplateRepository(ctx, organizationID, repository.ID); err != nil {
		t.Fatalf("failed evidence deleted template repository: %v", err)
	}
	if err = db.DeleteTemplateRepositoryWithAudit(ctx, principal, repository.ID, "127.0.0.1:1234"); err != nil {
		t.Fatal(err)
	}
	if _, err = db.GetTemplateRepository(ctx, organizationID, repository.ID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("deleted template repository lookup error=%v, want not found", err)
	}

	var operatorAuditCount, systemAuditCount, leakedSecretCount int
	if err = pool.QueryRow(ctx, `SELECT
		count(*) FILTER (WHERE actor_user_id=$2),
		count(*) FILTER (WHERE actor_user_id IS NULL AND action='template_repository.webhook'),
		count(*) FILTER (WHERE metadata::text LIKE '%encrypted-secret%')
		FROM audit_events WHERE organization_id=$1 AND resource_id=$3 AND action LIKE 'template_repository.%'`, organizationID, userID, repository.ID.String()).Scan(&operatorAuditCount, &systemAuditCount, &leakedSecretCount); err != nil {
		t.Fatal(err)
	}
	if operatorAuditCount != 7 || systemAuditCount != 1 || leakedSecretCount != 0 {
		t.Fatalf("template repository evidence: operator=%d system=%d leakedSecrets=%d", operatorAuditCount, systemAuditCount, leakedSecretCount)
	}
}
