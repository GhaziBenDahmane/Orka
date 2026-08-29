package store

import (
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"
)

func TestAIAuditsAndTemplateRepositories(t *testing.T) {
	pool, ctx := migrationTestPool(t)
	if err := Migrate(ctx, pool); err != nil {
		t.Fatal(err)
	}
	db := &Store{Pool: pool}
	organizationID, userID := uuid.New(), uuid.New()
	if _, err := pool.Exec(ctx, `INSERT INTO organizations(id,name,slug) VALUES($1,'AI test',$2)`, organizationID, "ai-"+organizationID.String()); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO users(id,email,password_hash) VALUES($1,$2,'unused')`, userID, userID.String()+"@example.test"); err != nil {
		t.Fatal(err)
	}
	credentialID := uuid.New()
	if _, err := db.CreateSourceCredential(ctx, SourceCredential{ID: credentialID, OrganizationID: organizationID, Kind: "git", Name: "GitHub", Server: "github.com", Username: "token", EncryptedSecret: "ciphertext"}); err != nil {
		t.Fatal(err)
	}
	repository, err := db.CreateTemplateRepository(ctx, TemplateRepository{OrganizationID: organizationID, Name: "Community", Slug: "community", RepositoryURL: "https://github.com/acme/templates", GitRef: "main", TrustedPublicKey: "catalog-key", RequireSignature: true, CredentialID: &credentialID, SyncIntervalSeconds: 3600})
	if err != nil {
		t.Fatal(err)
	}
	loaded, err := db.GetTemplateRepository(ctx, organizationID, repository.ID)
	if err != nil || loaded.TrustedPublicKey != "catalog-key" || !loaded.RequireSignature || loaded.CredentialID == nil || *loaded.CredentialID != credentialID || loaded.SyncIntervalSeconds != 3600 || loaded.NextSyncAt == nil {
		t.Fatalf("repository trust policy=%#v err=%v", loaded, err)
	}
	otherOrganizationID := uuid.New()
	if _, err = pool.Exec(ctx, `INSERT INTO organizations(id,name,slug) VALUES($1,'Other AI test',$2)`, otherOrganizationID, "other-ai-"+otherOrganizationID.String()); err != nil {
		t.Fatal(err)
	}
	if _, err = db.CreateTemplateRepository(ctx, TemplateRepository{OrganizationID: otherOrganizationID, Name: "Wrong scope", Slug: "wrong-scope", RepositoryURL: "https://github.com/acme/templates", GitRef: "main", CredentialID: &credentialID}); !errors.Is(err, ErrNotFound) {
		t.Fatalf("cross-organization catalog credential accepted: %v", err)
	}
	claimed, err := db.ClaimDueTemplateRepository(ctx)
	if err != nil || claimed.ID != repository.ID || claimed.LastSyncStatus != "running" {
		t.Fatalf("claimed repository=%#v err=%v", claimed, err)
	}
	if _, err = db.ClaimDueTemplateRepository(ctx); !errors.Is(err, ErrNotFound) {
		t.Fatalf("running repository was claimed twice: %v", err)
	}
	if err = db.FinishTemplateRepositorySync(ctx, claimed, "succeeded", ""); err != nil {
		t.Fatal(err)
	}
	loaded, err = db.GetTemplateRepository(ctx, organizationID, repository.ID)
	if err != nil || loaded.NextSyncAt == nil || !loaded.NextSyncAt.After(time.Now()) || loaded.LastSyncStatus != "succeeded" {
		t.Fatalf("completed repository schedule=%#v err=%v", loaded, err)
	}
	if err = db.SetTemplateRepositoryWebhookSecret(ctx, organizationID, repository.ID, "encrypted-webhook-secret"); err != nil {
		t.Fatal(err)
	}
	webhookRepository, err := db.GetTemplateRepositoryForWebhook(ctx, repository.ID)
	if err != nil || webhookRepository.EncryptedWebhookSecret != "encrypted-webhook-secret" || !webhookRepository.WebhookConfigured {
		t.Fatalf("webhook repository=%#v err=%v", webhookRepository, err)
	}
	if err = db.RequestTemplateRepositorySync(ctx, repository.ID, "delivery-1"); err != nil {
		t.Fatal(err)
	}
	if err = db.RequestTemplateRepositorySync(ctx, repository.ID, "delivery-1"); !errors.Is(err, ErrDuplicateDelivery) {
		t.Fatalf("duplicate webhook delivery accepted: %v", err)
	}
	claimed, err = db.ClaimDueTemplateRepository(ctx)
	if err != nil || claimed.ID != repository.ID || claimed.SyncRequestedAt != nil {
		t.Fatalf("webhook-requested repository=%#v err=%v", claimed, err)
	}
	if err = db.FinishTemplateRepositorySync(ctx, claimed, "succeeded", ""); err != nil {
		t.Fatal(err)
	}
	template, err := db.UpsertRepositoryTemplate(ctx, Template{OrganizationID: &organizationID, RepositoryID: &repository.ID, Key: "community/demo", Version: "1", Name: "Demo", ComposeYAML: "services: {}", Config: json.RawMessage(`{}`), Source: "github", SourcePath: "blueprints/demo", Checksum: "abc"})
	if err != nil {
		t.Fatal(err)
	}
	listed, err := db.ListTemplates(ctx, organizationID)
	if err != nil || len(listed) != 1 || listed[0].RepositoryID == nil || *listed[0].RepositoryID != repository.ID {
		t.Fatalf("templates=%#v err=%v", listed, err)
	}
	replacement := Template{OrganizationID: &organizationID, RepositoryID: &repository.ID, Key: "community/replacement", Version: "2", Name: "Replacement", ComposeYAML: "services: {}", Config: json.RawMessage(`{}`), Source: "github", SourcePath: "blueprints/replacement", Checksum: "def"}
	if err = db.ReplaceRepositoryTemplates(ctx, organizationID, repository.ID, []Template{replacement}); err != nil {
		t.Fatal(err)
	}
	listed, err = db.ListTemplates(ctx, organizationID)
	if err != nil || len(listed) != 1 || listed[0].Key != "community/replacement" {
		t.Fatalf("repository snapshot was not reconciled atomically: templates=%#v err=%v", listed, err)
	}
	badScope := replacement
	badScope.OrganizationID = &otherOrganizationID
	if err = db.ReplaceRepositoryTemplates(ctx, organizationID, repository.ID, []Template{badScope}); err == nil {
		t.Fatal("repository snapshot accepted a cross-tenant template")
	}
	listed, err = db.ListTemplates(ctx, organizationID)
	if err != nil || len(listed) != 1 || listed[0].Key != "community/replacement" {
		t.Fatalf("failed replacement changed catalog: templates=%#v err=%v", listed, err)
	}
	account, err := db.CreateServiceAccount(ctx, organizationID, userID, "auditor", "auditor", []byte("token-hash"), time.Now().Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	run, err := db.CreateAIAuditRun(ctx, organizationID, account.ID, "security", "v1", "test", json.RawMessage(`{"kind":"platform"}`))
	if err != nil {
		t.Fatal(err)
	}
	finding, err := db.AddAIAuditFinding(ctx, organizationID, account.ID, AIAuditFinding{RunID: run.ID, Severity: "high", Category: "backup", Title: "No backup", Description: "No recent successful backup", Evidence: json.RawMessage(`{}`), Fingerprint: "backup:none"})
	if err != nil {
		t.Fatal(err)
	}
	if finding.ID == uuid.Nil {
		t.Fatal("finding id is empty")
	}
	if err = db.FinishAIAuditRun(ctx, organizationID, account.ID, run.ID, "completed", "one finding"); err != nil {
		t.Fatal(err)
	}
	if snapshot, err := db.BuildAIAuditSnapshot(ctx, organizationID); err != nil || snapshot.Organization != organizationID {
		t.Fatalf("snapshot=%#v err=%v", snapshot, err)
	}
	if err = db.DeleteTemplateRepository(ctx, organizationID, repository.ID); err != nil {
		t.Fatal(err)
	}
	listed, err = db.ListTemplates(ctx, organizationID)
	if err != nil || len(listed) != 0 {
		t.Fatalf("templates remained after delete: %#v err=%v", listed, err)
	}
	_ = template
}
