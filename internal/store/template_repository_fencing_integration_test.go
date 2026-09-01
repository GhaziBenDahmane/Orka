package store

import (
	"encoding/json"
	"errors"
	"fmt"
	"testing"

	"github.com/google/uuid"
)

func TestTemplateRepositorySyncTakeoverFencesStaleAttempt(t *testing.T) {
	pool, ctx := migrationTestPool(t)
	if err := Migrate(ctx, pool); err != nil {
		t.Fatal(err)
	}
	db := &Store{Pool: pool}
	organizationID := uuid.New()
	if _, err := pool.Exec(ctx, `INSERT INTO organizations(id,name,slug) VALUES($1,'Catalog fencing',$2)`, organizationID, "catalog-fencing-"+organizationID.String()); err != nil {
		t.Fatal(err)
	}
	repository, err := db.CreateTemplateRepository(ctx, TemplateRepository{OrganizationID: organizationID, Name: "Catalog", Slug: "catalog", RepositoryURL: "https://github.com/acme/catalog", GitRef: "main"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = db.QueueTemplateRepositorySync(ctx, organizationID, repository.ID); err != nil {
		t.Fatal(err)
	}
	staleAttempt, err := db.ClaimDueTemplateRepository(ctx)
	if err != nil || staleAttempt.SyncAttemptID == nil {
		t.Fatalf("first attempt=%#v err=%v", staleAttempt, err)
	}
	if _, err = pool.Exec(ctx, `UPDATE template_repositories SET sync_started_at=now()-interval '6 minutes' WHERE id=$1`, repository.ID); err != nil {
		t.Fatal(err)
	}
	replacementAttempt, err := db.ClaimDueTemplateRepository(ctx)
	if err != nil || replacementAttempt.SyncAttemptID == nil || *replacementAttempt.SyncAttemptID == *staleAttempt.SyncAttemptID {
		t.Fatalf("replacement attempt=%#v stale=%#v err=%v", replacementAttempt, staleAttempt, err)
	}
	item := Template{OrganizationID: &organizationID, RepositoryID: &repository.ID, Key: "catalog/current", Version: "1", Name: "Current", ComposeYAML: "services: {}", Config: json.RawMessage(`{}`), Source: "github", SourcePath: "blueprints/current", Checksum: "current"}
	if err = db.PublishRepositoryTemplatesForSyncWithAudit(ctx, staleAttempt, []Template{item}, "scheduler", map[string]any{"imported": 1}); !errors.Is(err, ErrBusy) {
		t.Fatalf("stale attempt published catalog: %v", err)
	}
	if err = db.PublishRepositoryTemplatesForSyncWithAudit(ctx, replacementAttempt, []Template{item}, "scheduler", map[string]any{"imported": 1}); err != nil {
		t.Fatal(err)
	}
	if err = db.FinishTemplateRepositorySync(ctx, staleAttempt, "failed", "stale"); !errors.Is(err, ErrBusy) {
		t.Fatalf("stale attempt finalized replacement state: %v", err)
	}
	loaded, err := db.GetTemplateRepository(ctx, organizationID, repository.ID)
	if err != nil || loaded.LastSyncStatus != "succeeded" || loaded.SyncStartedAt != nil || loaded.SyncAttemptID != nil {
		t.Fatalf("completed replacement=%#v err=%v", loaded, err)
	}
}

func TestFailedTemplateRepositorySyncQueuesNotificationAtomically(t *testing.T) {
	pool, ctx := migrationTestPool(t)
	if err := Migrate(ctx, pool); err != nil {
		t.Fatal(err)
	}
	db := &Store{Pool: pool}
	organizationID, endpointID := uuid.New(), uuid.New()
	if _, err := pool.Exec(ctx, `INSERT INTO organizations(id,name,slug) VALUES($1,'Catalog failure notification',$2)`, organizationID, "catalog-failure-"+organizationID.String()); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO notification_endpoints(id,organization_id,name,kind,encrypted_url,encrypted_secret,events) VALUES($1,$2,'Catalog on-call','webhook','encrypted-url','encrypted-secret',ARRAY['template.sync.failed'])`, endpointID, organizationID); err != nil {
		t.Fatal(err)
	}
	repository, err := db.CreateTemplateRepository(ctx, TemplateRepository{OrganizationID: organizationID, Name: "Catalog", Slug: "catalog", RepositoryURL: "https://github.com/acme/catalog", GitRef: "main"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = db.QueueTemplateRepositorySync(ctx, organizationID, repository.ID); err != nil {
		t.Fatal(err)
	}
	attempt, err := db.ClaimDueTemplateRepository(ctx)
	if err != nil || attempt.SyncAttemptID == nil {
		t.Fatalf("sync attempt=%#v err=%v", attempt, err)
	}
	if err = db.FinishTemplateRepositorySyncWithAudit(ctx, attempt, "failed", "catalog signature rejected", "scheduler", map[string]any{"failed": 1}); err != nil {
		t.Fatal(err)
	}
	var eventType, resourceType, resourceID string
	var payload []byte
	if err = pool.QueryRow(ctx, `SELECT event_type,resource_type,resource_id,payload FROM notification_deliveries WHERE endpoint_id=$1`, endpointID).Scan(&eventType, &resourceType, &resourceID, &payload); err != nil {
		t.Fatal(err)
	}
	var body map[string]any
	if err = json.Unmarshal(payload, &body); err != nil {
		t.Fatal(err)
	}
	if eventType != "template.sync.failed" || resourceType != "template_repository_sync" || resourceID != attempt.SyncAttemptID.String() || body["templateRepositoryId"] != repository.ID.String() || body["error"] != "catalog signature rejected" {
		t.Fatalf("notification event=%q resource=%q/%q payload=%s", eventType, resourceType, resourceID, payload)
	}
	var jobs int
	if err = pool.QueryRow(ctx, `SELECT count(*) FROM jobs WHERE kind='notify.webhook' AND payload->>'deliveryId' IN (SELECT id::text FROM notification_deliveries WHERE endpoint_id=$1)`, endpointID).Scan(&jobs); err != nil || jobs != 1 {
		t.Fatalf("notification jobs=%d err=%v", jobs, err)
	}
	if err = db.FinishTemplateRepositorySync(ctx, attempt, "failed", "stale retry"); !errors.Is(err, ErrBusy) {
		t.Fatalf("stale sync completion=%v, want busy", err)
	}
	var deliveries int
	if err = pool.QueryRow(ctx, `SELECT count(*) FROM notification_deliveries WHERE endpoint_id=$1`, endpointID).Scan(&deliveries); err != nil || deliveries != 1 {
		t.Fatalf("notification deliveries=%d err=%v", deliveries, err)
	}
}

func TestTemplateRepositorySignerRotationWithdrawsAndFencesCatalog(t *testing.T) {
	pool, ctx := migrationTestPool(t)
	if err := Migrate(ctx, pool); err != nil {
		t.Fatal(err)
	}
	db := &Store{Pool: pool}
	organizationID := uuid.New()
	if _, err := pool.Exec(ctx, `INSERT INTO organizations(id,name,slug) VALUES($1,'Catalog signer rotation',$2)`, organizationID, "catalog-signer-"+organizationID.String()); err != nil {
		t.Fatal(err)
	}
	repository, err := db.CreateTemplateRepository(ctx, TemplateRepository{OrganizationID: organizationID, Name: "Catalog", Slug: "catalog", RepositoryURL: "https://github.com/acme/catalog", GitRef: "main", TrustedPublicKey: "old-key"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = db.QueueTemplateRepositorySync(ctx, organizationID, repository.ID); err != nil {
		t.Fatal(err)
	}
	staleAttempt, err := db.ClaimDueTemplateRepository(ctx)
	if err != nil || staleAttempt.SyncAttemptID == nil {
		t.Fatalf("attempt=%#v err=%v", staleAttempt, err)
	}
	item := Template{OrganizationID: &organizationID, RepositoryID: &repository.ID, Key: "catalog/old", Version: "1", Name: "Old", ComposeYAML: "services: {}", Config: json.RawMessage(`{}`), Source: "github", SourcePath: "blueprints/old", Checksum: "old"}
	if err = db.ReplaceRepositoryTemplatesForSync(ctx, staleAttempt, []Template{item}); err != nil {
		t.Fatal(err)
	}
	if err = db.UpdateTemplateRepositorySettings(ctx, organizationID, repository.ID, "new-key", true, nil, 0); err != nil {
		t.Fatal(err)
	}
	if err = db.PublishRepositoryTemplatesForSyncWithAudit(ctx, staleAttempt, []Template{item}, "scheduler", map[string]any{"imported": 1}); !errors.Is(err, ErrBusy) {
		t.Fatalf("old signer attempt published after rotation: %v", err)
	}
	if err = db.FinishTemplateRepositorySync(ctx, staleAttempt, "succeeded", ""); !errors.Is(err, ErrBusy) {
		t.Fatalf("old signer attempt finalized after rotation: %v", err)
	}
	items, err := db.ListTemplates(ctx, organizationID)
	if err != nil {
		t.Fatal(err)
	}
	if len(items) != 0 {
		t.Fatalf("old signer templates remain available: %#v", items)
	}
	loaded, err := db.GetTemplateRepository(ctx, organizationID, repository.ID)
	if err != nil {
		t.Fatal(err)
	}
	if loaded.TrustedPublicKey != "new-key" || !loaded.RequireSignature || loaded.LastSyncStatus != "never" || loaded.LastSyncedAt != nil || loaded.SyncStartedAt != nil || loaded.SyncAttemptID != nil || loaded.SyncRequestedAt == nil {
		t.Fatalf("rotated repository=%#v", loaded)
	}
	replacement, err := db.ClaimDueTemplateRepository(ctx)
	if err != nil || replacement.SyncAttemptID == nil || replacement.TrustedPublicKey != "new-key" || !replacement.RequireSignature {
		t.Fatalf("replacement attempt=%#v err=%v", replacement, err)
	}
}

func TestTemplateRepositoryCredentialRotationFencesButRetainsCatalog(t *testing.T) {
	pool, ctx := migrationTestPool(t)
	if err := Migrate(ctx, pool); err != nil {
		t.Fatal(err)
	}
	db := &Store{Pool: pool}
	organizationID := uuid.New()
	if _, err := pool.Exec(ctx, `INSERT INTO organizations(id,name,slug) VALUES($1,'Catalog credential rotation',$2)`, organizationID, "catalog-credential-"+organizationID.String()); err != nil {
		t.Fatal(err)
	}
	oldCredentialID, newCredentialID := uuid.New(), uuid.New()
	for index, credentialID := range []uuid.UUID{oldCredentialID, newCredentialID} {
		if _, err := db.CreateSourceCredential(ctx, SourceCredential{ID: credentialID, OrganizationID: organizationID, Kind: "git", Name: fmt.Sprintf("GitHub %d", index), Server: "github.com", Username: "token", EncryptedSecret: "ciphertext"}); err != nil {
			t.Fatal(err)
		}
	}
	repository, err := db.CreateTemplateRepository(ctx, TemplateRepository{OrganizationID: organizationID, Name: "Catalog", Slug: "catalog", RepositoryURL: "https://github.com/acme/catalog", GitRef: "main", CredentialID: &oldCredentialID})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = db.QueueTemplateRepositorySync(ctx, organizationID, repository.ID); err != nil {
		t.Fatal(err)
	}
	staleAttempt, err := db.ClaimDueTemplateRepository(ctx)
	if err != nil {
		t.Fatal(err)
	}
	item := Template{OrganizationID: &organizationID, RepositoryID: &repository.ID, Key: "catalog/current", Version: "1", Name: "Current", ComposeYAML: "services: {}", Config: json.RawMessage(`{}`), Source: "github", SourcePath: "blueprints/current", Checksum: "current"}
	if err = db.ReplaceRepositoryTemplatesForSync(ctx, staleAttempt, []Template{item}); err != nil {
		t.Fatal(err)
	}
	if err = db.UpdateTemplateRepositorySettings(ctx, organizationID, repository.ID, "", false, &newCredentialID, 0); err != nil {
		t.Fatal(err)
	}
	if err = db.PublishRepositoryTemplatesForSyncWithAudit(ctx, staleAttempt, []Template{item}, "scheduler", map[string]any{"imported": 1}); !errors.Is(err, ErrBusy) {
		t.Fatalf("old credential attempt published after rotation: %v", err)
	}
	items, err := db.ListTemplates(ctx, organizationID)
	if err != nil || len(items) != 1 || items[0].Key != item.Key {
		t.Fatalf("verified catalog was not retained: items=%#v err=%v", items, err)
	}
	replacement, err := db.ClaimDueTemplateRepository(ctx)
	if err != nil || replacement.CredentialID == nil || *replacement.CredentialID != newCredentialID || replacement.SyncAttemptID == nil {
		t.Fatalf("replacement attempt=%#v err=%v", replacement, err)
	}
}

func TestTemplateRepositoryCredentialMutationQueuesAuthenticationRefresh(t *testing.T) {
	pool, ctx := migrationTestPool(t)
	if err := Migrate(ctx, pool); err != nil {
		t.Fatal(err)
	}
	db := &Store{Pool: pool}
	organizationID, credentialID := uuid.New(), uuid.New()
	if _, err := pool.Exec(ctx, `INSERT INTO organizations(id,name,slug) VALUES($1,'Catalog credential refresh',$2)`, organizationID, "catalog-credential-refresh-"+organizationID.String()); err != nil {
		t.Fatal(err)
	}
	if _, err := db.CreateSourceCredential(ctx, SourceCredential{ID: credentialID, OrganizationID: organizationID, Kind: "git", Name: "GitHub", Server: "github.com", Username: "token", EncryptedSecret: "old-ciphertext"}); err != nil {
		t.Fatal(err)
	}
	repository, err := db.CreateTemplateRepository(ctx, TemplateRepository{OrganizationID: organizationID, Name: "Manual catalog", Slug: "manual", RepositoryURL: "https://github.com/acme/catalog", GitRef: "main", CredentialID: &credentialID})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = db.RotateSourceCredential(ctx, organizationID, credentialID, "new-ciphertext"); err != nil {
		t.Fatal(err)
	}
	stored, err := db.GetTemplateRepository(ctx, organizationID, repository.ID)
	if err != nil || stored.SyncRequestedAt == nil || stored.CredentialID == nil || *stored.CredentialID != credentialID {
		t.Fatalf("rotation did not queue authenticated refresh: repository=%#v err=%v", stored, err)
	}
	claimed, err := db.ClaimDueTemplateRepository(ctx)
	if err != nil || claimed.ID != repository.ID || claimed.CredentialID == nil || *claimed.CredentialID != credentialID {
		t.Fatalf("rotated credential refresh claim=%#v err=%v", claimed, err)
	}
	if err = db.FinishTemplateRepositorySync(ctx, claimed, "succeeded", ""); err != nil {
		t.Fatal(err)
	}
	if err = db.DeleteSourceCredential(ctx, organizationID, credentialID); err != nil {
		t.Fatal(err)
	}
	stored, err = db.GetTemplateRepository(ctx, organizationID, repository.ID)
	if err != nil || stored.SyncRequestedAt == nil || stored.CredentialID != nil {
		t.Fatalf("deletion did not queue anonymous refresh: repository=%#v err=%v", stored, err)
	}
	claimed, err = db.ClaimDueTemplateRepository(ctx)
	if err != nil || claimed.ID != repository.ID || claimed.CredentialID != nil {
		t.Fatalf("anonymous credential refresh claim=%#v err=%v", claimed, err)
	}
}

func TestTemplateRepositorySettingsRequireExactGitHubCredentialAuthority(t *testing.T) {
	pool, ctx := migrationTestPool(t)
	if err := Migrate(ctx, pool); err != nil {
		t.Fatal(err)
	}
	db := &Store{Pool: pool}
	organizationID := uuid.New()
	if _, err := pool.Exec(ctx, `INSERT INTO organizations(id,name,slug) VALUES($1,'Catalog credential scope',$2)`, organizationID, "catalog-credential-scope-"+organizationID.String()); err != nil {
		t.Fatal(err)
	}
	repository, err := db.CreateTemplateRepository(ctx, TemplateRepository{OrganizationID: organizationID, Name: "Catalog", Slug: "catalog", RepositoryURL: "https://github.com/acme/catalog", GitRef: "main"})
	if err != nil {
		t.Fatal(err)
	}
	for _, server := range []string{"github.com:443", "github.com.attacker.test"} {
		credentialID := uuid.New()
		if _, err = db.CreateSourceCredential(ctx, SourceCredential{ID: credentialID, OrganizationID: organizationID, Kind: "git", Name: server, Server: server, Username: "token", EncryptedSecret: "ciphertext"}); err != nil {
			t.Fatal(err)
		}
		if err = db.UpdateTemplateRepositorySettings(ctx, organizationID, repository.ID, "", false, &credentialID, 0); !errors.Is(err, ErrNotFound) {
			t.Fatalf("credential authority %q was accepted: %v", server, err)
		}
	}
	loaded, err := db.GetTemplateRepository(ctx, organizationID, repository.ID)
	if err != nil {
		t.Fatal(err)
	}
	if loaded.CredentialID != nil {
		t.Fatalf("rejected credential was persisted: %v", *loaded.CredentialID)
	}
}
