package store

import (
	"encoding/json"
	"errors"
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
	if err = db.ReplaceRepositoryTemplatesForSync(ctx, staleAttempt, []Template{item}); !errors.Is(err, ErrBusy) {
		t.Fatalf("stale attempt replaced catalog: %v", err)
	}
	if err = db.ReplaceRepositoryTemplatesForSync(ctx, replacementAttempt, []Template{item}); err != nil {
		t.Fatal(err)
	}
	if err = db.FinishTemplateRepositorySync(ctx, staleAttempt, "failed", "stale"); !errors.Is(err, ErrBusy) {
		t.Fatalf("stale attempt finalized replacement state: %v", err)
	}
	if err = db.FinishTemplateRepositorySync(ctx, replacementAttempt, "succeeded", ""); err != nil {
		t.Fatal(err)
	}
	loaded, err := db.GetTemplateRepository(ctx, organizationID, repository.ID)
	if err != nil || loaded.LastSyncStatus != "succeeded" || loaded.SyncStartedAt != nil || loaded.SyncAttemptID != nil {
		t.Fatalf("completed replacement=%#v err=%v", loaded, err)
	}
}
