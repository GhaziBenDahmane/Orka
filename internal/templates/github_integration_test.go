package templates

import (
	"bytes"
	"context"
	"os"
	"testing"
	"time"

	"github.com/GhaziBenDahmane/Orka/internal/cryptox"
	"github.com/GhaziBenDahmane/Orka/internal/store"
	"github.com/google/uuid"
)

func TestRepositoryTokenUsesResourceBoundOrganizationCredential(t *testing.T) {
	databaseURL := os.Getenv("DOCKYARD_TEST_DATABASE_URL")
	if databaseURL == "" {
		t.Skip("DOCKYARD_TEST_DATABASE_URL is not set")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	db, err := store.Open(ctx, databaseURL)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(db.Pool.Close)
	box, err := cryptox.New(bytes.Repeat([]byte{27}, 32))
	if err != nil {
		t.Fatal(err)
	}
	organizationID, credentialID := uuid.New(), uuid.New()
	if _, err = db.Pool.Exec(ctx, `INSERT INTO organizations(id,name,slug) VALUES($1,'Private catalog',$2)`, organizationID, "private-catalog-"+organizationID.String()); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = db.Pool.Exec(context.Background(), `DELETE FROM organizations WHERE id=$1`, organizationID)
	})
	encrypted, err := box.Encrypt([]byte("github-secret-token"), cryptox.ResourceContext("source-credential", credentialID.String()))
	if err != nil {
		t.Fatal(err)
	}
	if _, err = db.CreateSourceCredential(ctx, store.SourceCredential{ID: credentialID, OrganizationID: organizationID, Kind: "git", Name: "GitHub catalog", Server: "github.com", Username: "token", EncryptedSecret: encrypted}); err != nil {
		t.Fatal(err)
	}
	token, err := repositoryToken(ctx, db, box, store.TemplateRepository{OrganizationID: organizationID, CredentialID: &credentialID})
	if err != nil || token != "github-secret-token" {
		t.Fatalf("token=%q err=%v", token, err)
	}
	wrongOrganization := uuid.New()
	if _, err = repositoryToken(ctx, db, box, store.TemplateRepository{OrganizationID: wrongOrganization, CredentialID: &credentialID}); err == nil {
		t.Fatal("cross-organization credential was accepted")
	}
}
