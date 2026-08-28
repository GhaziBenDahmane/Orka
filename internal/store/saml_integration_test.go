package store

import (
	"context"
	"errors"
	"os"
	"testing"
	"time"

	"github.com/google/uuid"
)

func TestSAMLProviderStateReplayAndJITIsolation(t *testing.T) {
	databaseURL := os.Getenv("DOCKYARD_TEST_DATABASE_URL")
	if databaseURL == "" {
		t.Skip("DOCKYARD_TEST_DATABASE_URL is not set")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	db, err := Open(ctx, databaseURL)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(db.Pool.Close)

	orgID, otherOrgID := uuid.New(), uuid.New()
	_, err = db.Pool.Exec(ctx, `INSERT INTO organizations(id,name,slug) VALUES($1,'SAML Test',$2),($3,'Other SAML Test',$4)`, orgID, "saml-"+orgID.String(), otherOrgID, "other-saml-"+otherOrgID.String())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = db.Pool.Exec(context.Background(), `DELETE FROM organizations WHERE id=ANY($1)`, []uuid.UUID{orgID, otherOrgID})
		_, _ = db.Pool.Exec(context.Background(), `DELETE FROM users WHERE email=$1`, "saml-user-"+orgID.String()+"@example.test")
	})

	provider, err := db.CreateSAMLProvider(ctx, SAMLProvider{OrganizationID: orgID, Name: "workforce", IDPMetadata: "<metadata/>", CertificatePEM: "certificate", EncryptedPrivateKey: "ciphertext", Domains: []string{"example.test"}, EmailAttribute: "mail", NameAttribute: "displayName", DefaultRole: "developer", AllowIDPInitiated: true})
	if err != nil {
		t.Fatal(err)
	}
	otherProvider, err := db.CreateSAMLProvider(ctx, SAMLProvider{OrganizationID: otherOrgID, Name: "other", IDPMetadata: "<metadata/>", CertificatePEM: "certificate", EncryptedPrivateKey: "ciphertext", Domains: []string{"other.test"}, EmailAttribute: "mail", NameAttribute: "displayName", DefaultRole: "viewer"})
	if err != nil {
		t.Fatal(err)
	}

	items, err := db.ListSAMLProviders(ctx, orgID)
	if err != nil || len(items) != 1 || items[0].ID != provider.ID || !items[0].AllowIDPInitiated {
		t.Fatalf("organization providers = %#v, err = %v", items, err)
	}
	discovered, err := db.DiscoverSAML(ctx, "EXAMPLE.TEST")
	found := false
	for _, item := range discovered {
		found = found || item.ID == provider.ID
	}
	if err != nil || !found {
		t.Fatalf("discovered providers = %#v, err = %v", discovered, err)
	}
	if err = db.DisableSAMLProvider(ctx, orgID, otherProvider.ID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("cross-tenant disable error = %v, want not found", err)
	}

	state := []byte("opaque-state-hash")
	if err = db.CreateSAMLState(ctx, state, provider.ID, "request-1"); err != nil {
		t.Fatal(err)
	}
	if _, err = db.ConsumeSAMLState(ctx, state, otherProvider.ID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("cross-provider state consume error = %v, want not found", err)
	}
	requestID, err := db.ConsumeSAMLState(ctx, state, provider.ID)
	if err != nil || requestID != "request-1" {
		t.Fatalf("consumed request = %q, err = %v", requestID, err)
	}
	if _, err = db.ConsumeSAMLState(ctx, state, provider.ID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("replayed state error = %v, want not found", err)
	}

	if err = db.RecordSAMLAssertion(ctx, provider.ID, "assertion-1", time.Now().Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	if err = db.RecordSAMLAssertion(ctx, provider.ID, "assertion-1", time.Now().Add(time.Hour)); err == nil {
		t.Fatal("replayed assertion was accepted")
	}

	email := "saml-user-" + orgID.String() + "@example.test"
	userID, err := db.JITSAMLUser(ctx, provider, "subject-1", email, "SAML User")
	if err != nil {
		t.Fatal(err)
	}
	repeatedID, err := db.JITSAMLUser(ctx, provider, "subject-1", email, "Changed Name")
	if err != nil || repeatedID != userID {
		t.Fatalf("repeated JIT user = %s, err = %v", repeatedID, err)
	}
	var role string
	if err = db.Pool.QueryRow(ctx, `SELECT role FROM memberships WHERE organization_id=$1 AND user_id=$2`, orgID, userID).Scan(&role); err != nil || role != "developer" {
		t.Fatalf("JIT membership role = %q, err = %v", role, err)
	}
}
