package store

import (
	"context"
	"errors"
	"os"
	"testing"
	"time"

	"github.com/google/uuid"
)

func TestMandatorySSOAndSessionAdministration(t *testing.T) {
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

	orgID, userID := uuid.New(), uuid.New()
	_, err = db.Pool.Exec(ctx, `INSERT INTO organizations(id,name,slug) VALUES($1,'Identity Policy',$2)`, orgID, "identity-policy-"+orgID.String())
	if err == nil {
		_, err = db.Pool.Exec(ctx, `INSERT INTO users(id,email,password_hash) VALUES($1,$2,'!test')`, userID, userID.String()+"@example.test")
	}
	if err == nil {
		_, err = db.Pool.Exec(ctx, `INSERT INTO memberships(organization_id,user_id,role) VALUES($1,$2,'owner')`, orgID, userID)
	}
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = db.Pool.Exec(context.Background(), `DELETE FROM organizations WHERE id=$1`, orgID)
		_, _ = db.Pool.Exec(context.Background(), `DELETE FROM users WHERE id=$1`, userID)
	})

	if _, err = db.SetOrganizationAuthSettings(ctx, orgID, true); !errors.Is(err, ErrSSOProviderRequired) {
		t.Fatalf("enabling SSO without a provider error = %v", err)
	}
	if allowed, allowErr := db.LocalLoginAllowed(ctx, userID); allowErr != nil || !allowed {
		t.Fatalf("local login before enforcement = %v, err = %v", allowed, allowErr)
	}
	_, err = db.CreateSAMLProvider(ctx, SAMLProvider{OrganizationID: orgID, Name: "workforce", IDPMetadata: "metadata", CertificatePEM: "certificate", EncryptedPrivateKey: "ciphertext", Domains: []string{"example.test"}, EmailAttribute: "mail", NameAttribute: "name", DefaultRole: "developer"})
	if err != nil {
		t.Fatal(err)
	}
	settings, err := db.SetOrganizationAuthSettings(ctx, orgID, true)
	if err != nil || !settings.RequireSSO {
		t.Fatalf("settings = %#v, err = %v", settings, err)
	}
	if allowed, allowErr := db.LocalLoginAllowed(ctx, userID); allowErr != nil || allowed {
		t.Fatalf("local login after enforcement = %v, err = %v", allowed, allowErr)
	}

	localHash, samlHash := []byte("local-token-hash"), []byte("saml-token-hash")
	localID, err := db.CreateSessionWithMetadata(ctx, userID, localHash, time.Now().Add(time.Hour), "local", "local-agent", "127.0.0.1")
	if err != nil {
		t.Fatal(err)
	}
	samlID, err := db.CreateSessionWithMetadata(ctx, userID, samlHash, time.Now().Add(time.Hour), "saml", "saml-agent", "127.0.0.2")
	if err != nil {
		t.Fatal(err)
	}
	if _, err = db.Authenticate(ctx, localHash, &orgID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("local session under mandatory SSO error = %v, want not found", err)
	}
	principal, err := db.Authenticate(ctx, samlHash, &orgID)
	if err != nil || principal.SessionID != samlID {
		t.Fatalf("SAML principal = %#v, err = %v", principal, err)
	}
	sessions, err := db.ListSessions(ctx, userID, samlID)
	if err != nil || len(sessions) != 2 {
		t.Fatalf("sessions = %#v, err = %v", sessions, err)
	}
	if count, revokeErr := db.RevokeOtherSessions(ctx, userID, samlID); revokeErr != nil || count != 1 {
		t.Fatalf("revoked other sessions = %d, err = %v", count, revokeErr)
	}
	if err = db.RevokeSession(ctx, userID, localID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("already revoked session error = %v, want not found", err)
	}
	if err = db.RevokeSession(ctx, userID, samlID); err != nil {
		t.Fatal(err)
	}
}
