package store

import (
	"context"
	"errors"
	"os"
	"sync"
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

	orgID, ownerID, developerID := uuid.New(), uuid.New(), uuid.New()
	_, err = db.Pool.Exec(ctx, `INSERT INTO organizations(id,name,slug) VALUES($1,'Identity Policy',$2)`, orgID, "identity-policy-"+orgID.String())
	if err == nil {
		_, err = db.Pool.Exec(ctx, `INSERT INTO users(id,email,password_hash) VALUES($1,$2,'!test'),($3,$4,'!test')`, ownerID, ownerID.String()+"@example.test", developerID, developerID.String()+"@example.test")
	}
	if err == nil {
		_, err = db.Pool.Exec(ctx, `INSERT INTO memberships(organization_id,user_id,role) VALUES($1,$2,'owner'),($1,$3,'developer')`, orgID, ownerID, developerID)
	}
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = db.Pool.Exec(context.Background(), `DELETE FROM organizations WHERE id=$1`, orgID)
		_, _ = db.Pool.Exec(context.Background(), `DELETE FROM users WHERE id=$1 OR id=$2`, ownerID, developerID)
	})

	if _, err = db.SetOrganizationAuthSettings(ctx, orgID, true); !errors.Is(err, ErrSSOProviderRequired) {
		t.Fatalf("enabling SSO without a provider error = %v", err)
	}
	if allowed, allowErr := db.LocalLoginAllowed(ctx, developerID); allowErr != nil || !allowed {
		t.Fatalf("local login before enforcement = %v, err = %v", allowed, allowErr)
	}
	samlProvider, err := db.CreateSAMLProvider(ctx, SAMLProvider{OrganizationID: orgID, Name: "workforce", IDPMetadata: "metadata", CertificatePEM: "certificate", EncryptedPrivateKey: "ciphertext", Domains: []string{"example.test"}, EmailAttribute: "mail", NameAttribute: "name", DefaultRole: "developer"})
	if err != nil {
		t.Fatal(err)
	}
	settings, err := db.SetOrganizationAuthSettings(ctx, orgID, true)
	if err != nil || !settings.RequireSSO {
		t.Fatalf("settings = %#v, err = %v", settings, err)
	}
	if err = db.DisableSAMLProvider(ctx, orgID, samlProvider.ID); !errors.Is(err, ErrSSOProviderRequired) {
		t.Fatalf("disabling final SAML provider error = %v", err)
	}
	oidcProvider, err := db.CreateOIDCProvider(ctx, OIDCProvider{OrganizationID: orgID, Name: "fallback", Issuer: "https://identity.example.test", ClientID: "client", EncryptedClientSecret: "ciphertext", Domains: []string{"example.test"}})
	if err != nil {
		t.Fatal(err)
	}
	if err = db.DisableSAMLProvider(ctx, orgID, samlProvider.ID); err != nil {
		t.Fatalf("disabling SAML with OIDC fallback: %v", err)
	}
	if err = db.DisableOIDCProvider(ctx, orgID, oidcProvider.ID); !errors.Is(err, ErrSSOProviderRequired) {
		t.Fatalf("disabling final OIDC provider error = %v", err)
	}
	if err = db.SetSAMLProviderEnabled(ctx, orgID, samlProvider.ID, true); err != nil {
		t.Fatalf("re-enabling SAML provider: %v", err)
	}
	if err = db.DisableOIDCProvider(ctx, orgID, oidcProvider.ID); err != nil {
		t.Fatalf("disabling OIDC with SAML fallback: %v", err)
	}
	if allowed, allowErr := db.LocalLoginAllowed(ctx, ownerID); allowErr != nil || !allowed {
		t.Fatalf("owner break-glass login after enforcement = %v, err = %v", allowed, allowErr)
	}
	if allowed, allowErr := db.LocalLoginAllowed(ctx, developerID); allowErr != nil || allowed {
		t.Fatalf("developer local login after enforcement = %v, err = %v", allowed, allowErr)
	}

	ownerHash, localHash, samlHash := []byte("owner-local-token-hash"), []byte("developer-local-token-hash"), []byte("developer-saml-token-hash")
	ownerSessionID, err := db.CreateSessionWithMetadata(ctx, ownerID, nil, nil, ownerHash, time.Now().Add(time.Hour), "local", "owner-agent", "127.0.0.1")
	if err != nil {
		t.Fatal(err)
	}
	localID, err := db.CreateSessionWithMetadata(ctx, developerID, nil, nil, localHash, time.Now().Add(time.Hour), "local", "local-agent", "127.0.0.2")
	if err != nil {
		t.Fatal(err)
	}
	samlID, err := db.CreateSessionWithMetadata(ctx, developerID, &orgID, &samlProvider.ID, samlHash, time.Now().Add(time.Hour), "saml", "saml-agent", "127.0.0.3")
	if err != nil {
		t.Fatal(err)
	}
	owner, err := db.Authenticate(ctx, ownerHash, &orgID)
	if err != nil || owner.SessionID != ownerSessionID || owner.Role != "owner" {
		t.Fatalf("owner break-glass principal = %#v, err = %v", owner, err)
	}
	if _, err = db.Authenticate(ctx, localHash, &orgID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("developer local session under mandatory SSO error = %v, want not found", err)
	}
	principal, err := db.Authenticate(ctx, samlHash, &orgID)
	if err != nil || principal.SessionID != samlID {
		t.Fatalf("SAML principal = %#v, err = %v", principal, err)
	}
	otherOrgID := uuid.New()
	if _, err = db.Pool.Exec(ctx, `INSERT INTO organizations(id,name,slug) VALUES($1,'Other identity policy',$2)`, otherOrgID, "other-identity-policy-"+otherOrgID.String()); err == nil {
		_, err = db.Pool.Exec(ctx, `INSERT INTO memberships(organization_id,user_id,role) VALUES($1,$2,'admin')`, otherOrgID, developerID)
	}
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _ = db.Pool.Exec(context.Background(), `DELETE FROM organizations WHERE id=$1`, otherOrgID) })
	if _, err = db.Authenticate(ctx, samlHash, &otherOrgID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("federated session crossed organization boundary: %v", err)
	}
	sessions, err := db.ListSessions(ctx, developerID, samlID, &orgID)
	if err != nil || len(sessions) != 1 || sessions[0].OrganizationID == nil || *sessions[0].OrganizationID != orgID {
		t.Fatalf("sessions = %#v, err = %v", sessions, err)
	}
	if count, revokeErr := db.RevokeOtherSessions(ctx, developerID, samlID, &orgID); revokeErr != nil || count != 0 {
		t.Fatalf("revoked other sessions = %d, err = %v", count, revokeErr)
	}
	if err = db.RevokeSession(ctx, developerID, localID, &orgID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("federated session revoked an unscoped local session: %v", err)
	}
	if err = db.RevokeSession(ctx, developerID, samlID, &orgID); err != nil {
		t.Fatal(err)
	}
}

func TestMandatorySSOConcurrentProviderDisableKeepsOneProvider(t *testing.T) {
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
	organizationID := uuid.New()
	if _, err = db.Pool.Exec(ctx, `INSERT INTO organizations(id,name,slug) VALUES($1,'Concurrent SSO policy',$2)`, organizationID, "concurrent-sso-"+organizationID.String()); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = db.Pool.Exec(context.Background(), `DELETE FROM organizations WHERE id=$1`, organizationID)
	})
	oidc, err := db.CreateOIDCProvider(ctx, OIDCProvider{OrganizationID: organizationID, Name: "OIDC", Issuer: "https://oidc.example.test", ClientID: "client", EncryptedClientSecret: "ciphertext", Domains: []string{"example.test"}})
	if err != nil {
		t.Fatal(err)
	}
	saml, err := db.CreateSAMLProvider(ctx, SAMLProvider{OrganizationID: organizationID, Name: "SAML", IDPMetadata: "metadata", CertificatePEM: "certificate", EncryptedPrivateKey: "ciphertext", Domains: []string{"example.test"}, EmailAttribute: "mail", NameAttribute: "name", DefaultRole: "developer"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = db.SetOrganizationAuthSettings(ctx, organizationID, true); err != nil {
		t.Fatal(err)
	}
	start := make(chan struct{})
	results := make(chan error, 2)
	var workers sync.WaitGroup
	workers.Add(2)
	go func() {
		defer workers.Done()
		<-start
		results <- db.DisableOIDCProvider(ctx, organizationID, oidc.ID)
	}()
	go func() {
		defer workers.Done()
		<-start
		results <- db.DisableSAMLProvider(ctx, organizationID, saml.ID)
	}()
	close(start)
	workers.Wait()
	close(results)
	succeeded, rejected := 0, 0
	for result := range results {
		if result == nil {
			succeeded++
		} else if errors.Is(result, ErrSSOProviderRequired) {
			rejected++
		} else {
			t.Fatalf("unexpected disable error: %v", result)
		}
	}
	var enabledProviders int
	if err = db.Pool.QueryRow(ctx, `SELECT (SELECT count(*) FROM oidc_providers WHERE organization_id=$1 AND enabled) + (SELECT count(*) FROM saml_providers WHERE organization_id=$1 AND enabled)`, organizationID).Scan(&enabledProviders); err != nil {
		t.Fatal(err)
	}
	if succeeded != 1 || rejected != 1 || enabledProviders != 1 {
		t.Fatalf("disable results succeeded=%d rejected=%d enabled=%d", succeeded, rejected, enabledProviders)
	}
}
