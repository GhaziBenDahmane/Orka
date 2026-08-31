package store

import (
	"context"
	"errors"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

func TestSSOPolicyTransitionsCommitWithAudit(t *testing.T) {
	pool, ctx := migrationTestPool(t)
	if err := Migrate(ctx, pool); err != nil {
		t.Fatal(err)
	}
	db := &Store{Pool: pool}
	organizationID, userID := uuid.New(), uuid.New()
	if _, err := pool.Exec(ctx, `INSERT INTO organizations(id,name,slug) VALUES($1,'SSO audit',$2)`, organizationID, "sso-audit-"+organizationID.String()); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO users(id,email,password_hash) VALUES($1,$2,'!test')`, userID, userID.String()+"@example.test"); err != nil {
		t.Fatal(err)
	}
	provider, err := db.CreateOIDCProvider(ctx, OIDCProvider{OrganizationID: organizationID, Name: "Workforce", Issuer: "https://identity.example.test", ClientID: "client", EncryptedClientSecret: "ciphertext", Domains: []string{"example.test"}})
	if err != nil {
		t.Fatal(err)
	}
	invalidPrincipal := Principal{OrganizationID: organizationID, UserID: uuid.New()}
	principal := Principal{OrganizationID: organizationID, UserID: userID}

	if _, err = db.SetOrganizationAuthSettingsWithAudit(ctx, invalidPrincipal, true, "127.0.0.1:1234"); err == nil {
		t.Fatal("mandatory SSO was enabled without a valid audit actor")
	}
	settings, err := db.GetOrganizationAuthSettings(ctx, organizationID)
	if err != nil || settings.RequireSSO {
		t.Fatalf("failed audit did not roll back mandatory SSO: settings=%#v err=%v", settings, err)
	}
	if _, err = db.SetOrganizationAuthSettingsWithAudit(ctx, principal, true, "127.0.0.1:1234"); err != nil {
		t.Fatal(err)
	}
	if err = db.SetSSOProviderEnabledWithAudit(ctx, principal, provider.ID, "oidc", false, "127.0.0.1:1234"); !errors.Is(err, ErrSSOProviderRequired) {
		t.Fatalf("last provider disable error=%v, want SSO provider required", err)
	}
	if _, err = db.SetOrganizationAuthSettingsWithAudit(ctx, principal, false, "127.0.0.1:1234"); err != nil {
		t.Fatal(err)
	}

	if err = db.SetSSOProviderEnabledWithAudit(ctx, invalidPrincipal, provider.ID, "oidc", false, "127.0.0.1:1234"); err == nil {
		t.Fatal("OIDC disable succeeded without a valid audit actor")
	}
	assertOIDCProviderEnabled(t, pool, ctx, provider.ID, true)
	if err = db.SetSSOProviderEnabledWithAudit(ctx, principal, provider.ID, "oidc", false, "127.0.0.1:1234"); err != nil {
		t.Fatal(err)
	}
	assertOIDCProviderEnabled(t, pool, ctx, provider.ID, false)
	if err = db.SetSSOProviderEnabledWithAudit(ctx, invalidPrincipal, provider.ID, "oidc", true, "127.0.0.1:1234"); err == nil {
		t.Fatal("OIDC enable succeeded without a valid audit actor")
	}
	assertOIDCProviderEnabled(t, pool, ctx, provider.ID, false)
	if err = db.SetSSOProviderEnabledWithAudit(ctx, principal, provider.ID, "oidc", true, "127.0.0.1:1234"); err != nil {
		t.Fatal(err)
	}
	assertOIDCProviderEnabled(t, pool, ctx, provider.ID, true)

	var auditCount int
	if err = pool.QueryRow(ctx, `SELECT count(*) FROM audit_events WHERE organization_id=$1 AND actor_user_id=$2 AND action IN ('sso.policy.update','sso.oidc.disable','sso.oidc.enable')`, organizationID, userID).Scan(&auditCount); err != nil || auditCount != 4 {
		t.Fatalf("SSO transition audit count=%d err=%v", auditCount, err)
	}
}

func TestOIDCProviderMutationCommitsWithAudit(t *testing.T) {
	pool, ctx := migrationTestPool(t)
	if err := Migrate(ctx, pool); err != nil {
		t.Fatal(err)
	}
	db := &Store{Pool: pool}
	organizationID, userID, providerID := uuid.New(), uuid.New(), uuid.New()
	if _, err := pool.Exec(ctx, `INSERT INTO organizations(id,name,slug) VALUES($1,'OIDC provider audit',$2)`, organizationID, "oidc-provider-audit-"+organizationID.String()); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO users(id,email,password_hash) VALUES($1,$2,'!test')`, userID, userID.String()+"@example.test"); err != nil {
		t.Fatal(err)
	}
	invalidPrincipal := Principal{OrganizationID: organizationID, UserID: uuid.New()}
	principal := Principal{OrganizationID: organizationID, UserID: userID}
	providerInput := OIDCProvider{ID: providerID, Name: "Workforce", Issuer: "https://identity.example.test", ClientID: "client", EncryptedClientSecret: "original-ciphertext", Domains: []string{"example.test"}, Scopes: []string{"openid", "email"}, DefaultRole: "developer"}

	if _, err := db.CreateOIDCProviderWithAudit(ctx, invalidPrincipal, providerInput, "127.0.0.1:1234"); err == nil {
		t.Fatal("OIDC provider creation succeeded without a valid audit actor")
	}
	if _, err := db.GetOIDCProvider(ctx, providerID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("failed audit did not roll back OIDC provider creation: %v", err)
	}
	provider, err := db.CreateOIDCProviderWithAudit(ctx, principal, providerInput, "127.0.0.1:1234")
	if err != nil {
		t.Fatal(err)
	}
	stateHash := []byte("pending-oidc-state")
	if err = db.CreateOIDCState(ctx, stateHash, provider.ID, "verifier", "nonce"); err != nil {
		t.Fatal(err)
	}
	update := provider
	update.Name = "Renamed workforce"
	update.ClientID = "rotated-client"
	update.EncryptedClientSecret = "rotated-ciphertext"
	update.DefaultRole = "viewer"
	if _, err = db.UpdateOIDCProviderWithAudit(ctx, invalidPrincipal, update, true, "127.0.0.1:1234"); err == nil {
		t.Fatal("OIDC provider update succeeded without a valid audit actor")
	}
	stored, err := db.GetOIDCProvider(ctx, provider.ID)
	if err != nil || stored.Name != "Workforce" || stored.ClientID != "client" || stored.EncryptedClientSecret != "original-ciphertext" || stored.DefaultRole != "developer" {
		t.Fatalf("failed audit did not roll back OIDC update: provider=%#v err=%v", stored, err)
	}
	var stateCount int
	if err = pool.QueryRow(ctx, `SELECT count(*) FROM oidc_states WHERE token_hash=$1 AND provider_id=$2`, stateHash, provider.ID).Scan(&stateCount); err != nil || stateCount != 1 {
		t.Fatalf("failed audit did not restore pending OIDC state: count=%d err=%v", stateCount, err)
	}
	stored, err = db.UpdateOIDCProviderWithAudit(ctx, principal, update, true, "127.0.0.1:1234")
	if err != nil || stored.Name != "Renamed workforce" || stored.ClientID != "rotated-client" || stored.DefaultRole != "viewer" {
		t.Fatalf("audited OIDC update=%#v err=%v", stored, err)
	}
	if err = pool.QueryRow(ctx, `SELECT count(*) FROM oidc_states WHERE provider_id=$1`, provider.ID).Scan(&stateCount); err != nil || stateCount != 0 {
		t.Fatalf("successful OIDC update retained login state: count=%d err=%v", stateCount, err)
	}
	var auditCount int
	if err = pool.QueryRow(ctx, `SELECT count(*) FROM audit_events WHERE organization_id=$1 AND actor_user_id=$2 AND resource_id=$3 AND action IN ('sso.oidc.create','sso.oidc.update')`, organizationID, userID, provider.ID.String()).Scan(&auditCount); err != nil || auditCount != 2 {
		t.Fatalf("OIDC provider mutation audit count=%d err=%v", auditCount, err)
	}
}

func assertOIDCProviderEnabled(t *testing.T, pool interface {
	QueryRow(context.Context, string, ...any) pgx.Row
}, ctx context.Context, providerID uuid.UUID, want bool) {
	t.Helper()
	var enabled bool
	if err := pool.QueryRow(ctx, `SELECT enabled FROM oidc_providers WHERE id=$1`, providerID).Scan(&enabled); err != nil || enabled != want {
		t.Fatalf("OIDC enabled=%v want=%v err=%v", enabled, want, err)
	}
}
