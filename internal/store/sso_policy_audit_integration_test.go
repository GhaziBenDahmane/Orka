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

func assertOIDCProviderEnabled(t *testing.T, pool interface {
	QueryRow(context.Context, string, ...any) pgx.Row
}, ctx context.Context, providerID uuid.UUID, want bool) {
	t.Helper()
	var enabled bool
	if err := pool.QueryRow(ctx, `SELECT enabled FROM oidc_providers WHERE id=$1`, providerID).Scan(&enabled); err != nil || enabled != want {
		t.Fatalf("OIDC enabled=%v want=%v err=%v", enabled, want, err)
	}
}
