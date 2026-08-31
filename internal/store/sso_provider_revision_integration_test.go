package store

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

func TestSSOProviderRevisionsFenceStaleProvisioningAndSessions(t *testing.T) {
	pool, ctx := migrationTestPool(t)
	if err := Migrate(ctx, pool); err != nil {
		t.Fatal(err)
	}
	db := &Store{Pool: pool}
	organizationID, userID := uuid.New(), uuid.New()
	if _, err := pool.Exec(ctx, `INSERT INTO organizations(id,name,slug) VALUES($1,'Provider revision',$2)`, organizationID, "provider-revision-"+organizationID.String()); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO users(id,email,password_hash) VALUES($1,$2,'!test')`, userID, userID.String()+"@example.test"); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO memberships(organization_id,user_id,role) VALUES($1,$2,'owner')`, organizationID, userID); err != nil {
		t.Fatal(err)
	}

	oidc, err := db.CreateOIDCProvider(ctx, OIDCProvider{
		OrganizationID:        organizationID,
		Name:                  "OIDC",
		Issuer:                "https://oidc.example.test",
		ClientID:              "client",
		EncryptedClientSecret: "encrypted",
		Domains:               []string{"example.test"},
	})
	if err != nil || oidc.Revision != 1 {
		t.Fatalf("created OIDC provider revision=%d err=%v", oidc.Revision, err)
	}
	if err = db.CreateOIDCState(ctx, []byte("revision-oidc-state"), oidc.ID, oidc.Revision, "verifier", "nonce"); err != nil {
		t.Fatal(err)
	}
	_, consumedOIDCRevision, _, _, err := db.ConsumeOIDCState(ctx, []byte("revision-oidc-state"))
	if err != nil || consumedOIDCRevision != oidc.Revision {
		t.Fatalf("consumed OIDC revision=%d err=%v", consumedOIDCRevision, err)
	}
	updatedOIDC, err := db.UpdateOIDCProvider(ctx, organizationID, OIDCProvider{
		ID: oidc.ID, Name: "OIDC updated", Issuer: oidc.Issuer, ClientID: oidc.ClientID,
		Domains: oidc.Domains, Scopes: oidc.Scopes, DefaultRole: "viewer",
	})
	if err != nil || updatedOIDC.Revision != 2 {
		t.Fatalf("updated OIDC provider revision=%d err=%v", updatedOIDC.Revision, err)
	}
	staleOIDCEmail := "stale-oidc-" + organizationID.String() + "@example.test"
	if _, err = db.JITOIDCUser(ctx, oidc, "stale-subject", staleOIDCEmail, "Stale OIDC"); !errors.Is(err, ErrAuthenticationStateChanged) {
		t.Fatalf("stale OIDC provisioning error=%v, want ErrAuthenticationStateChanged", err)
	}
	assertNoUserWithEmail(t, pool, ctx, staleOIDCEmail)
	if _, err = db.CreateSessionWithAudit(ctx, userID, &organizationID, &oidc.ID, consumedOIDCRevision, []byte("stale-oidc-session"), time.Now().Add(time.Hour), "oidc", "", "", "", "", nil); !errors.Is(err, ErrAuthenticationStateChanged) {
		t.Fatalf("stale OIDC session error=%v, want ErrAuthenticationStateChanged", err)
	}
	assertProviderRevisionTransition(t, ctx, pool, "oidc_providers", oidc.ID, func(enabled bool) error {
		return db.SetOIDCProviderEnabled(ctx, organizationID, oidc.ID, enabled)
	}, 2)

	samlProvider, err := db.CreateSAMLProvider(ctx, SAMLProvider{
		OrganizationID:      organizationID,
		Name:                "SAML",
		IDPMetadata:         "<metadata/>",
		CertificatePEM:      "certificate",
		EncryptedPrivateKey: "encrypted",
		Domains:             []string{"example.test"},
		EmailAttribute:      "mail",
		NameAttribute:       "displayName",
		DefaultRole:         "developer",
	})
	if err != nil || samlProvider.Revision != 1 {
		t.Fatalf("created SAML provider revision=%d err=%v", samlProvider.Revision, err)
	}
	if err = db.CreateSAMLState(ctx, []byte("revision-saml-state"), samlProvider.ID, samlProvider.Revision, "request-id"); err != nil {
		t.Fatal(err)
	}
	_, consumedSAMLRevision, err := db.ConsumeSAMLState(ctx, []byte("revision-saml-state"), samlProvider.ID)
	if err != nil || consumedSAMLRevision != samlProvider.Revision {
		t.Fatalf("consumed SAML revision=%d err=%v", consumedSAMLRevision, err)
	}
	updatedSAML, err := db.UpdateSAMLProvider(ctx, organizationID, SAMLProvider{
		ID: samlProvider.ID, Name: "SAML updated", IDPMetadata: samlProvider.IDPMetadata,
		Domains: samlProvider.Domains, EmailAttribute: samlProvider.EmailAttribute,
		NameAttribute: samlProvider.NameAttribute, DefaultRole: "viewer",
	})
	if err != nil || updatedSAML.Revision != 2 {
		t.Fatalf("updated SAML provider revision=%d err=%v", updatedSAML.Revision, err)
	}
	staleSAMLEmail := "stale-saml-" + organizationID.String() + "@example.test"
	if _, err = db.JITSAMLUser(ctx, samlProvider, "stale-subject", staleSAMLEmail, "Stale SAML"); !errors.Is(err, ErrAuthenticationStateChanged) {
		t.Fatalf("stale SAML provisioning error=%v, want ErrAuthenticationStateChanged", err)
	}
	assertNoUserWithEmail(t, pool, ctx, staleSAMLEmail)
	if _, err = db.CreateSessionWithAudit(ctx, userID, &organizationID, &samlProvider.ID, consumedSAMLRevision, []byte("stale-saml-session"), time.Now().Add(time.Hour), "saml", "", "", "", "", nil); !errors.Is(err, ErrAuthenticationStateChanged) {
		t.Fatalf("stale SAML session error=%v, want ErrAuthenticationStateChanged", err)
	}
	assertProviderRevisionTransition(t, ctx, pool, "saml_providers", samlProvider.ID, func(enabled bool) error {
		return db.SetSAMLProviderEnabled(ctx, organizationID, samlProvider.ID, enabled)
	}, 2)
}

func TestFederatedJITProvisioningSerializesSubjectsAndRejectsDisabledUsers(t *testing.T) {
	pool, ctx := migrationTestPool(t)
	if err := Migrate(ctx, pool); err != nil {
		t.Fatal(err)
	}
	db := &Store{Pool: pool}
	organizationID := uuid.New()
	if _, err := pool.Exec(ctx, `INSERT INTO organizations(id,name,slug) VALUES($1,'JIT fencing',$2)`, organizationID, "jit-fencing-"+organizationID.String()); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `DELETE FROM organizations WHERE id=$1`, organizationID)
		_, _ = pool.Exec(context.Background(), `DELETE FROM users WHERE email LIKE $1`, "%-"+organizationID.String()+"@example.test")
	})
	oidc, err := db.CreateOIDCProvider(ctx, OIDCProvider{OrganizationID: organizationID, Name: "OIDC", Issuer: "https://oidc.example.test", ClientID: "client", EncryptedClientSecret: "encrypted", Domains: []string{"example.test"}})
	if err != nil {
		t.Fatal(err)
	}
	saml, err := db.CreateSAMLProvider(ctx, SAMLProvider{OrganizationID: organizationID, Name: "SAML", IDPMetadata: "<metadata/>", CertificatePEM: "certificate", EncryptedPrivateKey: "encrypted", Domains: []string{"example.test"}, EmailAttribute: "mail", NameAttribute: "displayName", DefaultRole: "viewer"})
	if err != nil {
		t.Fatal(err)
	}

	for name, test := range map[string]struct {
		lockKey string
		login   func(context.Context, string, string) (uuid.UUID, error)
	}{
		"oidc": {lockKey: "oidc:" + oidc.ID.String() + ":shared-subject", login: func(callCtx context.Context, subject, email string) (uuid.UUID, error) {
			return db.JITOIDCUser(callCtx, oidc, subject, email, "Federated User")
		}},
		"saml": {lockKey: "saml:" + saml.ID.String() + ":shared-subject", login: func(callCtx context.Context, subject, email string) (uuid.UUID, error) {
			return db.JITSAMLUser(callCtx, saml, subject, email, "Federated User")
		}},
	} {
		t.Run(name, func(t *testing.T) {
			lock, lockErr := pool.Begin(ctx)
			if lockErr != nil {
				t.Fatal(lockErr)
			}
			defer lock.Rollback(ctx)
			if _, lockErr = lock.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1,0))`, test.lockKey); lockErr != nil {
				t.Fatal(lockErr)
			}
			blockedCtx, cancel := context.WithTimeout(ctx, 100*time.Millisecond)
			defer cancel()
			if _, loginErr := test.login(blockedCtx, "shared-subject", name+"-first@example.test"); !errors.Is(loginErr, context.DeadlineExceeded) {
				t.Fatalf("JIT provisioning bypassed subject fence: %v", loginErr)
			}
			if lockErr = lock.Rollback(ctx); lockErr != nil {
				t.Fatal(lockErr)
			}

			disabledID := uuid.New()
			disabledEmail := name + "-disabled-" + organizationID.String() + "@example.test"
			if _, err = pool.Exec(ctx, `INSERT INTO users(id,email,password_hash,disabled_at) VALUES($1,$2,'!disabled',now())`, disabledID, disabledEmail); err != nil {
				t.Fatal(err)
			}
			if _, loginErr := test.login(ctx, name+"-disabled-subject", disabledEmail); !errors.Is(loginErr, ErrNotFound) {
				t.Fatalf("disabled user provisioning error=%v, want ErrNotFound", loginErr)
			}
			var memberships int
			if err = pool.QueryRow(ctx, `SELECT count(*) FROM memberships WHERE organization_id=$1 AND user_id=$2`, organizationID, disabledID).Scan(&memberships); err != nil || memberships != 0 {
				t.Fatalf("disabled user gained memberships=%d err=%v", memberships, err)
			}
		})
	}
}

func assertNoUserWithEmail(t *testing.T, db interface {
	QueryRow(context.Context, string, ...any) pgx.Row
}, ctx context.Context, email string) {
	t.Helper()
	var users int
	if err := db.QueryRow(ctx, `SELECT count(*) FROM users WHERE email=$1`, email).Scan(&users); err != nil || users != 0 {
		t.Fatalf("stale provisioning users=%d err=%v", users, err)
	}
}

func assertProviderRevisionTransition(t *testing.T, ctx context.Context, pool interface {
	QueryRow(context.Context, string, ...any) pgx.Row
}, table string, providerID uuid.UUID, setEnabled func(bool) error, initialRevision int64) {
	t.Helper()
	revision := func() int64 {
		var value int64
		if err := pool.QueryRow(ctx, `SELECT revision FROM `+table+` WHERE id=$1`, providerID).Scan(&value); err != nil {
			t.Fatal(err)
		}
		return value
	}
	if err := setEnabled(true); err != nil || revision() != initialRevision {
		t.Fatalf("idempotent enable changed provider revision: revision=%d err=%v", revision(), err)
	}
	if err := setEnabled(false); err != nil || revision() != initialRevision+1 {
		t.Fatalf("disable revision=%d err=%v", revision(), err)
	}
	if err := setEnabled(false); err != nil || revision() != initialRevision+1 {
		t.Fatalf("idempotent disable changed provider revision: revision=%d err=%v", revision(), err)
	}
	if err := setEnabled(true); err != nil || revision() != initialRevision+2 {
		t.Fatalf("re-enable revision=%d err=%v", revision(), err)
	}
}
