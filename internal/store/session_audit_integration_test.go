package store

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"
)

func TestCreateSessionWithAuditScopesEvidenceAndRollsBackWithoutMembership(t *testing.T) {
	pool, ctx := migrationTestPool(t)
	if err := Migrate(ctx, pool); err != nil {
		t.Fatal(err)
	}
	db := &Store{Pool: pool}
	firstOrganization, secondOrganization := uuid.New(), uuid.New()
	userID, orphanID := uuid.New(), uuid.New()
	for _, statement := range []struct {
		query string
		args  []any
	}{
		{`INSERT INTO organizations(id,name,slug) VALUES($1,'First',$2),($3,'Second',$4)`, []any{firstOrganization, "session-audit-first-" + firstOrganization.String(), secondOrganization, "session-audit-second-" + secondOrganization.String()}},
		{`INSERT INTO users(id,email,password_hash) VALUES($1,$2,'expected-hash'),($3,$4,'expected-hash')`, []any{userID, userID.String() + "@example.test", orphanID, orphanID.String() + "@example.test"}},
		{`INSERT INTO memberships(organization_id,user_id,role) VALUES($1,$3,'owner'),($2,$3,'viewer')`, []any{firstOrganization, secondOrganization, userID}},
	} {
		if _, err := pool.Exec(ctx, statement.query, statement.args...); err != nil {
			t.Fatal(err)
		}
	}

	localID, err := db.CreateSessionWithAudit(ctx, userID, nil, nil, 0, []byte("local-token-hash"), time.Now().Add(time.Hour), "local", "expected-hash", "browser", "127.0.0.1", "127.0.0.1:1234", nil)
	if err != nil {
		t.Fatal(err)
	}
	var localEvents int
	if localID == uuid.Nil {
		t.Fatal("local session ID is empty")
	}
	if err = pool.QueryRow(ctx, `SELECT count(*) FROM audit_events WHERE action='auth.local.login' AND resource_type='user' AND resource_id=$1 AND actor_user_id=$2`, userID.String(), userID).Scan(&localEvents); err != nil || localEvents != 2 {
		t.Fatalf("local audit events=%d err=%v", localEvents, err)
	}
	if _, err = db.CreateSessionWithAudit(ctx, userID, nil, nil, 0, []byte("stale-password-token"), time.Now().Add(time.Hour), "local", "stale-hash", "", "", "", nil); !errors.Is(err, ErrAuthenticationStateChanged) {
		t.Fatalf("stale password session error=%v, want ErrAuthenticationStateChanged", err)
	}
	var staleSessions int
	if err = pool.QueryRow(ctx, `SELECT count(*) FROM sessions WHERE token_hash=$1`, []byte("stale-password-token")).Scan(&staleSessions); err != nil || staleSessions != 0 {
		t.Fatalf("stale password sessions=%d err=%v", staleSessions, err)
	}
	provider, err := db.CreateOIDCProvider(ctx, OIDCProvider{OrganizationID: firstOrganization, Name: "Session audit", Issuer: "https://identity.example.test", ClientID: "client", EncryptedClientSecret: "ciphertext", Domains: []string{"example.test"}})
	if err != nil {
		t.Fatal(err)
	}
	federatedID, err := db.CreateSessionWithAudit(ctx, userID, &firstOrganization, &provider.ID, provider.Revision, []byte("oidc-token-hash"), time.Now().Add(time.Hour), "oidc", "", "browser", "127.0.0.1", "127.0.0.1:1234", map[string]string{"providerId": provider.ID.String()})
	if err != nil {
		t.Fatal(err)
	}
	var federatedEvents int
	if federatedID == uuid.Nil {
		t.Fatal("federated session ID is empty")
	}
	sessions, err := db.ListSessions(ctx, userID, federatedID, &firstOrganization)
	if err != nil || len(sessions) != 1 || sessions[0].ProviderID == nil || *sessions[0].ProviderID != provider.ID {
		t.Fatalf("federated session provider binding=%#v err=%v", sessions, err)
	}
	if err = pool.QueryRow(ctx, `SELECT count(*) FROM audit_events WHERE action='auth.oidc.login' AND resource_type='user' AND resource_id=$1 AND actor_user_id=$2 AND organization_id=$3`, userID.String(), userID, firstOrganization).Scan(&federatedEvents); err != nil || federatedEvents != 1 {
		t.Fatalf("federated audit events=%d err=%v", federatedEvents, err)
	}
	if _, err = db.CreateSessionWithAudit(ctx, userID, &firstOrganization, nil, 0, []byte("unbound-provider-token"), time.Now().Add(time.Hour), "oidc", "", "", "", "", nil); err == nil {
		t.Fatal("provider-unbound federated session was accepted")
	}
	if _, err = db.CreateSessionWithAudit(ctx, userID, &secondOrganization, &provider.ID, provider.Revision, []byte("cross-tenant-provider-token"), time.Now().Add(time.Hour), "oidc", "", "", "", "", nil); !errors.Is(err, ErrNotFound) {
		t.Fatalf("cross-tenant provider session error=%v, want not found", err)
	}
	if err = db.SetOIDCProviderEnabled(ctx, firstOrganization, provider.ID, false); err != nil {
		t.Fatal(err)
	}
	if _, err = db.CreateSessionWithAudit(ctx, userID, &firstOrganization, &provider.ID, provider.Revision, []byte("disabled-provider-token"), time.Now().Add(time.Hour), "oidc", "", "", "", "", nil); !errors.Is(err, ErrNotFound) {
		t.Fatalf("disabled provider session error=%v, want not found", err)
	}
	if _, err = db.CreateSessionWithAudit(ctx, orphanID, nil, nil, 0, []byte("orphan-token-hash"), time.Now().Add(time.Hour), "local", "expected-hash", "", "", "", nil); !errors.Is(err, ErrNotFound) {
		t.Fatalf("orphan session error=%v, want ErrNotFound", err)
	}
	var orphanSessions int
	if err = pool.QueryRow(ctx, `SELECT count(*) FROM sessions WHERE user_id=$1`, orphanID).Scan(&orphanSessions); err != nil || orphanSessions != 0 {
		t.Fatalf("orphan sessions=%d err=%v", orphanSessions, err)
	}
	_, _ = pool.Exec(context.Background(), `DELETE FROM organizations WHERE id IN ($1,$2)`, firstOrganization, secondOrganization)
	_, _ = pool.Exec(context.Background(), `DELETE FROM users WHERE id IN ($1,$2)`, userID, orphanID)
}
