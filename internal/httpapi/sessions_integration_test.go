package httpapi

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/GhaziBenDahmane/Orka/internal/auth"
	"github.com/GhaziBenDahmane/Orka/internal/cryptox"
	"github.com/GhaziBenDahmane/Orka/internal/store"
	"github.com/google/uuid"
)

func TestSessionRevocationIsEffectiveAndAudited(t *testing.T) {
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

	organizationID, userID := uuid.New(), uuid.New()
	currentID, revokedID, otherID := uuid.New(), uuid.New(), uuid.New()
	currentToken := "current-" + uuid.NewString()
	revokedToken := "revoked-" + uuid.NewString()
	otherToken := "other-" + uuid.NewString()
	statements := []struct {
		query string
		args  []any
	}{
		{`INSERT INTO organizations(id,name,slug) VALUES($1,'Session audit',$2)`, []any{organizationID, "session-audit-" + organizationID.String()}},
		{`INSERT INTO users(id,email,password_hash) VALUES($1,$2,'unused')`, []any{userID, userID.String() + "@example.test"}},
		{`INSERT INTO memberships(organization_id,user_id,role) VALUES($1,$2,'owner')`, []any{organizationID, userID}},
		{`INSERT INTO sessions(id,user_id,token_hash,expires_at) VALUES($1,$2,$3,now()+interval '1 hour'),($4,$2,$5,now()+interval '1 hour'),($6,$2,$7,now()+interval '1 hour')`, []any{currentID, userID, cryptox.Digest(currentToken), revokedID, cryptox.Digest(revokedToken), otherID, cryptox.Digest(otherToken)}},
	}
	for _, statement := range statements {
		if _, err = db.Pool.Exec(ctx, statement.query, statement.args...); err != nil {
			t.Fatal(err)
		}
	}
	t.Cleanup(func() {
		_, _ = db.Pool.Exec(context.Background(), `DELETE FROM organizations WHERE id=$1`, organizationID)
		_, _ = db.Pool.Exec(context.Background(), `DELETE FROM users WHERE id=$1`, userID)
	})

	server := httptest.NewServer((&Server{Store: db, Logger: slog.New(slog.NewTextHandler(io.Discard, nil))}).Handler())
	defer server.Close()
	if status, body := scopedAPIRequest(t, server.URL+"/v1/sessions/"+revokedID.String(), currentToken, organizationID, http.MethodDelete, nil); status != http.StatusNoContent {
		t.Fatalf("revoke session status=%d body=%s", status, body)
	}
	if status, _ := scopedAPIRequest(t, server.URL+"/v1/me", revokedToken, organizationID, http.MethodGet, nil); status != http.StatusUnauthorized {
		t.Fatalf("revoked session status=%d, want 401", status)
	}
	if status, body := scopedAPIRequest(t, server.URL+"/v1/sessions/revoke-others", currentToken, organizationID, http.MethodPost, nil); status != http.StatusOK || string(body) != "{\"revoked\":1}\n" {
		t.Fatalf("revoke others status=%d body=%s", status, body)
	}
	if status, _ := scopedAPIRequest(t, server.URL+"/v1/me", otherToken, organizationID, http.MethodGet, nil); status != http.StatusUnauthorized {
		t.Fatalf("other revoked session status=%d, want 401", status)
	}
	logoutRequest, err := http.NewRequest(http.MethodPost, server.URL+"/v1/auth/logout", nil)
	if err != nil {
		t.Fatal(err)
	}
	logoutRequest.Header.Set("Authorization", "bEaReR "+currentToken)
	logoutRequest.Header.Set("X-Organization-ID", organizationID.String())
	logoutResponse, err := http.DefaultClient.Do(logoutRequest)
	if err != nil {
		t.Fatal(err)
	}
	logoutBody, _ := io.ReadAll(logoutResponse.Body)
	_ = logoutResponse.Body.Close()
	if logoutResponse.StatusCode != http.StatusNoContent {
		t.Fatalf("logout status=%d body=%s", logoutResponse.StatusCode, logoutBody)
	}
	if status, _ := scopedAPIRequest(t, server.URL+"/v1/me", currentToken, organizationID, http.MethodGet, nil); status != http.StatusUnauthorized {
		t.Fatalf("logged-out session status=%d, want 401", status)
	}

	var individual, bulk, logout int
	if err = db.Pool.QueryRow(ctx, `SELECT
		count(*) FILTER (WHERE action='session.revoke' AND resource_id=$2),
		count(*) FILTER (WHERE action='session.revoke_others' AND metadata->>'revoked'='1'),
		count(*) FILTER (WHERE action='auth.logout' AND resource_id=$3)
		FROM audit_events WHERE organization_id=$1 AND actor_user_id=$4`, organizationID, revokedID.String(), currentID.String(), userID).Scan(&individual, &bulk, &logout); err != nil {
		t.Fatal(err)
	}
	if individual != 1 || bulk != 1 || logout != 1 {
		t.Fatalf("session audit counts individual=%d bulk=%d logout=%d", individual, bulk, logout)
	}
}

func TestLocalPasswordChangeIsAtomicAndRevokesOtherSessions(t *testing.T) {
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

	organizationID, userID, otherUserID, oidcProviderID := uuid.New(), uuid.New(), uuid.New(), uuid.New()
	currentID, otherID, federatedID, unrelatedID := uuid.New(), uuid.New(), uuid.New(), uuid.New()
	currentToken, otherToken := "current-"+uuid.NewString(), "other-"+uuid.NewString()
	federatedToken, unrelatedToken := "federated-"+uuid.NewString(), "unrelated-"+uuid.NewString()
	oldPassword, newPassword := "old-password-long-enough", "new-password-long-enough"
	oldHash, err := auth.HashPassword(oldPassword)
	if err != nil {
		t.Fatal(err)
	}
	statements := []struct {
		query string
		args  []any
	}{
		{`INSERT INTO organizations(id,name,slug) VALUES($1,'Password rotation',$2)`, []any{organizationID, "password-rotation-" + organizationID.String()}},
		{`INSERT INTO users(id,email,password_hash) VALUES($1,$2,$3),($4,$5,'unused')`, []any{userID, userID.String() + "@example.test", oldHash, otherUserID, otherUserID.String() + "@example.test"}},
		{`INSERT INTO memberships(organization_id,user_id,role) VALUES($1,$2,'owner'),($1,$3,'viewer')`, []any{organizationID, userID, otherUserID}},
		{`INSERT INTO oidc_providers(id,organization_id,name,issuer,client_id,encrypted_client_secret,domains) VALUES($1,$2,'Password test','https://identity.example.test','client','ciphertext','{example.test}')`, []any{oidcProviderID, organizationID}},
		{`INSERT INTO sessions(id,user_id,organization_id,oidc_provider_id,token_hash,expires_at,auth_method) VALUES($1,$2,NULL,NULL,$3,now()+interval '1 hour','local'),($4,$2,NULL,NULL,$5,now()+interval '1 hour','local'),($6,$2,$7,$8,$9,now()+interval '1 hour','oidc'),($10,$11,NULL,NULL,$12,now()+interval '1 hour','local')`, []any{currentID, userID, cryptox.Digest(currentToken), otherID, cryptox.Digest(otherToken), federatedID, organizationID, oidcProviderID, cryptox.Digest(federatedToken), unrelatedID, otherUserID, cryptox.Digest(unrelatedToken)}},
	}
	for _, statement := range statements {
		if _, err = db.Pool.Exec(ctx, statement.query, statement.args...); err != nil {
			t.Fatal(err)
		}
	}
	t.Cleanup(func() {
		_, _ = db.Pool.Exec(context.Background(), `DELETE FROM organizations WHERE id=$1`, organizationID)
		_, _ = db.Pool.Exec(context.Background(), `DELETE FROM users WHERE id IN ($1,$2)`, userID, otherUserID)
	})

	server := httptest.NewServer((&Server{Store: db, SessionTTL: time.Hour, Logger: slog.New(slog.NewTextHandler(io.Discard, nil))}).Handler())
	defer server.Close()
	change := func(token, current, replacement string) (int, []byte) {
		return scopedAPIRequest(t, server.URL+"/v1/auth/password", token, organizationID, http.MethodPut, map[string]string{"currentPassword": current, "newPassword": replacement})
	}
	if status, body := change(federatedToken, oldPassword, newPassword); status != http.StatusForbidden || !strings.Contains(string(body), `"code":"local_session_required"`) {
		t.Fatalf("federated password change status=%d body=%s", status, body)
	}
	if status, body := change(currentToken, "wrong-password-long-enough", newPassword); status != http.StatusUnauthorized || !strings.Contains(string(body), `"code":"invalid_current_password"`) {
		t.Fatalf("invalid current password status=%d body=%s", status, body)
	}
	if status, body := change(currentToken, oldPassword, newPassword); status != http.StatusOK || string(body) != "{\"revoked\":2}\n" {
		t.Fatalf("password change status=%d body=%s", status, body)
	}
	for _, token := range []string{otherToken, federatedToken} {
		if status, _ := scopedAPIRequest(t, server.URL+"/v1/me", token, organizationID, http.MethodGet, nil); status != http.StatusUnauthorized {
			t.Fatalf("revoked token remained usable: status=%d", status)
		}
	}
	for _, token := range []string{currentToken, unrelatedToken} {
		if status, body := scopedAPIRequest(t, server.URL+"/v1/me", token, organizationID, http.MethodGet, nil); status != http.StatusOK {
			t.Fatalf("preserved token status=%d body=%s", status, body)
		}
	}
	if _, hash, err := db.PasswordLogin(ctx, userID.String()+"@example.test"); err != nil || !auth.VerifyPassword(hash, newPassword) || auth.VerifyPassword(hash, oldPassword) {
		t.Fatalf("password hash was not rotated safely: err=%v", err)
	}
	if status, body := scopedAPIRequest(t, server.URL+"/v1/auth/login", "", organizationID, http.MethodPost, map[string]string{"email": userID.String() + "@example.test", "password": oldPassword}); status != http.StatusUnauthorized {
		t.Fatalf("old password login status=%d body=%s", status, body)
	}
	if status, body := scopedAPIRequest(t, server.URL+"/v1/auth/login", "", organizationID, http.MethodPost, map[string]string{"email": userID.String() + "@example.test", "password": newPassword}); status != http.StatusOK || !strings.Contains(string(body), `"token":`) {
		t.Fatalf("new password login status=%d body=%s", status, body)
	}
	var auditCount, revoked int
	if err = db.Pool.QueryRow(ctx, `SELECT count(*),COALESCE(max((metadata->>'revokedSessions')::integer),0) FROM audit_events WHERE organization_id=$1 AND actor_user_id=$2 AND action='auth.password_change'`, organizationID, userID).Scan(&auditCount, &revoked); err != nil {
		t.Fatal(err)
	}
	if auditCount != 1 || revoked != 2 {
		t.Fatalf("password audit count=%d revoked=%d", auditCount, revoked)
	}
	var loginAuditCount int
	if err = db.Pool.QueryRow(ctx, `SELECT count(*) FROM audit_events WHERE organization_id=$1 AND actor_user_id=$2 AND action='auth.local.login' AND resource_type='user'`, organizationID, userID).Scan(&loginAuditCount); err != nil {
		t.Fatal(err)
	}
	if loginAuditCount != 1 {
		t.Fatalf("local login audit count=%d", loginAuditCount)
	}
}
