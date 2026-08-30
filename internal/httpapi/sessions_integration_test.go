package httpapi

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/bendahma/dokploy-go/internal/cryptox"
	"github.com/bendahma/dokploy-go/internal/store"
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
