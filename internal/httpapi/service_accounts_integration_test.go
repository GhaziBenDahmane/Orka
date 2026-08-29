package httpapi

import (
	"bytes"
	"context"
	"encoding/json"
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

func TestServiceAccountAuthenticationAndRotation(t *testing.T) {
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
	box, err := cryptox.New(bytes.Repeat([]byte{3}, 32))
	if err != nil {
		t.Fatal(err)
	}
	orgID, userID := uuid.New(), uuid.New()
	userToken := "owner-session-" + uuid.NewString()
	_, err = db.Pool.Exec(ctx, `INSERT INTO organizations(id,name,slug) VALUES($1,'Service Accounts',$2)`, orgID, "service-accounts-"+orgID.String())
	if err == nil {
		_, err = db.Pool.Exec(ctx, `INSERT INTO users(id,email,password_hash) VALUES($1,$2,'!test')`, userID, userID.String()+"@example.test")
	}
	if err == nil {
		_, err = db.Pool.Exec(ctx, `INSERT INTO memberships(organization_id,user_id,role) VALUES($1,$2,'owner')`, orgID, userID)
	}
	if err == nil {
		_, err = db.Pool.Exec(ctx, `INSERT INTO sessions(id,user_id,token_hash,expires_at) VALUES($1,$2,$3,now()+interval '5 minutes')`, uuid.New(), userID, cryptox.Digest(userToken))
	}
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = db.Pool.Exec(context.Background(), `DELETE FROM organizations WHERE id=$1`, orgID)
		_, _ = db.Pool.Exec(context.Background(), `DELETE FROM users WHERE id=$1`, userID)
	})

	server := httptest.NewServer((&Server{Store: db, Box: box, PublicURL: "https://dockyard.example.test", SessionTTL: time.Hour, Logger: slog.New(slog.NewTextHandler(io.Discard, nil))}).Handler())
	defer server.Close()
	do := func(method, path, token string, body []byte) (*http.Response, []byte) {
		req, requestErr := http.NewRequest(method, server.URL+path, bytes.NewReader(body))
		if requestErr != nil {
			t.Fatal(requestErr)
		}
		req.Header.Set("Authorization", "Bearer "+token)
		req.Header.Set("X-Organization-ID", orgID.String())
		req.Header.Set("Content-Type", "application/json")
		response, requestErr := http.DefaultClient.Do(req)
		if requestErr != nil {
			t.Fatal(requestErr)
		}
		data, _ := io.ReadAll(response.Body)
		response.Body.Close()
		return response, data
	}

	response, data := do(http.MethodPost, "/v1/service-accounts", userToken, []byte(`{"name":"automation","role":"admin","expiresInDays":30}`))
	if response.StatusCode != http.StatusCreated {
		t.Fatalf("create status = %d: %s", response.StatusCode, data)
	}
	var created struct {
		ServiceAccount store.ServiceAccount `json:"serviceAccount"`
		Token          string               `json:"token"`
	}
	if err = json.Unmarshal(data, &created); err != nil || created.Token == "" {
		t.Fatalf("created account = %#v, err = %v", created, err)
	}
	response, data = do(http.MethodGet, "/v1/me", created.Token, nil)
	if response.StatusCode != http.StatusOK || !bytes.Contains(data, []byte(created.ServiceAccount.ID.String())) {
		t.Fatalf("service account auth status = %d: %s", response.StatusCode, data)
	}
	response, _ = do(http.MethodGet, "/v1/sessions", created.Token, nil)
	if response.StatusCode != http.StatusForbidden {
		t.Fatalf("service account session-list status = %d, want 403", response.StatusCode)
	}

	response, data = do(http.MethodPost, "/v1/service-accounts/"+created.ServiceAccount.ID.String()+"/rotate", userToken, []byte(`{"expiresInDays":60}`))
	if response.StatusCode != http.StatusOK {
		t.Fatalf("rotate status = %d: %s", response.StatusCode, data)
	}
	var rotated map[string]any
	if err = json.Unmarshal(data, &rotated); err != nil {
		t.Fatal(err)
	}
	newToken, _ := rotated["token"].(string)
	response, _ = do(http.MethodGet, "/v1/me", created.Token, nil)
	if response.StatusCode != http.StatusUnauthorized {
		t.Fatalf("old token status = %d, want 401", response.StatusCode)
	}
	response, _ = do(http.MethodGet, "/v1/me", newToken, nil)
	if response.StatusCode != http.StatusOK {
		t.Fatalf("rotated token status = %d, want 200", response.StatusCode)
	}
	response, data = do(http.MethodPost, "/v1/projects", newToken, []byte(`{"name":"Automated Project"}`))
	if response.StatusCode != http.StatusCreated {
		t.Fatalf("service-account project status = %d: %s", response.StatusCode, data)
	}
	var audited bool
	if err = db.Pool.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM audit_events WHERE organization_id=$1 AND actor_service_account_id=$2 AND action='project.create')`, orgID, created.ServiceAccount.ID).Scan(&audited); err != nil || !audited {
		t.Fatalf("service account audit present = %v, err = %v", audited, err)
	}

	response, data = do(http.MethodPost, "/v1/service-accounts", userToken, []byte(`{"name":"ai-auditor","role":"auditor","expiresInDays":30}`))
	if response.StatusCode != http.StatusCreated {
		t.Fatalf("create auditor status = %d: %s", response.StatusCode, data)
	}
	var auditor struct {
		Token string `json:"token"`
	}
	if err = json.Unmarshal(data, &auditor); err != nil || auditor.Token == "" {
		t.Fatalf("auditor response=%s err=%v", data, err)
	}
	response, _ = do(http.MethodGet, "/v1/projects", auditor.Token, nil)
	if response.StatusCode != http.StatusForbidden {
		t.Fatalf("auditor normal API status=%d, want 403", response.StatusCode)
	}
	response, data = do(http.MethodGet, "/v1/ai/audit-snapshot", auditor.Token, nil)
	if response.StatusCode != http.StatusOK {
		t.Fatalf("auditor snapshot status=%d: %s", response.StatusCode, data)
	}
	response, data = do(http.MethodPost, "/v1/ai/audit-runs", auditor.Token, []byte(`{"agentName":"test-auditor","model":"test"}`))
	if response.StatusCode != http.StatusCreated {
		t.Fatalf("auditor run status=%d: %s", response.StatusCode, data)
	}

	response, _ = do(http.MethodDelete, "/v1/service-accounts/"+created.ServiceAccount.ID.String(), userToken, nil)
	if response.StatusCode != http.StatusNoContent {
		t.Fatalf("disable status = %d, want 204", response.StatusCode)
	}
	response, _ = do(http.MethodGet, "/v1/me", newToken, nil)
	if response.StatusCode != http.StatusUnauthorized {
		t.Fatalf("disabled account token status = %d, want 401", response.StatusCode)
	}
}
