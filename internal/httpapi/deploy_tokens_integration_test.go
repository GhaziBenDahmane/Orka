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
	"strings"
	"testing"
	"time"

	"github.com/bendahma/dokploy-go/internal/cryptox"
	"github.com/bendahma/dokploy-go/internal/store"
	"github.com/google/uuid"
)

func TestDeployTokenExpiryUseAndRevocation(t *testing.T) {
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
	organizationID, otherOrganizationID := uuid.New(), uuid.New()
	userID, projectID, environmentID, serviceID := uuid.New(), uuid.New(), uuid.New(), uuid.New()
	sessionToken := "deploy-token-session-" + uuid.NewString()
	tx, err := db.Pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(ctx)
	statements := []struct {
		query string
		args  []any
	}{
		{`INSERT INTO organizations(id,name,slug) VALUES($1,'Deploy tokens',$2),($3,'Other deploy tokens',$4)`, []any{organizationID, "deploy-tokens-" + organizationID.String(), otherOrganizationID, "other-deploy-tokens-" + otherOrganizationID.String()}},
		{`INSERT INTO users(id,email,password_hash) VALUES($1,$2,'!test')`, []any{userID, userID.String() + "@example.test"}},
		{`INSERT INTO memberships(organization_id,user_id,role) VALUES($1,$2,'owner')`, []any{organizationID, userID}},
		{`INSERT INTO sessions(id,user_id,token_hash,expires_at) VALUES($1,$2,$3,now()+interval '5 minutes')`, []any{uuid.New(), userID, cryptox.Digest(sessionToken)}},
		{`INSERT INTO projects(id,organization_id,name,slug) VALUES($1,$2,'Project','project')`, []any{projectID, organizationID}},
		{`INSERT INTO environments(id,project_id,name,slug) VALUES($1,$2,'Production','production')`, []any{environmentID, projectID}},
		{`INSERT INTO compose_services(id,environment_id,name,slug,stack_name,compose_yaml) VALUES($1,$2,'API','api',$3,'services: {}')`, []any{serviceID, environmentID, "deploy-token-" + serviceID.String()}},
	}
	for _, statement := range statements {
		if _, err = tx.Exec(ctx, statement.query, statement.args...); err != nil {
			t.Fatal(err)
		}
	}
	if err = tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = db.Pool.Exec(context.Background(), `DELETE FROM jobs job USING deployments deployment WHERE job.payload->>'deploymentId'=deployment.id::text AND deployment.compose_service_id=$1`, serviceID)
		_, _ = db.Pool.Exec(context.Background(), `DELETE FROM organizations WHERE id IN ($1,$2)`, organizationID, otherOrganizationID)
		_, _ = db.Pool.Exec(context.Background(), `DELETE FROM users WHERE id=$1`, userID)
	})

	server := httptest.NewServer((&Server{Store: db, PublicURL: "https://dockyard.example.test", Logger: slog.New(slog.NewTextHandler(io.Discard, nil))}).Handler())
	defer server.Close()
	authenticatedRequest := func(method, path string, body []byte) *http.Response {
		req, requestErr := http.NewRequest(method, server.URL+path, bytes.NewReader(body))
		if requestErr != nil {
			t.Fatal(requestErr)
		}
		req.Header.Set("Authorization", "Bearer "+sessionToken)
		req.Header.Set("X-Organization-ID", organizationID.String())
		if body != nil {
			req.Header.Set("Content-Type", "application/json")
		}
		response, requestErr := http.DefaultClient.Do(req)
		if requestErr != nil {
			t.Fatal(requestErr)
		}
		return response
	}

	response := authenticatedRequest(http.MethodPost, "/v1/services/"+serviceID.String()+"/deploy-tokens", []byte(`{"name":"invalid","expiresInDays":366}`))
	response.Body.Close()
	if response.StatusCode != http.StatusBadRequest {
		t.Fatalf("invalid expiry status=%d", response.StatusCode)
	}

	response = authenticatedRequest(http.MethodPost, "/v1/services/"+serviceID.String()+"/deploy-tokens", []byte(`{"name":"ci-release","expiresInDays":2}`))
	data, _ := io.ReadAll(response.Body)
	response.Body.Close()
	if response.StatusCode != http.StatusCreated {
		t.Fatalf("create status=%d body=%s", response.StatusCode, data)
	}
	var created struct {
		DeployToken store.DeployToken `json:"deployToken"`
		Token       string            `json:"token"`
		URL         string            `json:"url"`
	}
	if err = json.Unmarshal(data, &created); err != nil || created.DeployToken.ID == uuid.Nil || created.Token == "" || !strings.HasSuffix(created.URL, created.Token) {
		t.Fatalf("created=%#v err=%v", created, err)
	}
	if created.DeployToken.ExpiresAt.Before(time.Now().Add(47*time.Hour)) || created.DeployToken.ExpiresAt.After(time.Now().Add(49*time.Hour)) || strings.Contains(string(data), "tokenHash") {
		t.Fatalf("unexpected deploy token response=%s", data)
	}

	response = authenticatedRequest(http.MethodGet, "/v1/services/"+serviceID.String()+"/deploy-tokens", nil)
	data, _ = io.ReadAll(response.Body)
	response.Body.Close()
	var listed struct {
		Items []store.DeployToken `json:"items"`
	}
	if response.StatusCode != http.StatusOK || json.Unmarshal(data, &listed) != nil || len(listed.Items) != 1 || listed.Items[0].ID != created.DeployToken.ID {
		t.Fatalf("list status=%d body=%s", response.StatusCode, data)
	}

	hookResponse, err := http.Post(server.URL+"/v1/hooks/deploy/"+created.Token, "application/json", nil)
	if err != nil {
		t.Fatal(err)
	}
	hookData, _ := io.ReadAll(hookResponse.Body)
	hookResponse.Body.Close()
	if hookResponse.StatusCode != http.StatusAccepted {
		t.Fatalf("hook status=%d body=%s", hookResponse.StatusCode, hookData)
	}
	var hookedDeployment store.Deployment
	if err = json.Unmarshal(hookData, &hookedDeployment); err != nil || hookedDeployment.ID == uuid.Nil {
		t.Fatalf("hook deployment=%#v err=%v", hookedDeployment, err)
	}
	var lastUsedAt *time.Time
	if err = db.Pool.QueryRow(ctx, `SELECT last_used_at FROM deploy_tokens WHERE id=$1`, created.DeployToken.ID).Scan(&lastUsedAt); err != nil || lastUsedAt == nil {
		t.Fatalf("last_used_at=%v err=%v", lastUsedAt, err)
	}
	var hookAudits int
	if err = db.Pool.QueryRow(ctx, `SELECT count(*) FROM audit_events WHERE organization_id=$1 AND action='deployment.hook' AND resource_id=$2 AND metadata->>'deployTokenId'=$3`, organizationID, hookedDeployment.ID.String(), created.DeployToken.ID.String()).Scan(&hookAudits); err != nil || hookAudits != 1 {
		t.Fatalf("deployment hook audits=%d err=%v", hookAudits, err)
	}

	if err = db.RevokeDeployToken(ctx, otherOrganizationID, serviceID, created.DeployToken.ID); err != store.ErrNotFound {
		t.Fatalf("cross-tenant revoke err=%v", err)
	}
	response = authenticatedRequest(http.MethodDelete, "/v1/services/"+serviceID.String()+"/deploy-tokens/"+created.DeployToken.ID.String(), nil)
	response.Body.Close()
	if response.StatusCode != http.StatusNoContent {
		t.Fatalf("revoke status=%d", response.StatusCode)
	}
	hookResponse, err = http.Post(server.URL+"/v1/hooks/deploy/"+created.Token, "application/json", nil)
	if err != nil {
		t.Fatal(err)
	}
	hookResponse.Body.Close()
	if hookResponse.StatusCode != http.StatusNotFound {
		t.Fatalf("revoked hook status=%d", hookResponse.StatusCode)
	}

	expiredToken := "expired-deploy-token-" + uuid.NewString()
	if _, err = db.CreateDeployToken(ctx, organizationID, serviceID, userID, "expired", cryptox.Digest(expiredToken), time.Now().Add(-time.Minute)); err != nil {
		t.Fatal(err)
	}
	hookResponse, err = http.Post(server.URL+"/v1/hooks/deploy/"+expiredToken, "application/json", nil)
	if err != nil {
		t.Fatal(err)
	}
	hookResponse.Body.Close()
	if hookResponse.StatusCode != http.StatusNotFound {
		t.Fatalf("expired hook status=%d", hookResponse.StatusCode)
	}
}
