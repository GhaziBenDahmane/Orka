package httpapi

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
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

func TestSignedProviderWebhookQueuesOnce(t *testing.T) {
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
	box, err := cryptox.New(bytes.Repeat([]byte{5}, 32))
	if err != nil {
		t.Fatal(err)
	}

	orgID, userID, projectID, environmentID, serviceID := uuid.New(), uuid.New(), uuid.New(), uuid.New(), uuid.New()
	token := "webhook-session-" + uuid.NewString()
	tx, err := db.Pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(ctx)
	_, err = tx.Exec(ctx, `INSERT INTO organizations(id,name,slug) VALUES($1,'Webhook Test',$2)`, orgID, "webhook-"+orgID.String())
	if err == nil {
		_, err = tx.Exec(ctx, `INSERT INTO users(id,email,password_hash) VALUES($1,$2,'!test')`, userID, userID.String()+"@example.test")
	}
	if err == nil {
		_, err = tx.Exec(ctx, `INSERT INTO memberships(organization_id,user_id,role) VALUES($1,$2,'owner')`, orgID, userID)
	}
	if err == nil {
		_, err = tx.Exec(ctx, `INSERT INTO sessions(id,user_id,token_hash,expires_at) VALUES($1,$2,$3,now()+interval '5 minutes')`, uuid.New(), userID, cryptox.Digest(token))
	}
	if err == nil {
		_, err = tx.Exec(ctx, `INSERT INTO projects(id,organization_id,name,slug) VALUES($1,$2,'Project','project')`, projectID, orgID)
	}
	if err == nil {
		_, err = tx.Exec(ctx, `INSERT INTO environments(id,project_id,name,slug) VALUES($1,$2,'Production','production')`, environmentID, projectID)
	}
	if err == nil {
		_, err = tx.Exec(ctx, `INSERT INTO compose_services(id,environment_id,name,slug,stack_name,compose_yaml) VALUES($1,$2,'API','api',$3,'services: {}')`, serviceID, environmentID, "webhook-"+serviceID.String())
	}
	credentialID := uuid.New()
	if err == nil {
		_, err = tx.Exec(ctx, `INSERT INTO source_credentials(id,organization_id,kind,name,server,username,encrypted_secret) VALUES($1,$2,'git','status-token','github.com','bot','encrypted-test')`, credentialID, orgID)
	}
	if err == nil {
		_, err = tx.Exec(ctx, `INSERT INTO application_sources(compose_service_id,repository_url,target_service,registry_image,status_provider,status_credential_id,status_context) VALUES($1,'https://github.com/acme/api.git','api','registry.example/acme/api','github',$2,'dockyard/deploy')`, serviceID, credentialID)
	}
	if err == nil {
		err = tx.Commit(ctx)
	}
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = db.Pool.Exec(context.Background(), `DELETE FROM jobs j USING deployments d WHERE j.payload->>'deploymentId'=d.id::text AND d.compose_service_id=$1`, serviceID)
		_, _ = db.Pool.Exec(context.Background(), `DELETE FROM jobs j USING commit_status_deliveries cs,deployments d WHERE j.payload->>'deliveryId'=cs.id::text AND cs.deployment_id=d.id AND d.compose_service_id=$1`, serviceID)
		_, _ = db.Pool.Exec(context.Background(), `DELETE FROM organizations WHERE id=$1`, orgID)
		_, _ = db.Pool.Exec(context.Background(), `DELETE FROM users WHERE id=$1`, userID)
	})

	server := httptest.NewServer((&Server{Store: db, Box: box, PublicURL: "https://dockyard.example.test", Logger: slog.New(slog.NewTextHandler(io.Discard, nil))}).Handler())
	defer server.Close()
	requestBody := []byte(`{"name":"github-main","provider":"github","branch":"main"}`)
	req, _ := http.NewRequest(http.MethodPost, server.URL+"/v1/services/"+serviceID.String()+"/webhooks", bytes.NewReader(requestBody))
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("X-Organization-ID", orgID.String())
	req.Header.Set("Content-Type", "application/json")
	response, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	data, _ := io.ReadAll(response.Body)
	response.Body.Close()
	if response.StatusCode != http.StatusCreated {
		t.Fatalf("create status = %d: %s", response.StatusCode, data)
	}
	var created struct {
		Integration store.WebhookIntegration `json:"integration"`
		Secret      string                   `json:"secret"`
		URL         string                   `json:"url"`
	}
	if err = json.Unmarshal(data, &created); err != nil || created.Secret == "" || created.Integration.ID == uuid.Nil {
		t.Fatalf("created webhook = %#v, err = %v", created, err)
	}
	if strings.Contains(string(data), "encryptedSecret") {
		t.Fatalf("response leaked encrypted secret: %s", data)
	}
	var encryptedSecret string
	if err = db.Pool.QueryRow(ctx, `SELECT encrypted_secret FROM webhook_integrations WHERE id=$1`, created.Integration.ID).Scan(&encryptedSecret); err != nil || encryptedSecret == created.Secret {
		t.Fatalf("stored secret was not encrypted, err = %v", err)
	}

	commitSHA := "0123456789abcdef0123456789abcdef01234567"
	payload := []byte(`{"ref":"refs/heads/main","after":"` + commitSHA + `","deleted":false}`)
	call := func(delivery, signature string) *http.Response {
		hookRequest, requestErr := http.NewRequest(http.MethodPost, server.URL+"/v1/hooks/provider/"+created.Integration.ID.String(), bytes.NewReader(payload))
		if requestErr != nil {
			t.Fatal(requestErr)
		}
		hookRequest.Header.Set("X-GitHub-Event", "push")
		hookRequest.Header.Set("X-GitHub-Delivery", delivery)
		hookRequest.Header.Set("X-Hub-Signature-256", signature)
		hookResponse, requestErr := http.DefaultClient.Do(hookRequest)
		if requestErr != nil {
			t.Fatal(requestErr)
		}
		return hookResponse
	}
	mac := hmac.New(sha256.New, []byte(created.Secret))
	_, _ = mac.Write(payload)
	signature := "sha256=" + hex.EncodeToString(mac.Sum(nil))
	response = call("delivery-1", signature)
	data, _ = io.ReadAll(response.Body)
	response.Body.Close()
	if response.StatusCode != http.StatusAccepted {
		t.Fatalf("webhook status = %d: %s", response.StatusCode, data)
	}
	response = call("delivery-1", signature)
	response.Body.Close()
	if response.StatusCode != http.StatusConflict {
		t.Fatalf("replayed webhook status = %d, want 409", response.StatusCode)
	}
	response = call("delivery-2", "sha256="+strings.Repeat("0", 64))
	response.Body.Close()
	if response.StatusCode != http.StatusUnauthorized {
		t.Fatalf("invalid signature status = %d, want 401", response.StatusCode)
	}

	var deploymentCount int
	if err = db.Pool.QueryRow(ctx, `SELECT count(*) FROM deployments WHERE compose_service_id=$1 AND trigger='github-webhook'`, serviceID).Scan(&deploymentCount); err != nil || deploymentCount != 1 {
		t.Fatalf("deployment count = %d, err = %v", deploymentCount, err)
	}
	var storedSHA string
	if err = db.Pool.QueryRow(ctx, `SELECT commit_sha FROM deployments WHERE compose_service_id=$1 AND trigger='github-webhook'`, serviceID).Scan(&storedSHA); err != nil || storedSHA != commitSHA {
		t.Fatalf("commit SHA = %q, err = %v", storedSHA, err)
	}
	var statusDeliveries, statusJobs int
	if err = db.Pool.QueryRow(ctx, `SELECT count(*) FROM commit_status_deliveries cs JOIN deployments d ON d.id=cs.deployment_id WHERE d.compose_service_id=$1 AND cs.state='pending'`, serviceID).Scan(&statusDeliveries); err != nil {
		t.Fatal(err)
	}
	if err = db.Pool.QueryRow(ctx, `SELECT count(*) FROM jobs WHERE kind='commit.status' AND payload->>'deliveryId' IN (SELECT cs.id::text FROM commit_status_deliveries cs JOIN deployments d ON d.id=cs.deployment_id WHERE d.compose_service_id=$1)`, serviceID).Scan(&statusJobs); err != nil || statusDeliveries != 1 || statusJobs != 1 {
		t.Fatalf("status deliveries=%d jobs=%d err=%v", statusDeliveries, statusJobs, err)
	}
}
