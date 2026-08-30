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
	"testing"
	"time"

	"github.com/bendahma/dokploy-go/internal/cryptox"
	"github.com/bendahma/dokploy-go/internal/store"
	"github.com/google/uuid"
)

func TestTemplateRepositorySyncTriggersAreDurableAndReplaySafe(t *testing.T) {
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
	box, err := cryptox.New(bytes.Repeat([]byte{31}, 32))
	if err != nil {
		t.Fatal(err)
	}
	organizationID, userID := uuid.New(), uuid.New()
	token := "catalog-webhook-" + uuid.NewString()
	for _, statement := range []struct {
		query string
		args  []any
	}{
		{`INSERT INTO organizations(id,name,slug) VALUES($1,'Webhook catalog',$2)`, []any{organizationID, "webhook-catalog-" + organizationID.String()}},
		{`INSERT INTO users(id,email,password_hash) VALUES($1,$2,'unused')`, []any{userID, userID.String() + "@example.test"}},
		{`INSERT INTO memberships(organization_id,user_id,role) VALUES($1,$2,'owner')`, []any{organizationID, userID}},
		{`INSERT INTO sessions(id,user_id,token_hash,expires_at) VALUES($1,$2,$3,now()+interval '5 minutes')`, []any{uuid.New(), userID, cryptox.Digest(token)}},
	} {
		if _, err = db.Pool.Exec(ctx, statement.query, statement.args...); err != nil {
			t.Fatal(err)
		}
	}
	t.Cleanup(func() {
		_, _ = db.Pool.Exec(context.Background(), `DELETE FROM organizations WHERE id=$1`, organizationID)
		_, _ = db.Pool.Exec(context.Background(), `DELETE FROM users WHERE id=$1`, userID)
	})
	repository, err := db.CreateTemplateRepository(ctx, store.TemplateRepository{OrganizationID: organizationID, Name: "Catalog", Slug: "catalog", RepositoryURL: "https://github.com/acme/catalog", GitRef: "main"})
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer((&Server{Store: db, Box: box, PublicURL: "https://dockyard.example.test", Logger: slog.New(slog.NewTextHandler(io.Discard, nil))}).Handler())
	t.Cleanup(server.Close)
	status, body := scopedAPIRequest(t, server.URL+"/v1/template-repositories/"+repository.ID.String()+"/sync", token, organizationID, http.MethodPost, map[string]any{})
	if status != http.StatusAccepted {
		t.Fatalf("manual sync status=%d body=%s", status, body)
	}
	var queued struct {
		Status      string    `json:"status"`
		RequestedAt time.Time `json:"requestedAt"`
	}
	if err = json.Unmarshal(body, &queued); err != nil || queued.Status != "queued" || queued.RequestedAt.IsZero() {
		t.Fatalf("manual sync response=%s err=%v", body, err)
	}
	status, body = scopedAPIRequest(t, server.URL+"/v1/template-repositories", token, organizationID, http.MethodGet, nil)
	var listed struct {
		Items []store.TemplateRepository `json:"items"`
	}
	if status != http.StatusOK {
		t.Fatalf("list repositories status=%d body=%s", status, body)
	}
	if err = json.Unmarshal(body, &listed); err != nil || len(listed.Items) != 1 || listed.Items[0].SyncRequestedAt == nil || !listed.Items[0].SyncRequestedAt.Equal(queued.RequestedAt) {
		t.Fatalf("queued sync is not visible in repository response: body=%s err=%v", body, err)
	}
	claimed, err := db.ClaimDueTemplateRepository(ctx)
	if err != nil || claimed.ID != repository.ID {
		t.Fatalf("manual sync was not durably claimable: repository=%#v err=%v", claimed, err)
	}
	if err = db.FinishTemplateRepositorySync(ctx, claimed, "succeeded", ""); err != nil {
		t.Fatal(err)
	}
	status, body = scopedAPIRequest(t, server.URL+"/v1/template-repositories/"+repository.ID.String()+"/webhook-secret", token, organizationID, http.MethodPost, map[string]any{})
	if status != http.StatusCreated {
		t.Fatalf("rotate webhook secret status=%d body=%s", status, body)
	}
	var created struct {
		Secret string `json:"secret"`
		URL    string `json:"url"`
	}
	if err = json.Unmarshal(body, &created); err != nil || len(created.Secret) < 32 || created.URL == "" {
		t.Fatalf("webhook response=%s err=%v", body, err)
	}
	payload := []byte(`{"ref":"refs/heads/main","after":"0123456789abcdef0123456789abcdef01234567"}`)
	call := func(delivery, signature string, payload []byte) (int, []byte) {
		req, _ := http.NewRequest(http.MethodPost, server.URL+"/v1/hooks/template-repositories/"+repository.ID.String(), bytes.NewReader(payload))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-GitHub-Event", "push")
		req.Header.Set("X-GitHub-Delivery", delivery)
		req.Header.Set("X-Hub-Signature-256", signature)
		response, requestErr := http.DefaultClient.Do(req)
		if requestErr != nil {
			t.Fatal(requestErr)
		}
		defer response.Body.Close()
		responseBody, _ := io.ReadAll(response.Body)
		return response.StatusCode, responseBody
	}
	sign := func(payload []byte) string {
		mac := hmac.New(sha256.New, []byte(created.Secret))
		_, _ = mac.Write(payload)
		return "sha256=" + hex.EncodeToString(mac.Sum(nil))
	}
	if status, body = call("delivery-1", sign(payload), payload); status != http.StatusAccepted {
		t.Fatalf("webhook status=%d body=%s", status, body)
	}
	if status, _ = call("delivery-1", sign(payload), payload); status != http.StatusConflict {
		t.Fatalf("duplicate webhook status=%d", status)
	}
	oldSignature := sign(payload)
	status, body = scopedAPIRequest(t, server.URL+"/v1/template-repositories/"+repository.ID.String()+"/webhook-secret", token, organizationID, http.MethodPost, map[string]any{})
	if status != http.StatusCreated {
		t.Fatalf("rotate webhook secret status=%d body=%s", status, body)
	}
	var rotated struct {
		Secret string `json:"secret"`
		URL    string `json:"url"`
	}
	if err = json.Unmarshal(body, &rotated); err != nil || rotated.Secret == created.Secret || rotated.URL != created.URL {
		t.Fatalf("rotated webhook response=%s err=%v", body, err)
	}
	created.Secret = rotated.Secret
	if status, _ = call("delivery-2", oldSignature, payload); status != http.StatusUnauthorized {
		t.Fatalf("old signature status=%d", status)
	}
	if status, _ = call("delivery-2", sign(payload), payload); status != http.StatusAccepted {
		t.Fatalf("rotated signature status=%d", status)
	}
	if status, _ = call("delivery-invalid", "sha256=00", payload); status != http.StatusUnauthorized {
		t.Fatalf("invalid signature status=%d", status)
	}
	wrongBranch := []byte(`{"ref":"refs/heads/other","after":"0123456789abcdef0123456789abcdef01234567"}`)
	if status, _ = call("delivery-3", sign(wrongBranch), wrongBranch); status != http.StatusNoContent {
		t.Fatalf("wrong branch status=%d", status)
	}
	var deliveries int
	if err = db.Pool.QueryRow(ctx, `SELECT count(*) FROM template_repository_webhook_deliveries WHERE repository_id=$1`, repository.ID).Scan(&deliveries); err != nil || deliveries != 2 {
		t.Fatalf("deliveries=%d err=%v", deliveries, err)
	}
	status, body = scopedAPIRequest(t, server.URL+"/v1/template-repositories/"+repository.ID.String()+"/webhook-secret", token, organizationID, http.MethodDelete, nil)
	if status != http.StatusNoContent {
		t.Fatalf("disable webhook status=%d body=%s", status, body)
	}
	if status, _ = call("delivery-4", sign(payload), payload); status != http.StatusNotFound {
		t.Fatalf("disabled webhook status=%d", status)
	}
}
