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

func TestAgentUpgradeAPIWaitsForHeartbeatConvergence(t *testing.T) {
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
	box, err := cryptox.New(bytes.Repeat([]byte{9}, 32))
	if err != nil {
		t.Fatal(err)
	}
	organizationID, userID, clusterID := uuid.New(), uuid.New(), uuid.New()
	token := "cluster-upgrade-" + uuid.NewString()
	for _, statement := range []struct {
		query string
		args  []any
	}{
		{`INSERT INTO organizations(id,name,slug) VALUES($1,'Cluster upgrade',$2)`, []any{organizationID, "cluster-upgrade-" + organizationID.String()}},
		{`INSERT INTO users(id,email,password_hash) VALUES($1,$2,'!test')`, []any{userID, userID.String() + "@example.test"}},
		{`INSERT INTO memberships(organization_id,user_id,role) VALUES($1,$2,'owner')`, []any{organizationID, userID}},
		{`INSERT INTO sessions(id,user_id,token_hash,expires_at) VALUES($1,$2,$3,now()+interval '5 minutes')`, []any{uuid.New(), userID, cryptox.Digest(token)}},
		{`INSERT INTO clusters(id,organization_id,name,slug,state) VALUES($1,$2,'Remote','remote','active')`, []any{clusterID, organizationID}},
	} {
		if _, err = db.Pool.Exec(ctx, statement.query, statement.args...); err != nil {
			t.Fatal(err)
		}
	}
	t.Cleanup(func() {
		_, _ = db.Pool.Exec(context.Background(), `DELETE FROM organizations WHERE id=$1`, organizationID)
		_, _ = db.Pool.Exec(context.Background(), `DELETE FROM users WHERE id=$1`, userID)
	})

	api := &Server{Store: db, Box: box, Logger: slog.New(slog.NewTextHandler(io.Discard, nil))}
	httpServer := httptest.NewServer(api.Handler())
	defer httpServer.Close()
	target := "registry.example/dockyard@sha256:" + strings.Repeat("a", 64)
	status, body := clusterUpgradeRequest(t, httpServer.URL+"/v1/clusters/"+clusterID.String()+"/agent-upgrades", token, organizationID, http.MethodPost, map[string]string{"image": target})
	if status != http.StatusAccepted {
		t.Fatalf("queue status=%d body=%s", status, body)
	}
	var command store.ClusterCommand
	if err = json.Unmarshal(body, &command); err != nil {
		t.Fatal(err)
	}
	if command.Status != "pending" || command.TargetImage != target {
		t.Fatalf("queued command=%#v", command)
	}

	otherTarget := "registry.example/dockyard@sha256:" + strings.Repeat("b", 64)
	status, body = clusterUpgradeRequest(t, httpServer.URL+"/v1/clusters/"+clusterID.String()+"/agent-upgrades", token, organizationID, http.MethodPost, map[string]string{"image": otherTarget})
	if status != http.StatusConflict || !bytes.Contains(body, []byte(`"code":"agent_upgrade_running"`)) {
		t.Fatalf("duplicate status=%d body=%s", status, body)
	}

	claimed, err := db.ClaimClusterCommand(ctx, clusterID, time.Minute)
	if err != nil || claimed.ID != command.ID || claimed.LeaseID == nil {
		t.Fatalf("claimed=%#v err=%v", claimed, err)
	}
	if err = db.CompleteClusterCommand(ctx, clusterID, command.ID, *claimed.LeaseID, "encrypted-result", false); err != nil {
		t.Fatal(err)
	}
	commandURL := httpServer.URL + "/v1/clusters/" + clusterID.String() + "/commands/" + command.ID.String()
	status, body = clusterUpgradeRequest(t, commandURL, token, organizationID, http.MethodGet, nil)
	if status != http.StatusOK || !bytes.Contains(body, []byte(`"status":"verifying"`)) {
		t.Fatalf("verifying status=%d body=%s", status, body)
	}

	for _, payload := range []string{
		`{"agentImage":"valid.example/agent:latest\nbad","agentUpdateState":"completed","capacity":{}}`,
		`{"agentImage":"valid.example/agent:latest","agentUpdateState":"unknown","capacity":{}}`,
	} {
		recorder := httptest.NewRecorder()
		request := httptest.NewRequest(http.MethodPost, "/v1/agent/heartbeat", strings.NewReader(payload))
		request = request.WithContext(context.WithValue(request.Context(), clusterIDKey, clusterID))
		api.agentHeartbeat(recorder, request)
		if recorder.Code != http.StatusBadRequest {
			t.Fatalf("invalid heartbeat status=%d body=%s", recorder.Code, recorder.Body.String())
		}
	}

	oldImage := "registry.example/dockyard@sha256:" + strings.Repeat("c", 64)
	postAgentHeartbeat(t, api, clusterID, map[string]any{"agentVersion": "1.0.0", "agentImage": oldImage, "agentUpdateState": "updating", "dockerVersion": "29.0.0", "capacity": map[string]any{"nodes": 3}})
	status, body = clusterUpgradeRequest(t, commandURL, token, organizationID, http.MethodGet, nil)
	if status != http.StatusOK || !bytes.Contains(body, []byte(`"status":"verifying"`)) {
		t.Fatalf("premature convergence status=%d body=%s", status, body)
	}

	postAgentHeartbeat(t, api, clusterID, map[string]any{"agentVersion": "1.0.0", "agentImage": oldImage, "agentUpdateState": "rollback_completed", "dockerVersion": "29.0.0", "capacity": map[string]any{"nodes": 3}})
	status, body = clusterUpgradeRequest(t, commandURL, token, organizationID, http.MethodGet, nil)
	if status != http.StatusOK || !bytes.Contains(body, []byte(`"status":"failed"`)) || !bytes.Contains(body, []byte("rollback_completed")) {
		t.Fatalf("rollback status=%d body=%s", status, body)
	}

	status, body = clusterUpgradeRequest(t, httpServer.URL+"/v1/clusters/"+clusterID.String()+"/agent-upgrades", token, organizationID, http.MethodPost, map[string]string{"image": otherTarget})
	if status != http.StatusAccepted {
		t.Fatalf("replacement queue status=%d body=%s", status, body)
	}
	if err = json.Unmarshal(body, &command); err != nil {
		t.Fatal(err)
	}
	claimed, err = db.ClaimClusterCommand(ctx, clusterID, time.Minute)
	if err != nil || claimed.ID != command.ID || claimed.LeaseID == nil {
		t.Fatalf("replacement claim=%#v err=%v", claimed, err)
	}
	if err = db.CompleteClusterCommand(ctx, clusterID, command.ID, *claimed.LeaseID, "encrypted-result", false); err != nil {
		t.Fatal(err)
	}
	postAgentHeartbeat(t, api, clusterID, map[string]any{"agentVersion": "2.0.0", "agentImage": otherTarget, "agentUpdateState": "completed", "dockerVersion": "29.0.0", "capacity": map[string]any{"nodes": 3}})
	commandURL = httpServer.URL + "/v1/clusters/" + clusterID.String() + "/commands/" + command.ID.String()
	status, body = clusterUpgradeRequest(t, commandURL, token, organizationID, http.MethodGet, nil)
	if status != http.StatusOK || !bytes.Contains(body, []byte(`"status":"succeeded"`)) {
		t.Fatalf("converged status=%d body=%s", status, body)
	}
}

func clusterUpgradeRequest(t *testing.T, url, token string, organizationID uuid.UUID, method string, input any) (int, []byte) {
	t.Helper()
	var body io.Reader
	if input != nil {
		encoded, err := json.Marshal(input)
		if err != nil {
			t.Fatal(err)
		}
		body = bytes.NewReader(encoded)
	}
	request, err := http.NewRequest(method, url, body)
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Authorization", "Bearer "+token)
	request.Header.Set("X-Organization-ID", organizationID.String())
	request.Header.Set("Content-Type", "application/json")
	response, err := http.DefaultClient.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	payload, err := io.ReadAll(response.Body)
	if err != nil {
		t.Fatal(err)
	}
	return response.StatusCode, payload
}

func postAgentHeartbeat(t *testing.T, api *Server, clusterID uuid.UUID, payload map[string]any) {
	t.Helper()
	body, err := json.Marshal(payload)
	if err != nil {
		t.Fatal(err)
	}
	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodPost, "/v1/agent/heartbeat", bytes.NewReader(body))
	request = request.WithContext(context.WithValue(request.Context(), clusterIDKey, clusterID))
	api.agentHeartbeat(recorder, request)
	if recorder.Code != http.StatusNoContent {
		t.Fatalf("heartbeat status=%d body=%s", recorder.Code, recorder.Body.String())
	}
}
