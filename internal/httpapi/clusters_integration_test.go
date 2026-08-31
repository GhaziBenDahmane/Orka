package httpapi

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/bendahma/dokploy-go/internal/agentpki"
	"github.com/bendahma/dokploy-go/internal/cryptox"
	"github.com/bendahma/dokploy-go/internal/store"
	"github.com/google/uuid"
)

func TestAgentEnrollmentIsIdempotentForTheSameCSR(t *testing.T) {
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
	now := time.Now().UTC()
	caPEM, caKey, err := agentpki.NewCA(now, 24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	organizationID, clusterID := uuid.New(), uuid.New()
	token := "enrollment-" + uuid.NewString()
	if _, err = db.Pool.Exec(ctx, `INSERT INTO organizations(id,name,slug) VALUES($1,'Enrollment retry',$2)`, organizationID, "enrollment-retry-"+organizationID.String()); err == nil {
		_, err = db.Pool.Exec(ctx, `INSERT INTO clusters(id,organization_id,name,slug,state) VALUES($1,$2,'Remote','remote','pending')`, clusterID, organizationID)
	}
	if err == nil {
		err = db.CreateClusterEnrollmentToken(ctx, organizationID, clusterID, uuid.Nil, cryptox.Digest(token), time.Now().Add(5*time.Minute))
	}
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = db.Pool.Exec(context.Background(), `DELETE FROM organizations WHERE id=$1`, organizationID)
	})
	makeCSR := func(t *testing.T) string {
		t.Helper()
		key, keyErr := rsa.GenerateKey(rand.Reader, 2048)
		if keyErr != nil {
			t.Fatal(keyErr)
		}
		request, requestErr := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{Subject: pkix.Name{CommonName: "dockyard-agent"}}, key)
		if requestErr != nil {
			t.Fatal(requestErr)
		}
		return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: request}))
	}
	api := &Server{Store: db, AgentCACertificate: caPEM, AgentCAKey: caKey, AgentCertificateTTL: time.Hour, Logger: slog.New(slog.NewTextHandler(io.Discard, nil))}
	enroll := func(csr string) (int, []byte) {
		body, _ := json.Marshal(map[string]string{"token": token, "csr": csr})
		request := httptest.NewRequest(http.MethodPost, "/v1/agent/enroll", bytes.NewReader(body))
		request.Header.Set("Content-Type", "application/json")
		recorder := httptest.NewRecorder()
		api.enrollClusterAgent(recorder, request)
		return recorder.Code, recorder.Body.Bytes()
	}
	csr := makeCSR(t)
	status, firstBody := enroll(csr)
	if status != http.StatusOK {
		t.Fatalf("first enrollment status=%d body=%s", status, firstBody)
	}
	status, retryBody := enroll(csr)
	if status != http.StatusOK {
		t.Fatalf("retry enrollment status=%d body=%s", status, retryBody)
	}
	var first, retry struct {
		Certificate string `json:"certificate"`
	}
	if err = json.Unmarshal(firstBody, &first); err == nil {
		err = json.Unmarshal(retryBody, &retry)
	}
	if err != nil || first.Certificate == "" || retry.Certificate != first.Certificate {
		t.Fatalf("retry did not return the original certificate: first=%q retry=%q err=%v", first.Certificate, retry.Certificate, err)
	}
	status, replayBody := enroll(makeCSR(t))
	if status != http.StatusUnauthorized || !bytes.Contains(replayBody, []byte(`"code":"invalid_enrollment_token"`)) {
		t.Fatalf("different-key replay status=%d body=%s", status, replayBody)
	}
	var auditCount int
	if err = db.Pool.QueryRow(ctx, `SELECT count(*) FROM audit_events WHERE organization_id=$1 AND action='cluster.enroll' AND resource_id=$2`, organizationID, clusterID.String()).Scan(&auditCount); err != nil || auditCount != 1 {
		t.Fatalf("enrollment audit count=%d err=%v", auditCount, err)
	}
}

func TestAgentCertificateRotationPromotesOnlyAfterReplacementAuthentication(t *testing.T) {
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
	now := time.Now().UTC()
	caPEM, caKey, err := agentpki.NewCA(now, 24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	clusterID, organizationID := uuid.New(), uuid.New()
	makeCSR := func(t *testing.T) ([]byte, *rsa.PrivateKey) {
		t.Helper()
		key, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			t.Fatal(err)
		}
		request, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{Subject: pkix.Name{CommonName: "dockyard-agent"}}, key)
		if err != nil {
			t.Fatal(err)
		}
		return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: request}), key
	}
	oldCSR, _ := makeCSR(t)
	_, oldCertificate, err := agentpki.SignAgentCSR(caPEM, caKey, oldCSR, clusterID, now, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	oldSerial := hex.EncodeToString(oldCertificate.SerialNumber.Bytes())
	if _, err = db.Pool.Exec(ctx, `INSERT INTO organizations(id,name,slug) VALUES($1,'Certificate rotation',$2)`, organizationID, "certificate-rotation-"+organizationID.String()); err == nil {
		_, err = db.Pool.Exec(ctx, `INSERT INTO clusters(id,organization_id,name,slug,state,certificate_serial,certificate_not_after,last_seen_at) VALUES($1,$2,'Remote','remote','active',$3,$4,now())`, clusterID, organizationID, oldSerial, oldCertificate.NotAfter)
	}
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = db.Pool.Exec(context.Background(), `DELETE FROM organizations WHERE id=$1`, organizationID)
	})
	rotationCSR, _ := makeCSR(t)
	body, _ := json.Marshal(map[string]string{"csr": string(rotationCSR)})
	request := httptest.NewRequest(http.MethodPost, "/v1/agent/rotate", bytes.NewReader(body))
	request.Header.Set("Content-Type", "application/json")
	request.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{oldCertificate}, VerifiedChains: [][]*x509.Certificate{{oldCertificate}}}
	recorder := httptest.NewRecorder()
	api := &Server{Store: db, AgentCACertificate: caPEM, AgentCAKey: caKey, AgentCertificateTTL: 7 * 24 * time.Hour}
	api.AgentHandler().ServeHTTP(recorder, request)
	if recorder.Code != http.StatusOK {
		t.Fatalf("rotate status=%d body=%s", recorder.Code, recorder.Body.String())
	}
	var rotated struct {
		Certificate string `json:"certificate"`
	}
	if err = json.Unmarshal(recorder.Body.Bytes(), &rotated); err != nil {
		t.Fatal(err)
	}
	block, _ := pem.Decode([]byte(rotated.Certificate))
	if block == nil {
		t.Fatal("rotation response did not contain a certificate")
	}
	newCertificate, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	newSerial := hex.EncodeToString(newCertificate.SerialNumber.Bytes())
	var currentSerial, pendingSerial string
	if err = db.Pool.QueryRow(ctx, `SELECT certificate_serial,pending_certificate_serial FROM clusters WHERE id=$1`, clusterID).Scan(&currentSerial, &pendingSerial); err != nil || currentSerial != oldSerial || pendingSerial != newSerial {
		t.Fatalf("issued rotation current=%q pending=%q err=%v", currentSerial, pendingSerial, err)
	}
	heartbeat := []byte(`{"agentVersion":"1.0.0","dockerVersion":"29.0.0","capacity":{}}`)
	request = httptest.NewRequest(http.MethodPost, "/v1/agent/heartbeat", bytes.NewReader(heartbeat))
	request.Header.Set("Content-Type", "application/json")
	request.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{newCertificate}, VerifiedChains: [][]*x509.Certificate{{newCertificate}}}
	recorder = httptest.NewRecorder()
	api.AgentHandler().ServeHTTP(recorder, request)
	if recorder.Code != http.StatusOK {
		t.Fatalf("replacement authentication status=%d body=%s", recorder.Code, recorder.Body.String())
	}
	request = httptest.NewRequest(http.MethodPost, "/v1/agent/heartbeat", bytes.NewReader(heartbeat))
	request.Header.Set("Content-Type", "application/json")
	request.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{oldCertificate}, VerifiedChains: [][]*x509.Certificate{{oldCertificate}}}
	recorder = httptest.NewRecorder()
	api.AgentHandler().ServeHTTP(recorder, request)
	if recorder.Code != http.StatusUnauthorized {
		t.Fatalf("superseded certificate status=%d body=%s", recorder.Code, recorder.Body.String())
	}
}

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
		{`INSERT INTO clusters(id,organization_id,name,slug,state,last_seen_at) VALUES($1,$2,'Remote','remote','active',now())`, []any{clusterID, organizationID}},
	} {
		if _, err = db.Pool.Exec(ctx, statement.query, statement.args...); err != nil {
			t.Fatal(err)
		}
	}
	t.Cleanup(func() {
		_, _ = db.Pool.Exec(context.Background(), `DELETE FROM organizations WHERE id=$1`, organizationID)
		_, _ = db.Pool.Exec(context.Background(), `DELETE FROM users WHERE id=$1`, userID)
	})
	otherOrganizationID, otherClusterID, otherCommandID := uuid.New(), uuid.New(), uuid.New()
	otherTarget := "registry.example/dockyard@sha256:" + strings.Repeat("f", 64)
	if _, err = db.Pool.Exec(ctx, `INSERT INTO organizations(id,name,slug) VALUES($1,'Other cluster upgrade',$2)`, otherOrganizationID, "other-cluster-upgrade-"+otherOrganizationID.String()); err == nil {
		_, err = db.Pool.Exec(ctx, `INSERT INTO clusters(id,organization_id,name,slug,state) VALUES($1,$2,'Other remote','other-remote','active')`, otherClusterID, otherOrganizationID)
	}
	if err == nil {
		_, err = db.Pool.Exec(ctx, `INSERT INTO cluster_commands(id,cluster_id,kind,encrypted_payload,status,target_image,last_error,finished_at) VALUES($1,$2,'agent.upgrade','other-command-secret','failed',$3,'other tenant failure',now())`, otherCommandID, otherClusterID, otherTarget)
	}
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = db.Pool.Exec(context.Background(), `DELETE FROM organizations WHERE id=$1`, otherOrganizationID)
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

	replacementTarget := "registry.example/dockyard@sha256:" + strings.Repeat("b", 64)
	status, body = clusterUpgradeRequest(t, httpServer.URL+"/v1/clusters/"+clusterID.String()+"/agent-upgrades", token, organizationID, http.MethodPost, map[string]string{"image": replacementTarget})
	if status != http.StatusConflict || !bytes.Contains(body, []byte(`"code":"agent_upgrade_running"`)) {
		t.Fatalf("duplicate status=%d body=%s", status, body)
	}
	status, body = clusterUpgradeRequest(t, httpServer.URL+"/v1/agent-upgrades?limit=20", token, organizationID, http.MethodGet, nil)
	var history struct {
		Items []store.ClusterCommand `json:"items"`
	}
	if err = json.Unmarshal(body, &history); status != http.StatusOK || err != nil || len(history.Items) != 1 || history.Items[0].ID != command.ID || bytes.Contains(body, []byte("other-command-secret")) || bytes.Contains(body, []byte(otherCommandID.String())) {
		t.Fatalf("history status=%d body=%s err=%v", status, body, err)
	}
	status, body = clusterUpgradeRequest(t, httpServer.URL+"/v1/agent-upgrades?limit=201", token, organizationID, http.MethodGet, nil)
	if status != http.StatusBadRequest || !bytes.Contains(body, []byte(`"code":"invalid_limit"`)) {
		t.Fatalf("invalid limit status=%d body=%s", status, body)
	}
	status, body = clusterUpgradeRequest(t, httpServer.URL+"/v1/clusters/"+otherClusterID.String()+"/agent-upgrades/"+otherCommandID.String(), token, organizationID, http.MethodDelete, nil)
	if status != http.StatusNotFound {
		t.Fatalf("cross-tenant cancellation status=%d body=%s", status, body)
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
	status, body = clusterUpgradeRequest(t, httpServer.URL+"/v1/clusters/"+clusterID.String()+"/agent-upgrades/"+command.ID.String(), token, organizationID, http.MethodDelete, nil)
	if status != http.StatusConflict || !bytes.Contains(body, []byte(`"code":"not_cancellable"`)) {
		t.Fatalf("in-flight cancellation status=%d body=%s", status, body)
	}

	for _, payload := range []string{
		`{"agentImage":"valid.example/agent:latest\nbad","agentUpdateState":"completed","capacity":{}}`,
		`{"agentImage":"valid.example/agent:latest","agentUpdateState":"unknown","capacity":{}}`,
		`{"agentVersion":"1.0\u0000bad","capacity":{}}`,
		`{"dockerVersion":"29.0\nbad","capacity":{}}`,
		`{"capacity":{"unknown":1}}`,
		`{"capacity":{"nodes":1.5}}`,
		`{"capacity":{"nodes":-1}}`,
		`{"capacity":{"nodes":1,"readyNodes":1,"activeNodes":1,"schedulableNodes":2}}`,
		`{"capacity":{"nodes":10001}}`,
		`{"capacity":{"nanoCpus":1}}`,
		`{"capacity":{},"capabilities":{"edgeProxy":{"provider":"traefik"}}}`,
	} {
		recorder := httptest.NewRecorder()
		request := httptest.NewRequest(http.MethodPost, "/v1/agent/heartbeat", strings.NewReader(payload))
		request.Header.Set("Content-Type", "application/json")
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

	status, body = clusterUpgradeRequest(t, httpServer.URL+"/v1/clusters/"+clusterID.String()+"/agent-upgrades", token, organizationID, http.MethodPost, map[string]string{"image": replacementTarget})
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
	postAgentHeartbeat(t, api, clusterID, map[string]any{"agentVersion": "2.0.0", "agentImage": replacementTarget, "agentUpdateState": "completed", "dockerVersion": "29.0.0", "capacity": map[string]any{"nodes": 3}})
	commandURL = httpServer.URL + "/v1/clusters/" + clusterID.String() + "/commands/" + command.ID.String()
	status, body = clusterUpgradeRequest(t, commandURL, token, organizationID, http.MethodGet, nil)
	if status != http.StatusOK || !bytes.Contains(body, []byte(`"status":"succeeded"`)) {
		t.Fatalf("converged status=%d body=%s", status, body)
	}

	cancelTarget := "registry.example/dockyard@sha256:" + strings.Repeat("d", 64)
	status, body = clusterUpgradeRequest(t, httpServer.URL+"/v1/clusters/"+clusterID.String()+"/agent-upgrades", token, organizationID, http.MethodPost, map[string]string{"image": cancelTarget})
	if status != http.StatusAccepted || json.Unmarshal(body, &command) != nil {
		t.Fatalf("cancellable queue status=%d body=%s", status, body)
	}
	cancelURL := httpServer.URL + "/v1/clusters/" + clusterID.String() + "/agent-upgrades/" + command.ID.String()
	status, body = clusterUpgradeRequest(t, cancelURL, token, organizationID, http.MethodDelete, nil)
	if status != http.StatusOK || !bytes.Contains(body, []byte(`"status":"cancelled"`)) {
		t.Fatalf("cancellation status=%d body=%s", status, body)
	}
	commandURL = httpServer.URL + "/v1/clusters/" + clusterID.String() + "/commands/" + command.ID.String()
	status, body = clusterUpgradeRequest(t, commandURL, token, organizationID, http.MethodGet, nil)
	if status != http.StatusOK || !bytes.Contains(body, []byte(`"status":"cancelled"`)) || !bytes.Contains(body, []byte("cancelled by user")) {
		t.Fatalf("cancelled command status=%d body=%s", status, body)
	}
	status, body = clusterUpgradeRequest(t, cancelURL, token, organizationID, http.MethodDelete, nil)
	if status != http.StatusConflict {
		t.Fatalf("repeat cancellation status=%d body=%s", status, body)
	}
	var auditCount int
	if err = db.Pool.QueryRow(ctx, `SELECT count(*) FROM audit_events WHERE organization_id=$1 AND action='cluster.agent.upgrade.cancel' AND resource_id=$2`, organizationID, command.ID.String()).Scan(&auditCount); err != nil || auditCount != 1 {
		t.Fatalf("cancellation audit count=%d err=%v", auditCount, err)
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
	request.Header.Set("Content-Type", "application/json")
	request = request.WithContext(context.WithValue(request.Context(), clusterIDKey, clusterID))
	api.agentHeartbeat(recorder, request)
	if recorder.Code != http.StatusOK {
		t.Fatalf("heartbeat status=%d body=%s", recorder.Code, recorder.Body.String())
	}
}
