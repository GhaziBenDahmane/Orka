package httpapi

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/GhaziBenDahmane/Orka/internal/cryptox"
	"github.com/GhaziBenDahmane/Orka/internal/store"
	"github.com/google/uuid"
)

func TestAgentHandlersRejectSupersededAuthenticatedCertificate(t *testing.T) {
	databaseURL := os.Getenv("DOCKYARD_TEST_DATABASE_URL")
	if databaseURL == "" {
		t.Skip("DOCKYARD_TEST_DATABASE_URL is not set")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	db, err := store.Open(ctx, databaseURL)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(db.Pool.Close)

	organizationID, clusterID := uuid.New(), uuid.New()
	if _, err = db.Pool.Exec(ctx, `INSERT INTO organizations(id,name,slug) VALUES($1,'Agent handler authority',$2)`, organizationID, "agent-handler-authority-"+organizationID.String()); err != nil {
		t.Fatal(err)
	}
	if _, err = db.Pool.Exec(ctx, `INSERT INTO clusters(id,organization_id,name,slug,state,certificate_serial,certificate_not_after,last_seen_at) VALUES($1,$2,'Remote','remote','active','current-serial',now()+interval '1 hour',now())`, clusterID, organizationID); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = db.Pool.Exec(context.Background(), `DELETE FROM organizations WHERE id=$1`, organizationID)
	})

	box, err := cryptox.New(bytes.Repeat([]byte{7}, 32))
	if err != nil {
		t.Fatal(err)
	}
	server := &Server{Store: db, Box: box}
	commandID, leaseID := uuid.New(), uuid.New()
	tests := []struct {
		name    string
		method  string
		path    string
		body    string
		handler http.HandlerFunc
	}{
		{name: "heartbeat", method: http.MethodPost, path: "/v1/agent/heartbeat", body: `{}`, handler: server.agentHeartbeat},
		{name: "claim", method: http.MethodGet, path: "/v1/agent/commands/next", handler: server.agentNextCommand},
		{name: "renew", method: http.MethodPost, path: "/v1/agent/commands/" + commandID.String() + "/lease", handler: server.agentRenewCommand},
		{name: "complete", method: http.MethodPost, path: "/v1/agent/commands/" + commandID.String() + "/complete", body: `{}`, handler: server.agentCompleteCommand},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			request := httptest.NewRequest(test.method, test.path, strings.NewReader(test.body))
			request.Header.Set("Content-Type", "application/json")
			request.Header.Set("X-Dockyard-Lease-ID", leaseID.String())
			request.SetPathValue("commandID", commandID.String())
			request = request.WithContext(context.WithValue(request.Context(), clusterIDKey, clusterID))
			request = request.WithContext(context.WithValue(request.Context(), clusterCertificateSerialKey, "superseded-serial"))
			recorder := httptest.NewRecorder()
			test.handler(recorder, request)
			if recorder.Code != http.StatusUnauthorized || !strings.Contains(recorder.Body.String(), `"code":"invalid_agent_certificate"`) {
				t.Fatalf("response=(%d, %q), want invalid certificate", recorder.Code, recorder.Body.String())
			}
		})
	}
}
