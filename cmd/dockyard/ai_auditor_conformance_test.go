package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/bendahma/dokploy-go/internal/cryptox"
	"github.com/bendahma/dokploy-go/internal/httpapi"
	"github.com/bendahma/dokploy-go/internal/store"
	"github.com/google/uuid"
)

func TestAIAuditorEndToEndConformance(t *testing.T) {
	if os.Getenv("DOCKYARD_AI_AUDIT_CONFORMANCE") == "" {
		t.Skip("DOCKYARD_AI_AUDIT_CONFORMANCE is not set")
	}
	databaseURL := os.Getenv("DOCKYARD_TEST_DATABASE_URL")
	if databaseURL == "" {
		t.Fatal("DOCKYARD_TEST_DATABASE_URL is required")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	db, err := store.Open(ctx, databaseURL)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(db.Pool.Close)

	organizationID, accountID := uuid.New(), uuid.New()
	projectID, environmentID, serviceID := uuid.New(), uuid.New(), uuid.New()
	auditorToken := "dky_ai_conformance_" + uuid.NewString()
	secretMarker := "DO_NOT_EXPOSE_AI_CONFORMANCE_SECRET_" + uuid.NewString()
	statements := []struct {
		query string
		args  []any
	}{
		{`INSERT INTO organizations(id,name,slug) VALUES($1,'AI conformance',$2)`, []any{organizationID, "ai-conformance-" + organizationID.String()}},
		{`INSERT INTO service_accounts(id,organization_id,name,role,enabled) VALUES($1,$2,'conformance-auditor','auditor',true)`, []any{accountID, organizationID}},
		{`INSERT INTO service_account_tokens(id,service_account_id,token_hash,expires_at) VALUES($1,$2,$3,now()+interval '1 day')`, []any{uuid.New(), accountID, cryptox.Digest(auditorToken)}},
		{`INSERT INTO projects(id,organization_id,name,slug) VALUES($1,$2,'Audited project','audited-project')`, []any{projectID, organizationID}},
		{`INSERT INTO environments(id,project_id,name,slug) VALUES($1,$2,'Production','production')`, []any{environmentID, projectID}},
		{`INSERT INTO compose_services(id,environment_id,name,slug,stack_name,compose_yaml,encrypted_env,revision) VALUES($1,$2,'Sensitive service','sensitive-service',$3,$4,$5,2)`, []any{serviceID, environmentID, "ai-conformance-" + serviceID.String(), "services: {app: {image: example.invalid/private, environment: [" + secretMarker + "]}}", "encrypted:" + secretMarker}},
	}
	for _, statement := range statements {
		if _, err = db.Pool.Exec(ctx, statement.query, statement.args...); err != nil {
			t.Fatal(err)
		}
	}
	t.Cleanup(func() {
		_, _ = db.Pool.Exec(context.Background(), `DELETE FROM organizations WHERE id=$1`, organizationID)
	})

	platform := httptest.NewServer((&httpapi.Server{Store: db}).Handler())
	defer platform.Close()
	modelCalled := false
	model := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/v1/chat/completions" {
			http.Error(w, "unexpected model request", http.StatusNotFound)
			return
		}
		if r.Header.Get("Authorization") != "Bearer model-conformance-token" {
			http.Error(w, "missing model authorization", http.StatusUnauthorized)
			return
		}
		body, readErr := io.ReadAll(io.LimitReader(r.Body, 2<<20))
		if readErr != nil {
			t.Error(readErr)
			http.Error(w, "read failed", http.StatusBadRequest)
			return
		}
		if bytes.Contains(body, []byte(secretMarker)) {
			t.Error("workload secret reached the model request")
			http.Error(w, "secret exposed", http.StatusBadRequest)
			return
		}
		if !bytes.Contains(body, []byte("SNAPSHOT_DATA_BEGIN")) || !bytes.Contains(body, []byte(serviceID.String())) || !bytes.Contains(body, []byte("untrusted data")) {
			t.Error("model request did not contain the bounded platform snapshot and trust instruction")
			http.Error(w, "incomplete prompt", http.StatusBadRequest)
			return
		}
		modelCalled = true
		_ = json.NewEncoder(w).Encode(map[string]any{"choices": []any{map[string]any{"message": map[string]string{"content": `{"summary":"Conformance audit completed","findings":[{"severity":"medium","category":"capacity","title":"Capacity requires review","description":"The service has no recorded deployment capacity evidence.","resourceType":"service","resourceId":"` + serviceID.String() + `","evidence":{"source":"model-conformance"},"remediation":"Record a successful deployment and capacity observation."}]}`}}}})
	}))
	defer model.Close()

	cfg := auditorConfig{
		DockyardURL:   platform.URL,
		DockyardToken: auditorToken,
		ModelURL:      model.URL + "/v1",
		ModelToken:    "model-conformance-token",
		Model:         "conformance-model",
		AgentName:     "conformance-auditor",
		AgentVersion:  "conformance",
		Focus:         "security, availability, backups, and migration readiness",
	}
	if err = performAIAudit(ctx, &http.Client{Timeout: 10 * time.Second}, cfg); err != nil {
		t.Fatal(err)
	}
	if !modelCalled {
		t.Fatal("OpenAI-compatible model endpoint was not called")
	}

	request, err := http.NewRequestWithContext(ctx, http.MethodGet, platform.URL+"/v1/projects", nil)
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Authorization", "Bearer "+auditorToken)
	response, err := http.DefaultClient.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	deniedBody, readErr := io.ReadAll(response.Body)
	response.Body.Close()
	if readErr != nil || response.StatusCode != http.StatusForbidden || !bytes.Contains(deniedBody, []byte(`"code":"auditor_scope"`)) {
		t.Fatalf("auditor workload access status=%d body=%s err=%v", response.StatusCode, deniedBody, readErr)
	}

	var runID uuid.UUID
	var status, summary string
	if err = db.Pool.QueryRow(ctx, `SELECT id,status,summary FROM ai_audit_runs WHERE organization_id=$1 AND service_account_id=$2 ORDER BY started_at DESC LIMIT 1`, organizationID, accountID).Scan(&runID, &status, &summary); err != nil {
		t.Fatal(err)
	}
	if status != "completed" || !strings.Contains(summary, "Conformance audit completed") || !strings.Contains(summary, "Deterministic baseline:") {
		t.Fatalf("audit run status=%q summary=%q", status, summary)
	}
	rows, err := db.Pool.Query(ctx, `SELECT title FROM ai_audit_findings WHERE run_id=$1`, runID)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	titles := map[string]bool{}
	for rows.Next() {
		var title string
		if err = rows.Scan(&title); err != nil {
			t.Fatal(err)
		}
		titles[title] = true
	}
	if err = rows.Err(); err != nil {
		t.Fatal(err)
	}
	for _, title := range []string{"Organization has no active owner", "Mandatory SSO is disabled", "Desired service revision is not deployed", "Capacity requires review"} {
		if !titles[title] {
			t.Errorf("missing persisted finding %q in %#v", title, titles)
		}
	}
	var auditEvents int
	if err = db.Pool.QueryRow(ctx, `SELECT count(*) FROM audit_events WHERE organization_id=$1 AND actor_service_account_id=$2 AND action IN ('ai_audit.start','ai_audit.completed')`, organizationID, accountID).Scan(&auditEvents); err != nil {
		t.Fatal(err)
	}
	if auditEvents != 2 {
		t.Fatalf("AI audit lifecycle events=%d, want 2", auditEvents)
	}

	evidence, _ := json.Marshal(map[string]any{
		"status":                         "passed",
		"realPlatformAPI":                true,
		"openAICompatibleGateway":        true,
		"snapshotSecretsRedacted":        true,
		"promptInjectionBoundaryPresent": true,
		"deterministicFindingsPersisted": true,
		"modelFindingsPersisted":         true,
		"durableRunCompleted":            true,
		"lifecycleAudited":               true,
		"auditorLeastPrivilege":          true,
	})
	fmt.Printf("AI_AUDIT_EVIDENCE %s\n", evidence)
}
