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

	"github.com/bendahma/dokploy-go/internal/agentpki"
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

	organizationID, accountID, clusterID := uuid.New(), uuid.New(), uuid.New()
	ownerID, ownerSessionID := uuid.New(), uuid.New()
	otherOrganizationID, otherAccountID, otherRunID, otherFindingID := uuid.New(), uuid.New(), uuid.New(), uuid.New()
	projectID, environmentID, serviceID := uuid.New(), uuid.New(), uuid.New()
	auditorToken := "dky_ai_conformance_" + uuid.NewString()
	ownerToken := "dky_ai_owner_conformance_" + uuid.NewString()
	secretMarker := "DO_NOT_EXPOSE_AI_CONFORMANCE_SECRET_" + uuid.NewString()
	activeAgentCA, _, err := agentpki.NewCA(time.Now(), 48*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	previousAgentCA, _, err := agentpki.NewCA(time.Now(), 48*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	previousAgentCAFingerprint, err := agentpki.CertificateFingerprint(previousAgentCA)
	if err != nil {
		t.Fatal(err)
	}
	statements := []struct {
		query string
		args  []any
	}{
		{`INSERT INTO organizations(id,name,slug) VALUES($1,'AI conformance',$2)`, []any{organizationID, "ai-conformance-" + organizationID.String()}},
		{`INSERT INTO organizations(id,name,slug) VALUES($1,'Other AI conformance',$2)`, []any{otherOrganizationID, "other-ai-conformance-" + otherOrganizationID.String()}},
		{`INSERT INTO users(id,email,password_hash) VALUES($1,$2,'!conformance')`, []any{ownerID, ownerID.String() + "@example.test"}},
		{`INSERT INTO sessions(id,user_id,token_hash,expires_at,auth_method) VALUES($1,$2,$3,now()+interval '1 day','local')`, []any{ownerSessionID, ownerID, cryptox.Digest(ownerToken)}},
		{`INSERT INTO service_accounts(id,organization_id,name,role,enabled) VALUES($1,$2,'conformance-auditor','auditor',true)`, []any{accountID, organizationID}},
		{`INSERT INTO service_account_tokens(id,service_account_id,token_hash,expires_at) VALUES($1,$2,$3,now()+interval '1 day')`, []any{uuid.New(), accountID, cryptox.Digest(auditorToken)}},
		{`INSERT INTO service_accounts(id,organization_id,name,role,enabled) VALUES($1,$2,'other-conformance-auditor','auditor',true)`, []any{otherAccountID, otherOrganizationID}},
		{`INSERT INTO ai_audit_runs(id,organization_id,service_account_id,agent_name,status) VALUES($1,$2,$3,'other-auditor','completed')`, []any{otherRunID, otherOrganizationID, otherAccountID}},
		{`INSERT INTO ai_audit_findings(id,run_id,severity,category,title,description,evidence,fingerprint) VALUES($1,$2,'low','isolation','Other tenant finding','Must remain unchanged','{}','other-tenant')`, []any{otherFindingID, otherRunID}},
		{`INSERT INTO projects(id,organization_id,name,slug) VALUES($1,$2,'Audited project','audited-project')`, []any{projectID, organizationID}},
		{`INSERT INTO environments(id,project_id,name,slug) VALUES($1,$2,'Production','production')`, []any{environmentID, projectID}},
		{`INSERT INTO compose_services(id,environment_id,name,slug,stack_name,compose_yaml,encrypted_env,revision) VALUES($1,$2,'Sensitive service','sensitive-service',$3,$4,$5,2)`, []any{serviceID, environmentID, "ai-conformance-" + serviceID.String(), "services: {app: {image: example.invalid/private, environment: [" + secretMarker + "]}}", "encrypted:" + secretMarker}},
		{`INSERT INTO clusters(id,organization_id,name,slug,state,certificate_ca_fingerprint,certificate_not_after,last_seen_at) VALUES($1,$2,'Legacy CA cluster','legacy-ca','active',$3,now()+interval '1 day',now())`, []any{clusterID, organizationID, previousAgentCAFingerprint}},
	}
	for _, statement := range statements {
		if _, err = db.Pool.Exec(ctx, statement.query, statement.args...); err != nil {
			t.Fatal(err)
		}
	}
	t.Cleanup(func() {
		_, _ = db.Pool.Exec(context.Background(), `DELETE FROM organizations WHERE id=$1`, organizationID)
		_, _ = db.Pool.Exec(context.Background(), `DELETE FROM organizations WHERE id=$1`, otherOrganizationID)
		_, _ = db.Pool.Exec(context.Background(), `DELETE FROM users WHERE id=$1`, ownerID)
	})

	platform := httptest.NewServer((&httpapi.Server{Store: db, AgentCACertificate: activeAgentCA, AgentPreviousCACertificate: previousAgentCA}).Handler())
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
	for _, title := range []string{"Organization has no active owner", "Mandatory SSO is disabled", "Remote cluster uses a non-active certificate authority", "Previous agent certificate authority remains trusted", "Desired service revision is not deployed", "Capacity requires review"} {
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
	if _, err = db.Pool.Exec(ctx, `INSERT INTO memberships(organization_id,user_id,role) VALUES($1,$2,'owner')`, organizationID, ownerID); err != nil {
		t.Fatal(err)
	}

	var findingID uuid.UUID
	if err = db.Pool.QueryRow(ctx, `SELECT id FROM ai_audit_findings WHERE run_id=$1 AND title='Capacity requires review'`, runID).Scan(&findingID); err != nil {
		t.Fatal(err)
	}
	if _, err = db.Pool.Exec(ctx, `
		CREATE FUNCTION reject_ai_triage_audit() RETURNS trigger LANGUAGE plpgsql AS $$
		BEGIN
			IF NEW.action LIKE 'ai_audit_finding.%' THEN
				RAISE EXCEPTION 'forced triage audit failure';
			END IF;
			RETURN NEW;
		END $$;
		CREATE TRIGGER reject_ai_triage_audit BEFORE INSERT ON audit_events
		FOR EACH ROW EXECUTE FUNCTION reject_ai_triage_audit()`); err != nil {
		t.Fatal(err)
	}
	dropAuditFailureTrigger := func() {
		_, _ = db.Pool.Exec(context.Background(), `DROP TRIGGER IF EXISTS reject_ai_triage_audit ON audit_events; DROP FUNCTION IF EXISTS reject_ai_triage_audit()`)
	}
	t.Cleanup(dropAuditFailureTrigger)
	if _, err = db.UpdateAIAuditFindingDisposition(ctx, store.Principal{UserID: ownerID, OrganizationID: organizationID, Role: "owner"}, findingID, "resolved", "must roll back", "127.0.0.1"); err == nil {
		t.Fatal("finding triage succeeded when its audit event was rejected")
	}
	var rolledBackDisposition string
	if err = db.Pool.QueryRow(ctx, `SELECT disposition FROM ai_audit_findings WHERE id=$1`, findingID).Scan(&rolledBackDisposition); err != nil || rolledBackDisposition != "open" {
		t.Fatalf("triage rollback disposition=%q err=%v", rolledBackDisposition, err)
	}
	dropAuditFailureTrigger()
	triage := func(token string, id uuid.UUID, body string) (int, []byte) {
		request, requestErr := http.NewRequestWithContext(ctx, http.MethodPatch, platform.URL+"/v1/ai/audit-findings/"+id.String(), strings.NewReader(body))
		if requestErr != nil {
			t.Fatal(requestErr)
		}
		request.Header.Set("Authorization", "Bearer "+token)
		request.Header.Set("X-Organization-ID", organizationID.String())
		request.Header.Set("Content-Type", "application/json")
		response, requestErr := http.DefaultClient.Do(request)
		if requestErr != nil {
			t.Fatal(requestErr)
		}
		data, readErr := io.ReadAll(response.Body)
		response.Body.Close()
		if readErr != nil {
			t.Fatal(readErr)
		}
		return response.StatusCode, data
	}
	triageStatus, triageBody := triage(ownerToken, findingID, `{"disposition":"acknowledged","note":"reviewed during conformance"}`)
	var triaged store.AIAuditFinding
	if err = json.Unmarshal(triageBody, &triaged); triageStatus != http.StatusOK || err != nil || triaged.Disposition != "acknowledged" || triaged.TriagedByUser == nil || *triaged.TriagedByUser != ownerID || triaged.TriagedAt == nil {
		t.Fatalf("owner triage status=%d finding=%#v body=%s err=%v", triageStatus, triaged, triageBody, err)
	}
	triageStatus, triageBody = triage(auditorToken, findingID, `{"disposition":"resolved"}`)
	if triageStatus != http.StatusForbidden || !bytes.Contains(triageBody, []byte(`"code":"forbidden"`)) {
		t.Fatalf("auditor triage status=%d body=%s", triageStatus, triageBody)
	}
	triageStatus, triageBody = triage(ownerToken, otherFindingID, `{"disposition":"resolved"}`)
	if triageStatus != http.StatusNotFound {
		t.Fatalf("cross-tenant triage status=%d body=%s", triageStatus, triageBody)
	}
	var otherDisposition string
	if err = db.Pool.QueryRow(ctx, `SELECT disposition FROM ai_audit_findings WHERE id=$1`, otherFindingID).Scan(&otherDisposition); err != nil || otherDisposition != "open" {
		t.Fatalf("other-tenant disposition=%q err=%v", otherDisposition, err)
	}
	var triageAuditEvents int
	if err = db.Pool.QueryRow(ctx, `SELECT count(*) FROM audit_events WHERE organization_id=$1 AND actor_user_id=$2 AND action='ai_audit_finding.acknowledged' AND resource_id=$3`, organizationID, ownerID, findingID.String()).Scan(&triageAuditEvents); err != nil || triageAuditEvents != 1 {
		t.Fatalf("AI finding triage audit events=%d err=%v", triageAuditEvents, err)
	}

	evidence, _ := json.Marshal(map[string]any{
		"status":                         "passed",
		"realPlatformAPI":                true,
		"openAICompatibleGateway":        true,
		"snapshotSecretsRedacted":        true,
		"promptInjectionBoundaryPresent": true,
		"deterministicFindingsPersisted": true,
		"agentCAMismatchDetected":        true,
		"modelFindingsPersisted":         true,
		"durableRunCompleted":            true,
		"lifecycleAudited":               true,
		"auditorLeastPrivilege":          true,
		"findingTriageAudited":           true,
		"findingTriageAtomic":            true,
		"auditorTriageDenied":            true,
		"triageTenantIsolated":           true,
	})
	fmt.Printf("AI_AUDIT_EVIDENCE %s\n", evidence)
}
