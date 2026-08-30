package main

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/bendahma/dokploy-go/internal/store"
	"github.com/google/uuid"
)

func TestPerformAIAuditLifecycle(t *testing.T) {
	var mutex sync.Mutex
	paths := []string{}
	platform := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer auditor-token" {
			t.Errorf("missing auditor token")
		}
		mutex.Lock()
		paths = append(paths, r.Method+" "+r.URL.Path)
		mutex.Unlock()
		switch r.URL.Path {
		case "/v1/ai/audit-snapshot":
			_ = json.NewEncoder(w).Encode(map[string]any{"projects": []any{}, "identityPosture": map[string]any{"requireSso": true, "activeOwners": 1}})
		case "/v1/ai/audit-runs":
			w.WriteHeader(http.StatusCreated)
			_ = json.NewEncoder(w).Encode(map[string]string{"id": "00000000-0000-0000-0000-000000000001"})
		default:
			if r.Method == http.MethodPost {
				w.WriteHeader(http.StatusCreated)
			} else {
				w.WriteHeader(http.StatusNoContent)
			}
		}
	}))
	defer platform.Close()
	model := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/chat/completions" {
			t.Errorf("model path=%s", r.URL.Path)
		}
		var request struct {
			Messages []struct {
				Role    string `json:"role"`
				Content string `json:"content"`
			} `json:"messages"`
		}
		if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
			t.Error(err)
		} else if len(request.Messages) != 2 || !strings.Contains(request.Messages[0].Content, "untrusted data") || !strings.Contains(request.Messages[1].Content, "SNAPSHOT_DATA_BEGIN") {
			t.Errorf("model prompt does not preserve the snapshot trust boundary: %#v", request.Messages)
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"choices": []any{map[string]any{"message": map[string]string{"content": `{"summary":"healthy","findings":[{"severity":"low","category":"capacity","title":"No projects","description":"Inventory is empty","resourceType":"organization","resourceId":"org","evidence":{},"remediation":"Create a project"}]}`}}}})
	}))
	defer model.Close()
	cfg := auditorConfig{DockyardURL: platform.URL, DockyardToken: "auditor-token", ModelURL: model.URL + "/v1", Model: "test", AgentName: "test-agent", Focus: "capacity", Interval: time.Hour}
	if err := performAIAudit(context.Background(), &http.Client{Timeout: time.Second}, cfg); err != nil {
		t.Fatal(err)
	}
	want := []string{"GET /v1/ai/audit-snapshot", "POST /v1/ai/audit-runs", "POST /v1/ai/audit-runs/00000000-0000-0000-0000-000000000001/findings", "PATCH /v1/ai/audit-runs/00000000-0000-0000-0000-000000000001"}
	if len(paths) != len(want) {
		t.Fatalf("paths=%v", paths)
	}
	for i := range want {
		if paths[i] != want[i] {
			t.Fatalf("paths=%v", paths)
		}
	}
}

func TestDeterministicAuditFindingsCoverCriticalPosture(t *testing.T) {
	now := time.Now().UTC()
	organizationID, databaseID, clusterID, repositoryID, serviceID := uuid.New(), uuid.New(), uuid.New(), uuid.New(), uuid.New()
	staleHeartbeat, expiringCertificate := now.Add(-3*time.Minute), now.Add(6*24*time.Hour)
	snapshot := store.AIAuditSnapshot{
		Organization:    organizationID,
		IdentityPosture: store.AIAuditIdentityPosture{},
		MigrationPosture: []store.AIAuditMigrationPosture{{
			SourceOrganizationID: "legacy", Resources: 4, Imported: 2, Unresolved: 2, Databases: 1,
		}},
		BackupPosture:        []store.AIAuditBackupPosture{{DatabaseID: databaseID, Engine: "postgres"}},
		Clusters:             []store.Cluster{{ID: clusterID, State: "active", LastSeenAt: &staleHeartbeat, CertificateNotAfter: &expiringCertificate}},
		AgentUpgradePosture:  []store.AIAuditAgentUpgradePosture{{ClusterID: clusterID, Status: "verifying", VerificationOverdue: true, TargetImage: "registry.example/dockyard@sha256:test"}},
		TemplateRepositories: []store.AIAuditTemplateRepositoryInfo{{ID: repositoryID, Enabled: true, GitRef: "main", LastSyncStatus: "failed"}},
		ServiceDeployments:   []store.AIAuditServiceDeployment{{ServiceID: serviceID, DesiredRevision: 2, LatestDeploymentRevision: 1, LatestDeploymentStatus: "succeeded"}},
		Reconciliation:       []store.ServiceReconciliation{{ComposeServiceID: serviceID, State: "degraded", ConsecutiveFailures: 2, LastCheckedAt: now}},
	}
	findings := deterministicAuditFindings(snapshot, now)
	titles := map[string]bool{}
	for _, finding := range findings {
		titles[finding.Title] = true
	}
	for _, title := range []string{"Organization has no active owner", "Mandatory SSO is disabled", "Dokploy migration has unresolved resources", "Dokploy database transfers are incomplete", "Database has no backup policy", "Remote cluster heartbeat is stale", "Remote cluster certificate expires soon", "Remote agent upgrade requires intervention", "Template repository does not require signatures", "Template repository synchronization failed", "Desired service revision is not deployed", "Swarm service reconciliation is unhealthy"} {
		if !titles[title] {
			t.Errorf("missing deterministic finding %q in %#v", title, findings)
		}
	}
	if len(findings) != 12 {
		t.Fatalf("findings=%d, want 12: %#v", len(findings), findings)
	}
}

func TestDeterministicAuditFindingsAreBounded(t *testing.T) {
	snapshot := store.AIAuditSnapshot{IdentityPosture: store.AIAuditIdentityPosture{RequireSSO: true, ActiveOwners: 1}}
	for range maxDeterministicAuditFindings + 10 {
		snapshot.BackupPosture = append(snapshot.BackupPosture, store.AIAuditBackupPosture{DatabaseID: uuid.New(), Engine: "postgres"})
	}
	findings := deterministicAuditFindings(snapshot, time.Now())
	if len(findings) != maxDeterministicAuditFindings || findings[len(findings)-1].Title != "Deterministic audit findings were truncated" {
		t.Fatalf("bounded findings=%d last=%#v", len(findings), findings[len(findings)-1])
	}
}

func TestPerformAIAuditPreservesBaselineWhenModelFails(t *testing.T) {
	var finding modelFinding
	var completion map[string]string
	paths := []string{}
	platform := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		paths = append(paths, r.Method+" "+r.URL.Path)
		switch {
		case r.URL.Path == "/v1/ai/audit-snapshot":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"identityPosture":  map[string]any{"requireSso": true, "activeOwners": 1},
				"migrationPosture": []map[string]any{{"sourceOrganizationId": "legacy", "resources": 2, "imported": 1, "unresolved": 1}},
			})
		case r.URL.Path == "/v1/ai/audit-runs":
			w.WriteHeader(http.StatusCreated)
			_ = json.NewEncoder(w).Encode(map[string]string{"id": "00000000-0000-0000-0000-000000000001"})
		case r.Method == http.MethodPost:
			if err := json.NewDecoder(r.Body).Decode(&finding); err != nil {
				t.Error(err)
			}
			w.WriteHeader(http.StatusCreated)
		case r.Method == http.MethodPatch:
			if err := json.NewDecoder(r.Body).Decode(&completion); err != nil {
				t.Error(err)
			}
			w.WriteHeader(http.StatusNoContent)
		}
	}))
	defer platform.Close()
	model := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "gateway-secret-response", http.StatusServiceUnavailable)
	}))
	defer model.Close()
	cfg := auditorConfig{DockyardURL: platform.URL, DockyardToken: "auditor-token", ModelURL: model.URL + "/v1", Model: "test", AgentName: "test-agent", Focus: "migration"}
	err := performAIAudit(context.Background(), &http.Client{Timeout: time.Second}, cfg)
	if err == nil || !strings.Contains(err.Error(), "HTTP 503") {
		t.Fatalf("model failure=%v", err)
	}
	if finding.Category != "migration" || finding.ResourceID != "legacy" || completion["status"] != "failed" || !strings.Contains(completion["summary"], "baseline recorded 1 findings") || strings.Contains(completion["summary"], "gateway-secret-response") {
		t.Fatalf("finding=%#v completion=%#v", finding, completion)
	}
	want := []string{"GET /v1/ai/audit-snapshot", "POST /v1/ai/audit-runs", "POST /v1/ai/audit-runs/00000000-0000-0000-0000-000000000001/findings", "PATCH /v1/ai/audit-runs/00000000-0000-0000-0000-000000000001"}
	if strings.Join(paths, "|") != strings.Join(want, "|") {
		t.Fatalf("paths=%v", paths)
	}
}

func TestValidateModelReportRejectsUnboundedOrMalformedOutput(t *testing.T) {
	valid := modelReport{Summary: "healthy", Findings: []modelFinding{{Severity: "HIGH", Category: " backup ", Title: " Missing backup ", Description: "No recent backup", Evidence: nil}}}
	if err := validateModelReport(&valid); err != nil {
		t.Fatal(err)
	}
	if valid.Findings[0].Severity != "high" || valid.Findings[0].Category != "backup" || valid.Findings[0].Evidence == nil {
		t.Fatalf("report was not normalized: %#v", valid)
	}
	tests := []modelReport{
		{Summary: ""},
		{Summary: strings.Repeat("x", 8001)},
		{Summary: "invalid severity", Findings: []modelFinding{{Severity: "urgent", Category: "security", Title: "Issue", Description: "Description"}}},
		{Summary: "missing title", Findings: []modelFinding{{Severity: "high", Category: "security", Description: "Description"}}},
	}
	for index := range tests {
		if err := validateModelReport(&tests[index]); err == nil {
			t.Fatalf("case %d accepted invalid report %#v", index, tests[index])
		}
	}
	tooMany := modelReport{Summary: "too many", Findings: make([]modelFinding, maxAuditFindings+1)}
	if err := validateModelReport(&tooMany); err == nil {
		t.Fatal("accepted too many model findings")
	}
}
