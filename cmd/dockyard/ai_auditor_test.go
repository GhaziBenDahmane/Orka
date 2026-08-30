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
			_ = json.NewEncoder(w).Encode(map[string]any{"projects": []any{}, "identityPosture": map[string]any{"requireSso": true, "activeOwners": 1}, "notificationPosture": fullyCoveredNotifications()})
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

func TestNormalizedAuditorEndpoint(t *testing.T) {
	for _, test := range []struct {
		name      string
		raw       string
		allowPath bool
		want      string
	}{
		{name: "control", raw: " https://dockyard.example.test/ ", want: "https://dockyard.example.test"},
		{name: "model", raw: "http://9router:20128/v1/", allowPath: true, want: "http://9router:20128/v1"},
		{name: "private model", raw: "http://10.20.30.40:20128/v1", allowPath: true, want: "http://10.20.30.40:20128/v1"},
	} {
		got, err := normalizedAuditorEndpoint(test.name, test.raw, test.allowPath)
		if err != nil || got != test.want {
			t.Errorf("normalizedAuditorEndpoint(%q)=%q, %v; want %q", test.raw, got, err, test.want)
		}
	}
	for _, test := range []struct {
		raw       string
		allowPath bool
	}{
		{raw: ""}, {raw: "ftp://dockyard.example.test"},
		{raw: "https://token@dockyard.example.test"}, {raw: "https://dockyard.example.test?target=evil"},
		{raw: "https://dockyard.example.test#fragment"}, {raw: "https://dockyard.example.test/prefix"},
		{raw: "//dockyard.example.test"}, {raw: "http://models.example.test", allowPath: true},
	} {
		if _, err := normalizedAuditorEndpoint("endpoint", test.raw, test.allowPath); err == nil {
			t.Errorf("accepted unsafe endpoint %q", test.raw)
		}
	}
}

func TestPerformAIAuditRefusesCredentialBearingRedirects(t *testing.T) {
	t.Run("control plane", func(t *testing.T) {
		redirectedRequests := 0
		target := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
			redirectedRequests++
		}))
		defer target.Close()
		platform := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			http.Redirect(w, r, target.URL, http.StatusTemporaryRedirect)
		}))
		defer platform.Close()

		err := performAIAudit(context.Background(), platform.Client(), auditorConfig{
			DockyardURL: platform.URL, DockyardToken: "control-plane-secret",
		})
		if err == nil || !strings.Contains(err.Error(), "redirects are disabled") {
			t.Fatalf("redirect error=%v", err)
		}
		if redirectedRequests != 0 {
			t.Fatalf("redirect target received %d credential-bearing request(s)", redirectedRequests)
		}
	})

	t.Run("model gateway", func(t *testing.T) {
		redirectedRequests := 0
		target := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
			redirectedRequests++
		}))
		defer target.Close()
		model := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			http.Redirect(w, r, target.URL, http.StatusTemporaryRedirect)
		}))
		defer model.Close()
		platform := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			switch r.URL.Path {
			case "/v1/ai/audit-snapshot":
				_ = json.NewEncoder(w).Encode(map[string]any{"identityPosture": map[string]any{"requireSso": true, "activeOwners": 1}})
			case "/v1/ai/audit-runs":
				w.WriteHeader(http.StatusCreated)
				_ = json.NewEncoder(w).Encode(map[string]string{"id": "00000000-0000-0000-0000-000000000001"})
			default:
				w.WriteHeader(http.StatusNoContent)
			}
		}))
		defer platform.Close()

		err := performAIAudit(context.Background(), &http.Client{Timeout: time.Second}, auditorConfig{
			DockyardURL: platform.URL, DockyardToken: "control-plane-secret",
			ModelURL: model.URL, ModelToken: "model-secret", Model: "test", Focus: "security",
		})
		if err == nil || !strings.Contains(err.Error(), "redirects are disabled") {
			t.Fatalf("redirect error=%v", err)
		}
		if redirectedRequests != 0 {
			t.Fatalf("redirect target received %d credential-bearing request(s)", redirectedRequests)
		}
	})
}

func TestDeterministicAuditFindingsCoverCriticalPosture(t *testing.T) {
	now := time.Now().UTC()
	organizationID, databaseID, clusterID, repositoryID, serviceID := uuid.New(), uuid.New(), uuid.New(), uuid.New(), uuid.New()
	staleHeartbeat, expiringCertificate := now.Add(-3*time.Minute), now.Add(6*24*time.Hour)
	stalledSAMLRotation := now.Add(-8 * 24 * time.Hour)
	oldSCIMToken, oldPendingJob := now.Add(-181*24*time.Hour), now.Add(-11*time.Minute)
	snapshot := store.AIAuditSnapshot{
		Organization:    organizationID,
		IdentityPosture: store.AIAuditIdentityPosture{PendingSAMLCertificateRotations: 1, OldestPendingSAMLRotationAt: &stalledSAMLRotation, ExpiringServiceAccounts: 2, ActiveSCIMTokens: 1, OldestActiveSCIMTokenCreatedAt: &oldSCIMToken},
		MigrationPosture: []store.AIAuditMigrationPosture{{
			SourceOrganizationID: "legacy", Resources: 4, Imported: 2, Unresolved: 2, Databases: 1,
		}},
		BackupPosture:        []store.AIAuditBackupPosture{{DatabaseID: databaseID, Engine: "postgres"}},
		VolumeBackupPosture:  []store.AIAuditVolumeBackupPosture{{ServiceID: serviceID, VolumeName: "uploads"}},
		Clusters:             []store.Cluster{{ID: clusterID, State: "active", LastSeenAt: &staleHeartbeat, CertificateAuthorityFingerprint: "sha256:old", PendingCertificateAuthorityFingerprint: "sha256:new", CertificateNotAfter: &expiringCertificate}},
		AgentCAPosture:       store.AIAuditAgentCAPosture{Configured: true, ActiveFingerprint: "sha256:new", PreviousFingerprint: "sha256:old", RolloverActive: true},
		AgentUpgradePosture:  []store.AIAuditAgentUpgradePosture{{ClusterID: clusterID, Status: "verifying", VerificationOverdue: true, TargetImage: "registry.example/dockyard@sha256:test"}},
		TemplateRepositories: []store.AIAuditTemplateRepositoryInfo{{ID: repositoryID, Enabled: true, GitRef: "main", LastSyncStatus: "failed"}},
		NotificationPosture:  []store.AIAuditNotificationPosture{{Enabled: true, Events: []string{"deployment.failed"}}},
		QueuePosture:         store.AIAuditQueuePosture{PendingServiceJobs: 1, PendingDatabaseJobs: 1, OldestPendingAt: &oldPendingJob},
		ServiceDeployments:   []store.AIAuditServiceDeployment{{ServiceID: serviceID, DesiredRevision: 2, LatestDeploymentRevision: 1, LatestDeploymentStatus: "succeeded"}},
		Reconciliation:       []store.ServiceReconciliation{{ComposeServiceID: serviceID, State: "degraded", ConsecutiveFailures: 2, LastCheckedAt: now}},
	}
	findings := deterministicAuditFindings(snapshot, now)
	titles := map[string]bool{}
	for _, finding := range findings {
		titles[finding.Title] = true
	}
	for _, title := range []string{"Organization has no active owner", "Mandatory SSO is disabled", "SAML certificate rotation is stalled", "Service account credentials expire soon", "Long-lived SCIM credential requires rotation", "Dokploy migration has unresolved resources", "Dokploy database transfers are incomplete", "Database has no backup policy", "Volume backup policy is disabled", "Protected volume has no storage-node binding", "Volume lacks a successful backup", "Volume backups do not pause writers", "Volume restore has not been validated", "Remote cluster heartbeat is stale", "Remote cluster certificate expires soon", "Remote cluster uses a non-active certificate authority", "Previous agent certificate authority remains trusted", "Remote agent upgrade requires intervention", "Template repository does not require signatures", "Template repository synchronization failed", "Deployment queue is stalled", "Failure notifications have coverage gaps", "Desired service revision is not deployed", "Swarm service reconciliation is unhealthy"} {
		if !titles[title] {
			t.Errorf("missing deterministic finding %q in %#v", title, findings)
		}
	}
	if len(findings) != 24 {
		t.Fatalf("findings=%d, want 24: %#v", len(findings), findings)
	}
}

func TestDeterministicAuditDetectsTemplateRepositoryFreshness(t *testing.T) {
	now := time.Now().UTC()
	stale, fresh := now.Add(-3*time.Hour), now.Add(-30*time.Minute)
	tests := []struct {
		name     string
		lastSync *time.Time
		want     string
	}{
		{name: "never synchronized", want: "Template repository has never synchronized"},
		{name: "stale", lastSync: &stale, want: "Template repository synchronization is stale"},
		{name: "fresh", lastSync: &fresh},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			snapshot := store.AIAuditSnapshot{
				Organization:         uuid.New(),
				IdentityPosture:      store.AIAuditIdentityPosture{RequireSSO: true, ActiveOwners: 1},
				NotificationPosture:  fullyCoveredNotifications(),
				TemplateRepositories: []store.AIAuditTemplateRepositoryInfo{{ID: uuid.New(), Enabled: true, GitRef: "main", RequireSignature: true, SyncIntervalSeconds: 3600, LastSyncStatus: "succeeded", LastSyncedAt: test.lastSync}},
			}
			findings := deterministicAuditFindings(snapshot, now)
			if test.want == "" && len(findings) != 0 || test.want != "" && (len(findings) != 1 || findings[0].Title != test.want) {
				t.Fatalf("findings=%#v", findings)
			}
		})
	}
}

func TestDeterministicAuditDetectsUnavailableAndUnprotectedDatabaseEngines(t *testing.T) {
	now := time.Now().UTC()
	unsupportedID, missingID, protectedID := uuid.New(), uuid.New(), uuid.New()
	digest := "sha256:" + strings.Repeat("a", 64)
	snapshot := store.AIAuditSnapshot{
		Organization:        uuid.New(),
		IdentityPosture:     store.AIAuditIdentityPosture{RequireSSO: true, ActiveOwners: 1},
		NotificationPosture: fullyCoveredNotifications(),
		DatabaseEngines:     []store.AIAuditDatabaseEngineInfo{{Name: "postgres", Source: "built-in", BackupCapable: true, BackupExtension: "dump"}, {Name: "custom", Source: "external", ArtifactDigest: digest}},
		Databases:           []store.DatabaseInstance{{ID: unsupportedID, Engine: "custom", Version: "1", DriverSource: "external", DriverDigest: digest}, {ID: missingID, Engine: "removed", Version: "2", DriverSource: "external", DriverDigest: digest}, {ID: protectedID, Engine: "postgres", Version: "17", DriverSource: "built-in"}},
		BackupPosture:       []store.AIAuditBackupPosture{{DatabaseID: unsupportedID, Engine: "custom"}, {DatabaseID: missingID, Engine: "removed"}, {DatabaseID: protectedID, Engine: "postgres"}},
	}
	findings := deterministicAuditFindings(snapshot, now)
	titles := map[string]int{}
	resources := map[string]bool{}
	for _, finding := range findings {
		titles[finding.Title]++
		resources[finding.ResourceID] = true
	}
	if titles["Database engine has no recovery support"] != 1 || titles["Database engine is unavailable"] != 1 || titles["Database has no backup policy"] != 1 {
		t.Fatalf("database engine findings=%#v", findings)
	}
	for _, id := range []uuid.UUID{unsupportedID, missingID, protectedID} {
		if !resources[id.String()] {
			t.Errorf("database %s has no finding", id)
		}
	}
}

func TestDeterministicAuditDetectsDatabaseDriverIdentityDrift(t *testing.T) {
	now := time.Now().UTC()
	unboundID, mismatchID := uuid.New(), uuid.New()
	digest := "sha256:" + strings.Repeat("a", 64)
	snapshot := store.AIAuditSnapshot{
		Organization:        uuid.New(),
		IdentityPosture:     store.AIAuditIdentityPosture{RequireSSO: true, ActiveOwners: 1},
		NotificationPosture: fullyCoveredNotifications(),
		DatabaseEngines:     []store.AIAuditDatabaseEngineInfo{{Name: "custom", Source: "external", ArtifactDigest: digest, BackupCapable: true, BackupExtension: "dump"}},
		Databases:           []store.DatabaseInstance{{ID: unboundID, Engine: "custom", Version: "1", DriverSource: "unbound"}, {ID: mismatchID, Engine: "custom", Version: "1", DriverSource: "external", DriverDigest: "sha256:" + strings.Repeat("b", 64)}},
		BackupPosture:       []store.AIAuditBackupPosture{{DatabaseID: unboundID, Engine: "custom"}, {DatabaseID: mismatchID, Engine: "custom"}},
	}
	findings := deterministicAuditFindings(snapshot, now)
	titles := map[string]int{}
	for _, finding := range findings {
		titles[finding.Title]++
	}
	if titles["Database driver identity is unbound"] != 1 || titles["Database driver identity mismatch"] != 1 || len(findings) != 2 {
		t.Fatalf("driver identity findings=%#v", findings)
	}
}

func TestDeterministicAuditAcceptsClusterOnActiveCertificateAuthority(t *testing.T) {
	now := time.Now().UTC()
	snapshot := store.AIAuditSnapshot{
		Organization:    uuid.New(),
		IdentityPosture: store.AIAuditIdentityPosture{RequireSSO: true, ActiveOwners: 1},
		AgentCAPosture:  store.AIAuditAgentCAPosture{Configured: true, ActiveFingerprint: "sha256:active"},
		Clusters:        []store.Cluster{{ID: uuid.New(), State: "active", CertificateAuthorityFingerprint: "sha256:active", LastSeenAt: &now}},
	}
	for _, finding := range deterministicAuditFindings(snapshot, now) {
		if finding.Title == "Remote cluster uses a non-active certificate authority" || finding.Title == "Previous agent certificate authority remains trusted" {
			t.Fatalf("healthy CA posture produced finding: %#v", finding)
		}
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
				"identityPosture":     map[string]any{"requireSso": true, "activeOwners": 1},
				"migrationPosture":    []map[string]any{{"sourceOrganizationId": "legacy", "resources": 2, "imported": 1, "unresolved": 1}},
				"notificationPosture": []map[string]any{{"enabled": true, "events": []string{"deployment.failed", "backup.failed", "restore.failed", "restore.drill.failed", "database.migration.failed", "audit.archive.failed", "ai.audit.failed", "ai.finding.critical"}}},
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

func TestPerformAIAuditFinalizesRunAfterContextDeadline(t *testing.T) {
	var mutex sync.Mutex
	completion := map[string]string{}
	platform := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/v1/ai/audit-snapshot":
			_ = json.NewEncoder(w).Encode(map[string]any{"identityPosture": map[string]any{"requireSso": true, "activeOwners": 1}, "notificationPosture": fullyCoveredNotifications()})
		case r.URL.Path == "/v1/ai/audit-runs":
			w.WriteHeader(http.StatusCreated)
			_ = json.NewEncoder(w).Encode(map[string]string{"id": "00000000-0000-0000-0000-000000000001"})
		case r.Method == http.MethodPatch:
			mutex.Lock()
			defer mutex.Unlock()
			if err := json.NewDecoder(r.Body).Decode(&completion); err != nil {
				t.Error(err)
			}
			w.WriteHeader(http.StatusNoContent)
		default:
			t.Errorf("unexpected platform request %s %s", r.Method, r.URL.Path)
			http.Error(w, "unexpected request", http.StatusNotFound)
		}
	}))
	defer platform.Close()
	model := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-r.Context().Done():
		case <-time.After(200 * time.Millisecond):
		}
	}))
	defer model.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	cfg := auditorConfig{DockyardURL: platform.URL, DockyardToken: "auditor-token", ModelURL: model.URL + "/v1", Model: "test", AgentName: "test-agent", Focus: "reliability"}
	err := performAIAudit(ctx, &http.Client{Timeout: time.Second}, cfg)
	if err == nil || !strings.Contains(err.Error(), "context deadline exceeded") {
		t.Fatalf("deadline failure=%v", err)
	}
	mutex.Lock()
	defer mutex.Unlock()
	if completion["status"] != "failed" || !strings.Contains(completion["summary"], "context deadline exceeded") {
		t.Fatalf("completion=%#v", completion)
	}
}

func fullyCoveredNotifications() []store.AIAuditNotificationPosture {
	return []store.AIAuditNotificationPosture{{Enabled: true, Events: []string{
		"deployment.failed", "backup.failed", "restore.failed", "restore.drill.failed", "database.migration.failed", "audit.archive.failed", "ai.audit.failed", "ai.finding.critical",
	}}}
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

func TestFitModelFindingsSharesRunLimitWithBaseline(t *testing.T) {
	findings := make([]modelFinding, 10)
	selected, omitted := fitModelFindings(maxAuditFindings-3, findings)
	if len(selected) != 3 || omitted != 7 {
		t.Fatalf("selected=%d omitted=%d", len(selected), omitted)
	}
	selected, omitted = fitModelFindings(maxAuditFindings, findings)
	if len(selected) != 0 || omitted != 10 {
		t.Fatalf("full baseline selected=%d omitted=%d", len(selected), omitted)
	}
	selected, omitted = fitModelFindings(1, findings)
	if len(selected) != len(findings) || omitted != 0 {
		t.Fatalf("available budget selected=%d omitted=%d", len(selected), omitted)
	}
}
