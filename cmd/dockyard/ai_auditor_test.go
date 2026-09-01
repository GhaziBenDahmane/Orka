package main

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/GhaziBenDahmane/Orka/internal/clustercontract"
	"github.com/GhaziBenDahmane/Orka/internal/store"
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
		} else if len(request.Messages) != 2 || !strings.Contains(request.Messages[0].Content, "untrusted data") || !strings.Contains(request.Messages[1].Content, "SNAPSHOT_DATA_BEGIN") || !strings.Contains(request.Messages[1].Content, "never infer") {
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

func TestRunAIAuditorOnce(t *testing.T) {
	completed := 0
	platform := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/ai/audit-snapshot":
			_ = json.NewEncoder(w).Encode(map[string]any{"projects": []any{}, "identityPosture": map[string]any{"requireSso": true, "activeOwners": 1}, "notificationPosture": fullyCoveredNotifications()})
		case "/v1/ai/audit-runs":
			w.WriteHeader(http.StatusCreated)
			_ = json.NewEncoder(w).Encode(map[string]string{"id": "00000000-0000-0000-0000-000000000001"})
		default:
			if r.Method == http.MethodPatch {
				completed++
				w.WriteHeader(http.StatusNoContent)
			} else {
				w.WriteHeader(http.StatusCreated)
			}
		}
	}))
	defer platform.Close()
	model := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{"choices": []any{map[string]any{"message": map[string]string{"content": `{"summary":"healthy","findings":[]}`}}}})
	}))
	defer model.Close()
	t.Setenv("DOCKYARD_CONTROL_PLANE_URL", platform.URL)
	t.Setenv("DOCKYARD_AI_AUDITOR_TOKEN", "auditor-token")
	t.Setenv("DOCKYARD_AI_BASE_URL", model.URL+"/v1")
	t.Setenv("DOCKYARD_AI_MODEL", "test-model")
	t.Setenv("DOCKYARD_AI_AUDIT_TIMEOUT", "1m")
	if err := runAIAuditor([]string{"--once"}); err != nil || completed != 1 {
		t.Fatalf("one-shot audit completed=%d err=%v", completed, err)
	}
	if err := runAIAuditor([]string{"unexpected"}); err == nil || !strings.Contains(err.Error(), "usage:") {
		t.Fatalf("unexpected arguments error=%v", err)
	}
}

func TestAIAuditRetryDelay(t *testing.T) {
	base, maximum := 5*time.Minute, 24*time.Hour
	for _, test := range []struct {
		failures int
		want     time.Duration
	}{
		{failures: 0, want: maximum},
		{failures: 1, want: 5 * time.Minute},
		{failures: 2, want: 10 * time.Minute},
		{failures: 6, want: 160 * time.Minute},
		{failures: 20, want: maximum},
	} {
		if got := aiAuditRetryDelay(test.failures, base, maximum); got != test.want {
			t.Errorf("aiAuditRetryDelay(%d)=%s, want %s", test.failures, got, test.want)
		}
	}
}

func TestChunkAuditSnapshotPreservesEveryResource(t *testing.T) {
	projects := make([]map[string]any, 5)
	for index := range projects {
		projects[index] = map[string]any{"id": index, "payload": strings.Repeat(string(rune('a'+index)), 180<<10)}
	}
	snapshot, _ := json.Marshal(map[string]any{
		"generatedAt": "2026-08-30T12:00:00Z", "organizationId": "00000000-0000-0000-0000-000000000001",
		"projects": projects, "identityPosture": map[string]any{"activeOwners": 1},
	})
	chunks, err := chunkAuditSnapshot(snapshot)
	if err != nil {
		t.Fatal(err)
	}
	if len(chunks) < 2 {
		t.Fatalf("large snapshot produced %d chunk(s), want multiple", len(chunks))
	}
	seen := map[int]bool{}
	for index, chunk := range chunks {
		if len(chunk) > maxAuditModelChunkBytes {
			t.Fatalf("chunk %d has %d bytes", index, len(chunk))
		}
		var decoded struct {
			OrganizationID string `json:"organizationId"`
			AuditChunk     struct {
				Index    int      `json:"index"`
				Total    int      `json:"total"`
				Partial  bool     `json:"partial"`
				Sections []string `json:"sections"`
			} `json:"auditChunk"`
			Projects []struct {
				ID int `json:"id"`
			} `json:"projects"`
		}
		if err = json.Unmarshal(chunk, &decoded); err != nil {
			t.Fatal(err)
		}
		if decoded.OrganizationID == "" || decoded.AuditChunk.Index != index+1 || decoded.AuditChunk.Total != len(chunks) || !decoded.AuditChunk.Partial || len(decoded.AuditChunk.Sections) == 0 {
			t.Fatalf("chunk metadata=%#v organization=%q", decoded.AuditChunk, decoded.OrganizationID)
		}
		for _, project := range decoded.Projects {
			if seen[project.ID] {
				t.Fatalf("project %d appeared in multiple chunks", project.ID)
			}
			seen[project.ID] = true
		}
	}
	if len(seen) != len(projects) {
		t.Fatalf("chunked projects=%v, want %d", seen, len(projects))
	}
}

func TestChunkAuditSnapshotRejectsOversizedResource(t *testing.T) {
	snapshot, _ := json.Marshal(map[string]any{"projects": []map[string]string{{"payload": strings.Repeat("x", maxAuditModelChunkBytes)}}})
	if _, err := chunkAuditSnapshot(snapshot); err == nil || !strings.Contains(err.Error(), "item exceeding") {
		t.Fatalf("oversized resource error=%v", err)
	}
}

func TestPerformAIAuditReviewsEverySnapshotChunk(t *testing.T) {
	projects := make([]map[string]any, 5)
	for index := range projects {
		projects[index] = map[string]any{"id": uuid.New(), "name": "project", "payload": strings.Repeat(string(rune('a'+index)), 180<<10)}
	}
	modelRequests, recordedChunks, modelFindingRequests := 0, 0, 0
	modelFindingSeverity := ""
	completion := map[string]string{}
	platform := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/v1/ai/audit-snapshot":
			_ = json.NewEncoder(w).Encode(map[string]any{"projects": projects, "identityPosture": map[string]any{"requireSso": true, "activeOwners": 1}, "notificationPosture": fullyCoveredNotifications()})
		case r.URL.Path == "/v1/ai/audit-runs":
			var input struct {
				Scope struct {
					SnapshotChunks int `json:"snapshotChunks"`
				} `json:"scope"`
			}
			_ = json.NewDecoder(r.Body).Decode(&input)
			recordedChunks = input.Scope.SnapshotChunks
			w.WriteHeader(http.StatusCreated)
			_ = json.NewEncoder(w).Encode(map[string]string{"id": "00000000-0000-0000-0000-000000000001"})
		case r.Method == http.MethodPatch:
			_ = json.NewDecoder(r.Body).Decode(&completion)
			w.WriteHeader(http.StatusNoContent)
		default:
			var finding modelFinding
			_ = json.NewDecoder(r.Body).Decode(&finding)
			if finding.Category == "chunk" {
				modelFindingRequests++
				modelFindingSeverity = finding.Severity
			}
			w.WriteHeader(http.StatusCreated)
		}
	}))
	defer platform.Close()
	model := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		modelRequests++
		severity := "low"
		if modelRequests > 1 {
			severity = "high"
		}
		report := modelReport{Summary: "chunk reviewed", Findings: []modelFinding{{Severity: severity, Category: "chunk", Title: "Repeated issue", Description: "Repeated across related sections", ResourceType: "organization", ResourceID: "platform", Evidence: map[string]any{}, Remediation: "Review once"}}}
		content, _ := json.Marshal(report)
		_ = json.NewEncoder(w).Encode(map[string]any{"choices": []any{map[string]any{"message": map[string]string{"content": string(content)}}}})
	}))
	defer model.Close()
	err := performAIAudit(context.Background(), platform.Client(), auditorConfig{DockyardURL: platform.URL, DockyardToken: "token", ModelURL: model.URL, Model: "test", AgentName: "chunk-test", Focus: "security"})
	if err != nil {
		t.Fatal(err)
	}
	if modelRequests < 2 || recordedChunks != modelRequests || modelFindingRequests != 1 || modelFindingSeverity != "high" || !strings.Contains(completion["summary"], "Model review: ") || !strings.Contains(completion["summary"], "snapshot chunk(s)") || !strings.Contains(completion["summary"], "Duplicate model findings merged") {
		t.Fatalf("model requests=%d recorded=%d finding requests=%d severity=%q completion=%#v", modelRequests, recordedChunks, modelFindingRequests, modelFindingSeverity, completion)
	}
}

func TestRunAIAuditorRejectsInvalidRetryInterval(t *testing.T) {
	t.Setenv("DOCKYARD_AI_AUDIT_INTERVAL", "10m")
	t.Setenv("DOCKYARD_AI_AUDIT_RETRY_INTERVAL", "11m")
	if err := runAIAuditor([]string{"--once"}); err == nil || !strings.Contains(err.Error(), "DOCKYARD_AI_AUDIT_RETRY_INTERVAL") {
		t.Fatalf("invalid retry interval error=%v", err)
	}
}

func TestAuditorSecretValueFailsClosed(t *testing.T) {
	t.Run("inline", func(t *testing.T) {
		t.Setenv("DOCKYARD_TEST_AUDITOR_SECRET", " inline-secret ")
		t.Setenv("DOCKYARD_TEST_AUDITOR_SECRET_FILE", "")
		value, err := auditorSecretValue("DOCKYARD_TEST_AUDITOR_SECRET")
		if err != nil || value != "inline-secret" {
			t.Fatalf("secret=%q err=%v", value, err)
		}
	})
	t.Run("file", func(t *testing.T) {
		path := t.TempDir() + "/secret"
		if err := os.WriteFile(path, []byte(" file-secret\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		t.Setenv("DOCKYARD_TEST_AUDITOR_SECRET", "")
		t.Setenv("DOCKYARD_TEST_AUDITOR_SECRET_FILE", path)
		value, err := auditorSecretValue("DOCKYARD_TEST_AUDITOR_SECRET")
		if err != nil || value != "file-secret" {
			t.Fatalf("secret=%q err=%v", value, err)
		}
	})
	for _, test := range []struct {
		name  string
		value string
		path  string
		want  string
	}{
		{name: "ambiguous", value: "inline", path: "/mounted/secret", want: "cannot both be configured"},
		{name: "unreadable", path: t.TempDir() + "/missing", want: "read DOCKYARD_TEST_AUDITOR_SECRET_FILE"},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Setenv("DOCKYARD_TEST_AUDITOR_SECRET", test.value)
			t.Setenv("DOCKYARD_TEST_AUDITOR_SECRET_FILE", test.path)
			if _, err := auditorSecretValue("DOCKYARD_TEST_AUDITOR_SECRET"); err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("error=%v, want %q", err, test.want)
			}
		})
	}
	t.Run("empty file", func(t *testing.T) {
		path := t.TempDir() + "/secret"
		if err := os.WriteFile(path, []byte(" \n"), 0o600); err != nil {
			t.Fatal(err)
		}
		t.Setenv("DOCKYARD_TEST_AUDITOR_SECRET", "")
		t.Setenv("DOCKYARD_TEST_AUDITOR_SECRET_FILE", path)
		if _, err := auditorSecretValue("DOCKYARD_TEST_AUDITOR_SECRET"); err == nil || !strings.Contains(err.Error(), "is empty") {
			t.Fatalf("error=%v", err)
		}
	})
}

func TestRunAIAuditorRejectsInvalidSecretConfiguration(t *testing.T) {
	configure := func(t *testing.T) {
		t.Helper()
		t.Setenv("DOCKYARD_CONTROL_PLANE_URL", "https://dockyard.example.test")
		t.Setenv("DOCKYARD_AI_BASE_URL", "https://models.example.test/v1")
		t.Setenv("DOCKYARD_AI_MODEL", "test-model")
		t.Setenv("DOCKYARD_AI_AUDITOR_TOKEN", "auditor-token")
		t.Setenv("DOCKYARD_AI_AUDITOR_TOKEN_FILE", "")
		t.Setenv("DOCKYARD_AI_API_KEY", "")
		t.Setenv("DOCKYARD_AI_API_KEY_FILE", "")
	}
	t.Run("ambiguous auditor token", func(t *testing.T) {
		configure(t)
		t.Setenv("DOCKYARD_AI_AUDITOR_TOKEN_FILE", "/run/secrets/auditor")
		if err := runAIAuditor([]string{"--once"}); err == nil || !strings.Contains(err.Error(), "DOCKYARD_AI_AUDITOR_TOKEN and DOCKYARD_AI_AUDITOR_TOKEN_FILE cannot both be configured") {
			t.Fatalf("error=%v", err)
		}
	})
	t.Run("unreadable optional model token", func(t *testing.T) {
		configure(t)
		t.Setenv("DOCKYARD_AI_API_KEY_FILE", t.TempDir()+"/missing")
		if err := runAIAuditor([]string{"--once"}); err == nil || !strings.Contains(err.Error(), "read DOCKYARD_AI_API_KEY_FILE") {
			t.Fatalf("error=%v", err)
		}
	})
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
		{raw: "https://bad_label.example.test"}, {raw: "https://-bad.example.test"},
		{raw: "https://dockyard.example.test:"}, {raw: "https://dockyard.example.test:0"},
		{raw: "https://dockyard.example.test:65536"}, {raw: "https://models.example.test/v1/../admin", allowPath: true},
		{raw: "https://models.example.test/v1//chat", allowPath: true},
		{raw: "https://models.example.test/" + strings.Repeat("a", maxAuditorEndpointBytes), allowPath: true},
	} {
		if _, err := normalizedAuditorEndpoint("endpoint", test.raw, test.allowPath); err == nil {
			t.Errorf("accepted unsafe endpoint %q", test.raw)
		}
	}
}

func TestAuditorConfigurationFieldsAreBounded(t *testing.T) {
	if !validAuditorMetadata("provider/model", "security-auditor", "security and reliability") {
		t.Fatal("valid auditor metadata was rejected")
	}
	for _, values := range [][3]string{
		{"", "agent", "focus"},
		{"model\nheader", "agent", "focus"},
		{strings.Repeat("m", maxAuditModelNameBytes+1), "agent", "focus"},
		{"model", "agent\nname", "focus"},
		{"model", strings.Repeat("a", maxAuditAgentNameBytes+1), "focus"},
		{"model", "agent", strings.Repeat("f", maxAuditFocusBytes+1)},
		{"model", "agent", "focus\x00data"},
	} {
		if validAuditorMetadata(values[0], values[1], values[2]) {
			t.Errorf("invalid auditor metadata lengths %d/%d/%d were accepted", len(values[0]), len(values[1]), len(values[2]))
		}
	}
}

func TestAuditorSecretValueRejectsUnsafeAndOversizedValues(t *testing.T) {
	if _, err := validateAuditorSecret("TEST_SECRET", "secret\x00value"); err == nil {
		t.Fatal("secret containing NUL was accepted")
	}
	for _, value := range []string{"secret\nheader", strings.Repeat("s", maxAuditorSecretBytes+1)} {
		t.Setenv("DOCKYARD_TEST_AUDITOR_SECRET", value)
		t.Setenv("DOCKYARD_TEST_AUDITOR_SECRET_FILE", "")
		if _, err := auditorSecretValue("DOCKYARD_TEST_AUDITOR_SECRET"); err == nil {
			t.Errorf("unsafe inline secret of length %d was accepted", len(value))
		}
	}
	path := t.TempDir() + "/oversized"
	if err := os.WriteFile(path, []byte(strings.Repeat("s", maxAuditorSecretBytes+1)), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("DOCKYARD_TEST_AUDITOR_SECRET", "")
	t.Setenv("DOCKYARD_TEST_AUDITOR_SECRET_FILE", path)
	if _, err := auditorSecretValue("DOCKYARD_TEST_AUDITOR_SECRET"); err == nil {
		t.Fatal("oversized secret file was accepted")
	}
}

func TestAuditorHTTPClientDisablesAmbientProxy(t *testing.T) {
	t.Setenv("HTTP_PROXY", "http://proxy.example.test:8080")
	t.Setenv("HTTPS_PROXY", "http://proxy.example.test:8080")
	client := auditorHTTPClient(nil)
	transport, ok := client.Transport.(*http.Transport)
	if !ok {
		t.Fatalf("auditor transport=%T, want *http.Transport", client.Transport)
	}
	if transport.Proxy != nil {
		t.Fatal("auditor transport retained ambient proxy resolution")
	}
	if client.Timeout != 2*time.Minute {
		t.Fatalf("auditor timeout=%s", client.Timeout)
	}
	original := &http.Client{Transport: http.DefaultTransport, Timeout: time.Second}
	secured := auditorHTTPClient(original)
	if secured.Transport != original.Transport || secured == original || original.CheckRedirect != nil {
		t.Fatal("explicit transport was replaced or caller client was mutated")
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
	organizationID, databaseID, clusterID, repositoryID, serviceID, backupDestinationID := uuid.New(), uuid.New(), uuid.New(), uuid.New(), uuid.New(), uuid.New()
	staleHeartbeat, expiringCertificate := now.Add(-3*time.Minute), now.Add(6*24*time.Hour)
	stalledSAMLRotation := now.Add(-8 * 24 * time.Hour)
	oldSCIMToken, oldPendingJob, staleJobHeartbeat := now.Add(-181*24*time.Hour), now.Add(-11*time.Minute), now.Add(-3*time.Minute)
	snapshot := store.AIAuditSnapshot{
		Organization:       organizationID,
		IdentityPosture:    store.AIAuditIdentityPosture{PendingSAMLCertificateRotations: 1, OldestPendingSAMLRotationAt: &stalledSAMLRotation, ExpiringServiceAccounts: 2, ActiveSCIMTokens: 1, OldestActiveSCIMTokenCreatedAt: &oldSCIMToken, PendingInvitations: 2, PendingPrivilegedInvitations: 1, InvitationsExpiringSoon: 1, ExpiredInvitations: 1, ProjectScopedGrants: 1, EnvironmentScopedGrants: 1, AdminScopedGrants: 1, RedundantScopedGrants: 1, SCIMGroups: 2, WriteCapableSCIMGroups: 1, SCIMGroupMemberships: 2},
		DeployTokenPosture: store.AIAuditDeployTokenPosture{ActiveTokens: 2, ExpiringTokens: 1, ExpiredUnrevokedTokens: 1, UnusedActiveTokens: 1},
		MigrationPosture: []store.AIAuditMigrationPosture{{
			SourceOrganizationID: "legacy", Resources: 4, Imported: 2, Unresolved: 2, Databases: 1,
		}},
		BackupPosture:        []store.AIAuditBackupPosture{{DatabaseID: databaseID, Engine: "postgres"}},
		BackupDestinations:   []store.AIAuditBackupDestinationInfo{{ID: backupDestinationID, DatabasePolicies: 1, VolumePolicies: 1, AuditArchives: 1}},
		VolumeBackupPosture:  []store.AIAuditVolumeBackupPosture{{ServiceID: serviceID, VolumeName: "uploads"}},
		Clusters:             []store.AIAuditClusterInfo{{ID: clusterID, State: "active", AgentImage: "registry.example/dockyard:latest", LastSeenAt: &staleHeartbeat, CertificateAuthorityFingerprint: "sha256:old", PendingCertificateAuthorityFingerprint: "sha256:new", CertificateNotAfter: &expiringCertificate}},
		AgentCAPosture:       store.AIAuditAgentCAPosture{Configured: true, ActiveFingerprint: "sha256:new", PreviousFingerprint: "sha256:old", RolloverActive: true},
		AgentUpgradePosture:  []store.AIAuditAgentUpgradePosture{{ClusterID: clusterID, Status: "verifying", VerificationOverdue: true, TargetImage: "registry.example/dockyard@sha256:test"}},
		TemplateRepositories: []store.AIAuditTemplateRepositoryInfo{{ID: repositoryID, Enabled: true, GitRef: "main", LastSyncStatus: "failed"}},
		NotificationPosture:  []store.AIAuditNotificationPosture{{Enabled: true, Events: []string{"deployment.failed"}}},
		QueuePosture:         store.AIAuditQueuePosture{PendingJobs: 2, RunningJobs: 1, OldestPendingAt: &oldPendingJob, OldestRunningHeartbeatAt: &staleJobHeartbeat, Kinds: []store.AIAuditQueueKindPosture{{Kind: "audit.archive", PendingJobs: 1}, {Kind: "backup.database", PendingJobs: 1, RunningJobs: 1}}},
		FinalizerPosture:     store.AIAuditFinalizerPosture{DeletingClusters: 1, FailedJobs: 1, ResourcesWithoutActiveJob: 1},
		ServiceDeployments:   []store.AIAuditServiceDeployment{{ServiceID: serviceID, DesiredRevision: 2, LatestDeploymentRevision: 1, LatestDeploymentStatus: "succeeded"}},
		Reconciliation:       []store.AIAuditReconciliationPosture{{ComposeServiceID: serviceID, State: "degraded", ConsecutiveFailures: 2, LastCheckedAt: now}},
	}
	findings := deterministicAuditFindings(snapshot, now)
	titles := map[string]bool{}
	for _, finding := range findings {
		titles[finding.Title] = true
	}
	for _, title := range []string{"Organization has no active owner", "Mandatory SSO is disabled", "SAML certificate rotation is stalled", "Service account credentials expire soon", "Long-lived SCIM credential requires rotation", "Dokploy migration has unresolved resources", "Dokploy database transfers are incomplete", "Database has no backup policy", "Volume backup policy is disabled", "Protected volume has no storage-node binding", "Volume lacks a successful backup", "Volume backups do not pause writers", "Volume restore has not been validated", "Remote agent image is not immutable", "Remote cluster heartbeat is stale", "Remote cluster certificate expires soon", "Remote cluster uses a non-active certificate authority", "Previous agent certificate authority remains trusted", "Remote agent upgrade requires intervention", "Template repository does not require signatures", "Template repository synchronization failed", "Platform job queue is stalled", "Platform job lease heartbeat is stale", "Failure notifications have coverage gaps", "Desired service revision is not deployed", "Swarm service reconciliation is unhealthy"} {
		if !titles[title] {
			t.Errorf("missing deterministic finding %q in %#v", title, findings)
		}
	}
	for _, title := range []string{"Privileged organization invitations are pending", "Expired organization invitations remain active in inventory", "Scoped access grants are redundant"} {
		if !titles[title] {
			t.Errorf("missing identity governance finding %q in %#v", title, findings)
		}
	}
	if !titles["Backup destination permits plaintext object-store transport"] {
		t.Errorf("missing plaintext backup destination finding in %#v", findings)
	}
	if !titles["Resource deletion finalizer requires intervention"] {
		t.Errorf("missing failed resource finalizer finding in %#v", findings)
	}
	for _, title := range []string{"Deployment hook credentials expire soon", "Expired deployment hook credentials remain in inventory"} {
		if !titles[title] {
			t.Errorf("missing deployment token finding %q in %#v", title, findings)
		}
	}
	if len(findings) != 33 {
		t.Fatalf("findings=%d, want 33: %#v", len(findings), findings)
	}
}

func TestDeterministicAuditDetectsStaleUnusedDeploymentHookCredentials(t *testing.T) {
	now := time.Date(2026, 8, 31, 12, 0, 0, 0, time.UTC)
	oldestUnused := now.Add(-31 * 24 * time.Hour)
	snapshot := store.AIAuditSnapshot{
		Organization:        uuid.New(),
		IdentityPosture:     store.AIAuditIdentityPosture{RequireSSO: true, ActiveOwners: 1},
		NotificationPosture: fullyCoveredNotifications(),
		DeployTokenPosture: store.AIAuditDeployTokenPosture{
			ActiveTokens:                      3,
			UnusedActiveTokens:                2,
			UnusedActiveTokensOlderThan30Days: 1,
			OldestUnusedActiveTokenCreatedAt:  &oldestUnused,
		},
	}
	findings := deterministicAuditFindings(snapshot, now)
	if len(findings) != 1 || findings[0].Title != "Unused deployment hook credentials are stale" || findings[0].Severity != "medium" || findings[0].Evidence["unusedActiveTokensOlderThan30Days"] != int64(1) {
		t.Fatalf("stale deployment hook findings=%#v", findings)
	}
	snapshot.DeployTokenPosture.UnusedActiveTokensOlderThan30Days = 0
	if findings = deterministicAuditFindings(snapshot, now); len(findings) != 0 {
		t.Fatalf("fresh unused deployment hook produced findings=%#v", findings)
	}
}

func TestDeterministicAuditDetectsStaleUnusedServiceAccountCredentials(t *testing.T) {
	now := time.Date(2026, 8, 31, 12, 0, 0, 0, time.UTC)
	oldestUnused := now.Add(-45 * 24 * time.Hour)
	snapshot := store.AIAuditSnapshot{
		Organization: uuid.New(),
		IdentityPosture: store.AIAuditIdentityPosture{
			RequireSSO:                         true,
			ActiveOwners:                       1,
			UnusedServiceAccounts30d:           2,
			UnusedPrivilegedServiceAccounts30d: 1,
			OldestUnusedServiceAccountTokenAt:  &oldestUnused,
		},
		NotificationPosture: fullyCoveredNotifications(),
	}
	findings := deterministicAuditFindings(snapshot, now)
	if len(findings) != 1 || findings[0].Title != "Unused service-account credentials are stale" || findings[0].Severity != "high" || findings[0].Evidence["unusedPrivilegedServiceAccounts30d"] != int64(1) {
		t.Fatalf("stale service-account findings=%#v", findings)
	}
	snapshot.IdentityPosture.UnusedPrivilegedServiceAccounts30d = 0
	if findings = deterministicAuditFindings(snapshot, now); len(findings) != 1 || findings[0].Severity != "medium" {
		t.Fatalf("unprivileged stale service-account findings=%#v", findings)
	}
	snapshot.IdentityPosture.UnusedServiceAccounts30d = 0
	if findings = deterministicAuditFindings(snapshot, now); len(findings) != 0 {
		t.Fatalf("fresh service-account posture produced findings=%#v", findings)
	}
}

func TestDeterministicAuditDetectsStaleUnusedSourceCredentials(t *testing.T) {
	now := time.Date(2026, 8, 31, 12, 0, 0, 0, time.UTC)
	staleID := uuid.New()
	snapshot := store.AIAuditSnapshot{
		Organization:        uuid.New(),
		IdentityPosture:     store.AIAuditIdentityPosture{RequireSSO: true, ActiveOwners: 1},
		NotificationPosture: fullyCoveredNotifications(),
		SourceCredentials: []store.AIAuditSourceCredentialPosture{
			{ID: staleID, Kind: "registry", CreatedAt: now.Add(-45 * 24 * time.Hour), LastRotatedAt: now.Add(-45 * 24 * time.Hour)},
			{ID: uuid.New(), Kind: "git-ssh", CreatedAt: now.Add(-7 * 24 * time.Hour)},
		},
	}
	findings := deterministicAuditFindings(snapshot, now)
	if len(findings) != 1 || findings[0].Title != "Unused source credential is stale" || findings[0].ResourceID != staleID.String() || findings[0].Evidence["kind"] != "registry" || findings[0].Evidence["references"] != int64(0) {
		t.Fatalf("stale source credential findings=%#v", findings)
	}
}

func TestDeterministicAuditDetectsOverdueSourceCredentialRotation(t *testing.T) {
	now := time.Date(2026, 8, 31, 12, 0, 0, 0, time.UTC)
	overdueID := uuid.New()
	snapshot := store.AIAuditSnapshot{
		Organization:        uuid.New(),
		IdentityPosture:     store.AIAuditIdentityPosture{RequireSSO: true, ActiveOwners: 1},
		NotificationPosture: fullyCoveredNotifications(),
		SourceCredentials: []store.AIAuditSourceCredentialPosture{
			{ID: overdueID, Kind: "git-ssh", GitReferences: 1, StatusReferences: 1, CreatedAt: now.Add(-400 * 24 * time.Hour), LastRotatedAt: now.Add(-181 * 24 * time.Hour)},
			{ID: uuid.New(), Kind: "registry", RegistryReferences: 1, CreatedAt: now.Add(-400 * 24 * time.Hour), LastRotatedAt: now.Add(-179 * 24 * time.Hour)},
		},
	}
	findings := deterministicAuditFindings(snapshot, now)
	if len(findings) != 1 || findings[0].Title != "Source credential rotation is overdue" || findings[0].ResourceID != overdueID.String() || findings[0].Evidence["references"] != int64(2) || findings[0].Evidence["ageDays"] != 181 {
		t.Fatalf("source credential rotation findings=%#v", findings)
	}
}

func TestDeterministicAuditDetectsMandatorySSOLockout(t *testing.T) {
	organizationID := uuid.New()
	snapshot := store.AIAuditSnapshot{
		Organization: organizationID,
		IdentityPosture: store.AIAuditIdentityPosture{
			RequireSSO:    true,
			ActiveMembers: 3,
			ActiveOwners:  1,
		},
		NotificationPosture: fullyCoveredNotifications(),
	}
	findings := deterministicAuditFindings(snapshot, time.Now().UTC())
	if len(findings) != 1 || findings[0].Title != "Mandatory SSO has no enabled provider" || findings[0].Severity != "critical" || findings[0].ResourceID != organizationID.String() {
		t.Fatalf("SSO lockout findings=%#v", findings)
	}
	snapshot.IdentityPosture.EnabledOIDCProviders = 1
	if findings = deterministicAuditFindings(snapshot, time.Now().UTC()); len(findings) != 0 {
		t.Fatalf("enabled SSO provider produced findings=%#v", findings)
	}
}

func TestDeterministicAuditDetectsMissingLocalMFA(t *testing.T) {
	snapshot := store.AIAuditSnapshot{
		Organization: uuid.New(),
		IdentityPosture: store.AIAuditIdentityPosture{
			RequireSSO: true, EnabledOIDCProviders: 1, ActiveOwners: 1,
			ActiveLocalMembers: 3, MFAEnabledLocalMembers: 1,
			PrivilegedLocalMembers: 2, MFAEnabledPrivilegedLocalMembers: 1,
		},
		NotificationPosture: fullyCoveredNotifications(),
	}
	findings := deterministicAuditFindings(snapshot, time.Now().UTC())
	if len(findings) != 1 || findings[0].Title != "Privileged local accounts lack MFA" || findings[0].Severity != "high" {
		t.Fatalf("privileged MFA findings=%#v", findings)
	}
	snapshot.IdentityPosture.MFAEnabledPrivilegedLocalMembers = 2
	if findings = deterministicAuditFindings(snapshot, time.Now().UTC()); len(findings) != 1 || findings[0].Title != "Local accounts lack MFA" || findings[0].Severity != "medium" {
		t.Fatalf("local MFA findings=%#v", findings)
	}
	snapshot.IdentityPosture.MFAEnabledLocalMembers = 3
	if findings = deterministicAuditFindings(snapshot, time.Now().UTC()); len(findings) != 0 {
		t.Fatalf("complete MFA posture produced findings=%#v", findings)
	}
}

func TestDeterministicAuditDetectsStalledRemoteCommands(t *testing.T) {
	now := time.Now().UTC()
	clusterID := uuid.New()
	staleDue, staleLease := now.Add(-3*time.Minute), now.Add(-4*time.Minute)
	snapshot := store.AIAuditSnapshot{
		Organization:        uuid.New(),
		IdentityPosture:     store.AIAuditIdentityPosture{RequireSSO: true, ActiveOwners: 1},
		NotificationPosture: fullyCoveredNotifications(),
		AgentCommandPosture: []store.AIAuditAgentCommandPosture{
			{ClusterID: clusterID, Kind: "swarm.deploy", PendingCommands: 1, DueCommands: 1, OldestDueAt: &staleDue},
			{ClusterID: clusterID, Kind: "database.utility", LeasedCommands: 1, ExpiredLeases: 1, OldestExpiredLeaseAt: &staleLease},
		},
	}
	findings := deterministicAuditFindings(snapshot, now)
	if len(findings) != 2 || findings[0].Title != "Remote command queue is stalled" || findings[0].ResourceID != clusterID.String()+"/swarm.deploy" || findings[1].Title != "Remote command lease recovery is stalled" || findings[1].ResourceID != clusterID.String()+"/database.utility" {
		t.Fatalf("remote command findings=%#v", findings)
	}
	fresh := now.Add(-time.Minute)
	snapshot.AgentCommandPosture = []store.AIAuditAgentCommandPosture{{ClusterID: clusterID, Kind: "swarm.logs", PendingCommands: 1, DueCommands: 1, OldestDueAt: &fresh}}
	if findings = deterministicAuditFindings(snapshot, now); len(findings) != 0 {
		t.Fatalf("fresh remote command produced findings=%#v", findings)
	}
}

func TestDeterministicAuditDetectsNamedVolumesWithoutPolicies(t *testing.T) {
	serviceID := uuid.New()
	now := time.Now().UTC()
	snapshot := store.AIAuditSnapshot{
		Organization:        uuid.New(),
		IdentityPosture:     store.AIAuditIdentityPosture{RequireSSO: true, ActiveOwners: 1},
		NotificationPosture: fullyCoveredNotifications(),
		WorkloadPosture:     []store.AIAuditWorkloadPosture{{ServiceID: serviceID, DefinitionParseable: true, NamedVolumes: []string{"cache", "uploads"}}},
		VolumeBackupPosture: []store.AIAuditVolumeBackupPosture{{ServiceID: serviceID, VolumeName: "cache", PolicyEnabled: true, StorageNodeID: "node-1", IntervalSeconds: 3600, LastBackupStatus: "succeeded", LastBackupAt: &now, LastBackupArtifactValid: true, Quiesce: true, LastRestoreStatus: "succeeded", LastRestoreAt: &now}},
	}
	findings := deterministicAuditFindings(snapshot, now)
	if len(findings) != 1 || findings[0].Title != "Named volume has no backup policy" || findings[0].ResourceType != "service_volume" || findings[0].ResourceID != serviceID.String()+"/uploads" {
		t.Fatalf("named volume findings=%#v", findings)
	}
}

func TestDeterministicAuditDetectsFailedAndStalledOfflineVolumeRecovery(t *testing.T) {
	now := time.Date(2026, 8, 31, 12, 0, 0, 0, time.UTC)
	serviceID := uuid.New()
	failedID, stalledID := uuid.New(), uuid.New()
	failedAt, startedAt := now.Add(-time.Hour), now.Add(-40*time.Minute)
	snapshot := store.AIAuditSnapshot{
		Organization:        uuid.New(),
		IdentityPosture:     store.AIAuditIdentityPosture{RequireSSO: true, ActiveOwners: 1},
		NotificationPosture: fullyCoveredNotifications(),
		VolumeRestorePosture: []store.AIAuditVolumeRestorePosture{
			{ID: failedID, ServiceID: serviceID, ServiceName: "App", VolumeName: "uploads", StorageNodeID: "node-new", TargetStorageNodeID: "node-new", Status: "failed", CreatedAt: now.Add(-70 * time.Minute), FinishedAt: &failedAt},
			{ID: stalledID, ServiceID: serviceID, ServiceName: "App", VolumeName: "cache", StorageNodeID: "node-new", TargetStorageNodeID: "node-new", Status: "running", CreatedAt: now.Add(-41 * time.Minute), StartedAt: &startedAt},
			{ID: uuid.New(), ServiceID: serviceID, ServiceName: "App", VolumeName: "fresh", StorageNodeID: "node-new", TargetStorageNodeID: "node-new", Status: "queued", CreatedAt: now.Add(-5 * time.Minute)},
			{ID: uuid.New(), ServiceID: serviceID, ServiceName: "App", VolumeName: "recovered", StorageNodeID: "node-new", TargetStorageNodeID: "node-new", Status: "succeeded", CreatedAt: now.Add(-time.Hour), FinishedAt: &failedAt},
		},
	}
	findings := deterministicAuditFindings(snapshot, now)
	if len(findings) != 2 {
		t.Fatalf("offline recovery findings=%#v", findings)
	}
	if findings[0].Title != "Offline volume recovery failed" || findings[0].Severity != "critical" || findings[0].ResourceID != failedID.String() || findings[0].Evidence["volumeName"] != "uploads" || findings[0].Evidence["targetStorageNodeId"] != "node-new" {
		t.Fatalf("failed recovery finding=%#v", findings[0])
	}
	if findings[1].Title != "Offline volume recovery is stalled" || findings[1].Severity != "critical" || findings[1].ResourceID != stalledID.String() || findings[1].Evidence["ageSeconds"] != int64(41*60) || findings[1].Evidence["maximumAgeSeconds"] != int64(30*60) {
		t.Fatalf("stalled recovery finding=%#v", findings[1])
	}
}

func TestDeterministicAuditDetectsMutableRemoteAgentImages(t *testing.T) {
	now := time.Now().UTC()
	missingID, mutableID := uuid.New(), uuid.New()
	snapshot := store.AIAuditSnapshot{
		Organization:        uuid.New(),
		IdentityPosture:     store.AIAuditIdentityPosture{RequireSSO: true, ActiveOwners: 1},
		NotificationPosture: fullyCoveredNotifications(),
		Clusters: []store.AIAuditClusterInfo{
			{ID: missingID, State: "active", LastSeenAt: &now, Nodes: 1, ReadyNodes: 1, ActiveNodes: 1, SchedulableNodes: 1, Managers: 1, DockerSwarm: true, DockerCompose: true},
			{ID: mutableID, State: "draining", AgentImage: "registry.example/dockyard:latest", LastSeenAt: &now, Nodes: 1, ReadyNodes: 1, ActiveNodes: 1, SchedulableNodes: 1, Managers: 1, DockerSwarm: true, DockerCompose: true},
			{ID: uuid.New(), State: "active", AgentImage: "registry.example/dockyard:v1@sha256:" + strings.Repeat("a", 64), LastSeenAt: &now, Nodes: 1, ReadyNodes: 1, ActiveNodes: 1, SchedulableNodes: 1, Managers: 1, DockerSwarm: true, DockerCompose: true},
			{ID: uuid.New(), State: "pending", AgentImage: "registry.example/dockyard:latest"},
		},
	}
	findings := deterministicAuditFindings(snapshot, now)
	if len(findings) != 2 || findings[0].Title != "Remote agent image is not immutable" || findings[0].ResourceID != missingID.String() || findings[0].Evidence["agentImageRecorded"] != false || findings[1].Title != "Remote agent image is not immutable" || findings[1].ResourceID != mutableID.String() || findings[1].Evidence["agentImageRecorded"] != true {
		t.Fatalf("agent image findings=%#v", findings)
	}
}

func TestDeterministicAuditDetectsStuckFinalizers(t *testing.T) {
	now := time.Now().UTC()
	recent, stale := now.Add(-time.Minute), now.Add(-finalizerStallThreshold-time.Second)
	for _, test := range []struct {
		name    string
		posture store.AIAuditFinalizerPosture
		want    string
	}{
		{name: "healthy active finalizer", posture: store.AIAuditFinalizerPosture{DeletingServices: 1, PendingJobs: 1, OldestRequestedAt: &recent}},
		{name: "stalled active finalizer", posture: store.AIAuditFinalizerPosture{DeletingServices: 1, RunningJobs: 1, OldestRequestedAt: &stale}, want: "Resource deletion finalizer is stalled"},
		{name: "failed finalizer", posture: store.AIAuditFinalizerPosture{DeletingClusters: 1, FailedJobs: 1, ResourcesWithoutActiveJob: 1, OldestRequestedAt: &stale}, want: "Resource deletion finalizer requires intervention"},
	} {
		t.Run(test.name, func(t *testing.T) {
			snapshot := store.AIAuditSnapshot{
				Organization:        uuid.New(),
				IdentityPosture:     store.AIAuditIdentityPosture{RequireSSO: true, ActiveOwners: 1},
				NotificationPosture: fullyCoveredNotifications(),
				FinalizerPosture:    test.posture,
			}
			findings := deterministicAuditFindings(snapshot, now)
			if test.want == "" && len(findings) != 0 || test.want != "" && (len(findings) != 1 || findings[0].Title != test.want) {
				t.Fatalf("findings=%#v", findings)
			}
		})
	}
}

func TestDeterministicAuditDetectsPlaintextBackupDestination(t *testing.T) {
	now := time.Now().UTC()
	for _, test := range []struct {
		name     string
		useTLS   bool
		findings int
	}{
		{name: "plaintext", findings: 1},
		{name: "TLS", useTLS: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			snapshot := store.AIAuditSnapshot{
				Organization:        uuid.New(),
				IdentityPosture:     store.AIAuditIdentityPosture{RequireSSO: true, ActiveOwners: 1},
				NotificationPosture: fullyCoveredNotifications(),
				BackupDestinations:  []store.AIAuditBackupDestinationInfo{{ID: uuid.New(), UseTLS: test.useTLS}},
			}
			findings := deterministicAuditFindings(snapshot, now)
			if len(findings) != test.findings {
				t.Fatalf("findings=%#v, want %d", findings, test.findings)
			}
		})
	}
}

func TestDeterministicAuditDetectsBackupDestinationCredentialLifecycle(t *testing.T) {
	now := time.Date(2026, 8, 31, 12, 0, 0, 0, time.UTC)
	unusedID, overdueID := uuid.New(), uuid.New()
	snapshot := store.AIAuditSnapshot{
		Organization:        uuid.New(),
		IdentityPosture:     store.AIAuditIdentityPosture{RequireSSO: true, ActiveOwners: 1},
		NotificationPosture: fullyCoveredNotifications(),
		BackupDestinations: []store.AIAuditBackupDestinationInfo{
			{ID: unusedID, UseTLS: true, CreatedAt: now.Add(-31 * 24 * time.Hour), LastRotatedAt: now.Add(-31 * 24 * time.Hour)},
			{ID: overdueID, UseTLS: true, DatabasePolicies: 1, AuditArchives: 1, CreatedAt: now.Add(-400 * 24 * time.Hour), LastRotatedAt: now.Add(-181 * 24 * time.Hour)},
			{ID: uuid.New(), UseTLS: true, VolumePolicies: 1, CreatedAt: now.Add(-400 * 24 * time.Hour), LastRotatedAt: now.Add(-179 * 24 * time.Hour)},
		},
	}
	findings := deterministicAuditFindings(snapshot, now)
	if len(findings) != 2 || findings[0].Title != "Unused backup destination is stale" || findings[0].ResourceID != unusedID.String() || findings[1].Title != "Backup destination credential rotation is overdue" || findings[1].ResourceID != overdueID.String() || findings[1].Severity != "high" || findings[1].Evidence["ageDays"] != 181 {
		t.Fatalf("backup destination credential findings=%#v", findings)
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

func TestDeterministicAuditDetectsStalledTemplateRepositorySync(t *testing.T) {
	now := time.Now().UTC()
	freshSync := now.Add(-time.Minute)
	staleQueued := now.Add(-6 * time.Minute)
	staleRunning := now.Add(-11 * time.Minute)
	lastSuccess := now.Add(-30 * time.Minute)
	for _, test := range []struct {
		name        string
		status      string
		requestedAt *time.Time
		startedAt   *time.Time
		wantFinding string
	}{
		{name: "fresh queue", status: "succeeded", requestedAt: &freshSync},
		{name: "stalled queue", status: "succeeded", requestedAt: &staleQueued, wantFinding: "Template repository synchronization is queued too long"},
		{name: "fresh running", status: "running", startedAt: &freshSync},
		{name: "stalled running", status: "running", startedAt: &staleRunning, wantFinding: "Template repository synchronization is stuck"},
	} {
		t.Run(test.name, func(t *testing.T) {
			snapshot := store.AIAuditSnapshot{
				Organization:        uuid.New(),
				IdentityPosture:     store.AIAuditIdentityPosture{RequireSSO: true, ActiveOwners: 1},
				NotificationPosture: fullyCoveredNotifications(),
				TemplateRepositories: []store.AIAuditTemplateRepositoryInfo{{
					ID: uuid.New(), Enabled: true, GitRef: "main", RequireSignature: true,
					LastSyncStatus: test.status, LastSyncedAt: &lastSuccess,
					SyncRequestedAt: test.requestedAt, SyncStartedAt: test.startedAt,
				}},
			}
			findings := deterministicAuditFindings(snapshot, now)
			if test.wantFinding == "" && len(findings) != 0 || test.wantFinding != "" && (len(findings) != 1 || findings[0].Title != test.wantFinding) {
				t.Fatalf("findings=%#v", findings)
			}
		})
	}
}

func TestDeterministicAuditDetectsOverdueRecoveryEvidence(t *testing.T) {
	now := time.Now().UTC()
	pinnedUtility := "postgres@sha256:" + strings.Repeat("a", 64)
	staleBackup, staleRestore := now.Add(-3*time.Hour), now.Add(-25*time.Hour)
	freshBackup, freshRestore := now.Add(-time.Hour), now.Add(-23*time.Hour)
	for _, test := range []struct {
		name       string
		backupAt   *time.Time
		restoreAt  *time.Time
		wantTitles []string
	}{
		{name: "stale", backupAt: &staleBackup, restoreAt: &staleRestore, wantTitles: []string{"Database backup is overdue", "Database restore drill is overdue", "Volume backup is overdue", "Volume restore validation is overdue"}},
		{name: "fresh", backupAt: &freshBackup, restoreAt: &freshRestore},
	} {
		t.Run(test.name, func(t *testing.T) {
			snapshot := store.AIAuditSnapshot{
				Organization:        uuid.New(),
				IdentityPosture:     store.AIAuditIdentityPosture{RequireSSO: true, ActiveOwners: 1},
				NotificationPosture: fullyCoveredNotifications(),
				BackupPosture: []store.AIAuditBackupPosture{{
					DatabaseID: uuid.New(), PolicyConfigured: true, PolicyEnabled: true, IntervalSeconds: 3600,
					VerifyRestore: true, LastBackupStatus: "succeeded", LastBackupAt: test.backupAt, LastBackupArtifactValid: true, LastBackupUtilityImage: pinnedUtility,
					LastRestoreDrillStatus: "succeeded", LastRestoreDrillAt: test.restoreAt, LastRestoreUtilityImage: pinnedUtility, LastRestoreReadinessImage: pinnedUtility,
				}},
				VolumeBackupPosture: []store.AIAuditVolumeBackupPosture{{
					ServiceID: uuid.New(), VolumeName: "uploads", StorageNodeID: "nodeabc123", PolicyEnabled: true,
					IntervalSeconds: 3600, Quiesce: true, LastBackupStatus: "succeeded", LastBackupAt: test.backupAt, LastBackupArtifactValid: true,
					LastRestoreStatus: "succeeded", LastRestoreAt: test.restoreAt,
				}},
			}
			findings := deterministicAuditFindings(snapshot, now)
			gotTitles := make([]string, 0, len(findings))
			for _, finding := range findings {
				gotTitles = append(gotTitles, finding.Title)
			}
			if !slices.Equal(gotTitles, test.wantTitles) {
				t.Fatalf("finding titles=%v, want %v", gotTitles, test.wantTitles)
			}
		})
	}
}

func TestDeterministicAuditDetectsMutableDatabaseRecoveryUtilities(t *testing.T) {
	now := time.Now().UTC()
	snapshot := store.AIAuditSnapshot{
		Organization:        uuid.New(),
		IdentityPosture:     store.AIAuditIdentityPosture{RequireSSO: true, ActiveOwners: 1},
		NotificationPosture: fullyCoveredNotifications(),
		BackupPosture: []store.AIAuditBackupPosture{{
			DatabaseID: uuid.New(), Engine: "postgres", PolicyConfigured: true, PolicyEnabled: true, IntervalSeconds: 3600,
			VerifyRestore: true, LastBackupStatus: "succeeded", LastBackupAt: &now, LastBackupArtifactValid: true, LastBackupUtilityImage: "postgres:17",
			LastRestoreDrillStatus: "succeeded", LastRestoreDrillAt: &now, LastRestoreUtilityImage: "postgres:17",
		}},
	}
	findings := deterministicAuditFindings(snapshot, now)
	titles := map[string]bool{}
	for _, finding := range findings {
		titles[finding.Title] = true
	}
	for _, title := range []string{"Database backup utility provenance is missing", "Database restore drill utility provenance is missing"} {
		if !titles[title] {
			t.Fatalf("missing finding %q in %#v", title, findings)
		}
	}
}

func TestDeterministicAuditRejectsSuccessfulBackupsWithInvalidArtifactMetadata(t *testing.T) {
	now := time.Now().UTC()
	databaseID, serviceID := uuid.New(), uuid.New()
	snapshot := store.AIAuditSnapshot{
		Organization:        uuid.New(),
		IdentityPosture:     store.AIAuditIdentityPosture{RequireSSO: true, ActiveOwners: 1},
		NotificationPosture: fullyCoveredNotifications(),
		BackupPosture: []store.AIAuditBackupPosture{{
			DatabaseID: databaseID, Engine: "postgres", PolicyConfigured: true, PolicyEnabled: true, IntervalSeconds: 3600,
			LastBackupStatus: "succeeded", LastBackupAt: &now, LastBackupUtilityImage: "postgres@sha256:" + strings.Repeat("a", 64),
		}},
		VolumeBackupPosture: []store.AIAuditVolumeBackupPosture{{
			ServiceID: serviceID, VolumeName: "uploads", StorageNodeID: "nodeabc123", PolicyEnabled: true,
			IntervalSeconds: 3600, Quiesce: true, LastBackupStatus: "succeeded", LastBackupAt: &now,
		}},
	}
	findings := deterministicAuditFindings(snapshot, now)
	titles := map[string]bool{}
	for _, finding := range findings {
		titles[finding.Title] = true
	}
	for _, title := range []string{"Database backup artifact metadata is invalid", "Volume backup artifact metadata is invalid"} {
		if !titles[title] {
			t.Fatalf("missing finding %q in %#v", title, findings)
		}
	}
}

func TestDeterministicAuditDetectsMaintenanceAndQuotaPressure(t *testing.T) {
	now := time.Now().UTC()
	nine, ten, two := 9, 10, 2
	snapshot := store.AIAuditSnapshot{
		Organization:        uuid.New(),
		IdentityPosture:     store.AIAuditIdentityPosture{RequireSSO: true, ActiveOwners: 1},
		NotificationPosture: fullyCoveredNotifications(),
		ResourcePolicies: []store.AIAuditResourcePolicyPosture{
			{ScopeType: "organization", ScopeID: uuid.New(), Maintenance: true, MaxProjects: &ten, CurrentProjects: nine, UpdatedAt: now.Add(-time.Hour)},
			{ScopeType: "environment", ScopeID: uuid.New(), MaxServices: &two, CurrentServices: two, UpdatedAt: now},
		},
	}
	findings := deterministicAuditFindings(snapshot, now)
	titles := map[string]int{}
	for _, finding := range findings {
		titles[finding.Title]++
	}
	if len(findings) != 3 || titles["Maintenance mode is active"] != 1 || titles["Resource quota is nearly exhausted"] != 1 || titles["Resource quota is exhausted"] != 1 {
		t.Fatalf("policy findings=%#v", findings)
	}
}

func TestDeterministicAuditDetectsSAMLTrustExpiryAndInvalidConfiguration(t *testing.T) {
	now := time.Now().UTC()
	soon, later := now.Add(29*24*time.Hour), now.Add(31*24*time.Hour)
	invalidID, expiringID, healthyID := uuid.New(), uuid.New(), uuid.New()
	snapshot := store.AIAuditSnapshot{
		Organization:        uuid.New(),
		IdentityPosture:     store.AIAuditIdentityPosture{RequireSSO: true, ActiveOwners: 1},
		NotificationPosture: fullyCoveredNotifications(),
		SAMLPosture: []store.AIAuditSAMLProviderPosture{
			{ID: invalidID},
			{ID: expiringID, CertificateConfigurationOK: true, SPCertificateNotAfter: &soon, IDPCertificateNotAfter: &later},
			{ID: healthyID, CertificateConfigurationOK: true, SPCertificateNotAfter: &later, IDPCertificateNotAfter: &later},
		},
	}
	findings := deterministicAuditFindings(snapshot, now)
	if len(findings) != 2 || findings[0].Title != "SAML certificate configuration is invalid" || findings[0].ResourceID != invalidID.String() || findings[1].Title != "SAML trust certificate expires soon" || findings[1].ResourceID != expiringID.String() {
		t.Fatalf("SAML posture findings=%#v", findings)
	}
}

func TestDeterministicAuditDetectsAuditArchiveDurabilityGaps(t *testing.T) {
	now := time.Now().UTC()
	failedAt, staleEvent, recentEvent := now.Add(-time.Minute), now.Add(-6*time.Minute), now.Add(-4*time.Minute)
	failedID, recentID, disabledID := uuid.New(), uuid.New(), uuid.New()
	snapshot := store.AIAuditSnapshot{
		Organization:        uuid.New(),
		IdentityPosture:     store.AIAuditIdentityPosture{RequireSSO: true, ActiveOwners: 1},
		NotificationPosture: fullyCoveredNotifications(),
		AuditLogPosture: store.AIAuditLogPosture{
			RetentionDays: 730, CurrentMaxEventID: 42, EnabledArchives: 2, DisabledArchives: 1,
			Destinations: []store.AIAuditArchivePosture{
				{ID: failedID, Enabled: true, RetentionDays: 730, LastArchivedID: 40, UnarchivedEvents: 2, OldestUnarchivedAt: &staleEvent, LatestBatchStatus: "failed", LatestBatchFinishedAt: &failedAt},
				{ID: recentID, Enabled: true, RetentionDays: 730, LastArchivedID: 41, UnarchivedEvents: 1, OldestUnarchivedAt: &recentEvent, LatestBatchStatus: "pending"},
				{ID: disabledID, RetentionDays: 730, UnarchivedEvents: 100, OldestUnarchivedAt: &staleEvent, LatestBatchStatus: "failed"},
			},
		},
	}
	findings := deterministicAuditFindings(snapshot, now)
	if len(findings) != 2 || findings[0].Title != "Immutable audit archive delivery failed" || findings[1].Title != "Immutable audit archive is behind" {
		t.Fatalf("archive findings=%#v", findings)
	}
	for _, finding := range findings {
		if finding.ResourceID != failedID.String() {
			t.Fatalf("unexpected archive resource: %#v", finding)
		}
	}
}

func TestDeterministicAuditDetectsMissingImmutableAuditArchive(t *testing.T) {
	snapshot := store.AIAuditSnapshot{
		Organization:        uuid.New(),
		IdentityPosture:     store.AIAuditIdentityPosture{RequireSSO: true, ActiveOwners: 1},
		NotificationPosture: fullyCoveredNotifications(),
		AuditLogPosture:     store.AIAuditLogPosture{RetentionDays: 365, DisabledArchives: 1},
	}
	findings := deterministicAuditFindings(snapshot, time.Now().UTC())
	if len(findings) != 1 || findings[0].Title != "Immutable audit archive is not enabled" || findings[0].Severity != "medium" {
		t.Fatalf("missing archive findings=%#v", findings)
	}
}

func TestDeterministicAuditDetectsPlaintextPublicRoutes(t *testing.T) {
	insecureID := uuid.New()
	snapshot := store.AIAuditSnapshot{
		Organization:        uuid.New(),
		IdentityPosture:     store.AIAuditIdentityPosture{RequireSSO: true, ActiveOwners: 1},
		NotificationPosture: fullyCoveredNotifications(),
		Routes: []store.AIAuditRouteInfo{
			{ID: insecureID, ComposeServiceID: uuid.New(), Host: "legacy.example.test", PathPrefix: "/", TargetPort: 8080},
			{ID: uuid.New(), ComposeServiceID: uuid.New(), Host: "retired.example.test", PathPrefix: "/", TargetPort: 8080, Disabled: true},
			{ID: uuid.New(), ComposeServiceID: uuid.New(), Host: "secure.example.test", PathPrefix: "/", TargetPort: 8443, TLS: true, CertificateResolver: "letsencrypt"},
		},
	}
	findings := deterministicAuditFindings(snapshot, time.Now().UTC())
	if len(findings) != 1 || findings[0].Title != "Public route permits plaintext HTTP" || findings[0].ResourceID != insecureID.String() || findings[0].Severity != "medium" {
		t.Fatalf("route findings=%#v", findings)
	}
}

func TestDeterministicAuditDetectsCustomTLSCertificateValidityRisks(t *testing.T) {
	now := time.Date(2026, 8, 31, 12, 0, 0, 0, time.UTC)
	expiredID, futureID, activeExpiringID, unusedExpiringID := uuid.New(), uuid.New(), uuid.New(), uuid.New()
	snapshot := store.AIAuditSnapshot{
		Organization:        uuid.New(),
		IdentityPosture:     store.AIAuditIdentityPosture{RequireSSO: true, ActiveOwners: 1},
		NotificationPosture: fullyCoveredNotifications(),
		CustomTLSPosture: []store.AIAuditCustomTLSPosture{
			{ID: expiredID, NotBefore: now.Add(-90 * 24 * time.Hour), NotAfter: now.Add(-time.Minute), Revision: 2, AttachedRoutes: 1, EnabledRoutes: 1},
			{ID: futureID, NotBefore: now.Add(time.Hour), NotAfter: now.Add(90 * 24 * time.Hour), Revision: 1, AttachedRoutes: 1, EnabledRoutes: 1},
			{ID: activeExpiringID, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(29 * 24 * time.Hour), Revision: 3, AttachedRoutes: 2, EnabledRoutes: 2},
			{ID: unusedExpiringID, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(29 * 24 * time.Hour), Revision: 1},
			{ID: uuid.New(), NotBefore: now.Add(-time.Hour), NotAfter: now.Add(31 * 24 * time.Hour), Revision: 1},
		},
	}
	findings := deterministicAuditFindings(snapshot, now)
	want := []struct {
		title    string
		severity string
		id       uuid.UUID
	}{
		{title: "Custom TLS certificate has expired", severity: "critical", id: expiredID},
		{title: "Custom TLS certificate is not yet valid", severity: "high", id: futureID},
		{title: "Custom TLS certificate expires soon", severity: "high", id: activeExpiringID},
		{title: "Custom TLS certificate expires soon", severity: "medium", id: unusedExpiringID},
	}
	if len(findings) != len(want) {
		t.Fatalf("custom TLS validity findings=%#v", findings)
	}
	for index := range want {
		if findings[index].Title != want[index].title || findings[index].Severity != want[index].severity || findings[index].ResourceID != want[index].id.String() {
			t.Fatalf("custom TLS validity finding %d=%#v, want %#v", index, findings[index], want[index])
		}
		if _, exposed := findings[index].Evidence["certificatePem"]; exposed {
			t.Fatalf("custom TLS finding exposed certificate material: %#v", findings[index])
		}
	}
}

func TestDeterministicAuditDetectsCustomTLSEdgeReconciliationRisks(t *testing.T) {
	now := time.Date(2026, 8, 31, 12, 0, 0, 0, time.UTC)
	errorClusterID, stalledClusterID, freshClusterID, inconsistentClusterID, healthyClusterID := uuid.New(), uuid.New(), uuid.New(), uuid.New(), uuid.New()
	snapshot := store.AIAuditSnapshot{
		Organization:        uuid.New(),
		IdentityPosture:     store.AIAuditIdentityPosture{RequireSSO: true, ActiveOwners: 1},
		NotificationPosture: fullyCoveredNotifications(),
		EdgeTLSPosture: []store.AIAuditEdgeTLSPosture{
			{TargetKey: errorClusterID.String(), ClusterID: &errorClusterID, Generation: 3, AppliedGeneration: 2, Status: "error", UpdatedAt: now.Add(-time.Minute)},
			{TargetKey: stalledClusterID.String(), ClusterID: &stalledClusterID, Generation: 4, AppliedGeneration: 3, Status: "pending", UpdatedAt: now.Add(-6 * time.Minute)},
			{TargetKey: freshClusterID.String(), ClusterID: &freshClusterID, Generation: 2, AppliedGeneration: 1, Status: "pending", UpdatedAt: now.Add(-time.Minute)},
			{TargetKey: inconsistentClusterID.String(), ClusterID: &inconsistentClusterID, Generation: 8, AppliedGeneration: 7, Status: "ready", UpdatedAt: now},
			{TargetKey: healthyClusterID.String(), ClusterID: &healthyClusterID, Generation: 5, AppliedGeneration: 5, Status: "ready", UpdatedAt: now},
		},
	}
	findings := deterministicAuditFindings(snapshot, now)
	want := []struct {
		title    string
		severity string
		id       uuid.UUID
	}{
		{title: "Custom TLS edge reconciliation failed", severity: "critical", id: errorClusterID},
		{title: "Custom TLS edge reconciliation is stalled", severity: "high", id: stalledClusterID},
		{title: "Custom TLS edge reconciliation state is inconsistent", severity: "high", id: inconsistentClusterID},
	}
	if len(findings) != len(want) {
		t.Fatalf("custom TLS edge findings=%#v", findings)
	}
	for index := range want {
		if findings[index].Title != want[index].title || findings[index].Severity != want[index].severity || findings[index].ResourceID != want[index].id.String() {
			t.Fatalf("custom TLS edge finding %d=%#v, want %#v", index, findings[index], want[index])
		}
		if _, exposed := findings[index].Evidence["lastError"]; exposed {
			t.Fatalf("custom TLS edge finding exposed reconciliation error: %#v", findings[index])
		}
	}
}

func TestDeterministicAuditDetectsMissingCustomTLSEdgeTarget(t *testing.T) {
	environmentID, serviceID, certificateID := uuid.New(), uuid.New(), uuid.New()
	snapshot := store.AIAuditSnapshot{
		Organization:        uuid.New(),
		IdentityPosture:     store.AIAuditIdentityPosture{RequireSSO: true, ActiveOwners: 1},
		NotificationPosture: fullyCoveredNotifications(),
		Environments:        []store.AIAuditEnvironmentInfo{{ID: environmentID}},
		Services:            []store.AIAuditServiceInfo{{ID: serviceID, EnvironmentID: environmentID}},
		Routes: []store.AIAuditRouteInfo{
			{ID: uuid.New(), ComposeServiceID: serviceID, Host: "app.example.test", TLS: true, CustomCertificateID: &certificateID},
			{ID: uuid.New(), ComposeServiceID: serviceID, Host: "api.example.test", TLS: true, CustomCertificateID: &certificateID},
			{ID: uuid.New(), ComposeServiceID: serviceID, Host: "disabled.example.test", TLS: true, CustomCertificateID: &certificateID, Disabled: true},
		},
	}
	findings := deterministicAuditFindings(snapshot, time.Now().UTC())
	if len(findings) != 1 || findings[0].Title != "Custom TLS edge target is missing" || findings[0].Severity != "critical" || findings[0].ResourceID != "local" {
		t.Fatalf("missing custom TLS edge target findings=%#v", findings)
	}
	snapshot.EdgeTLSPosture = []store.AIAuditEdgeTLSPosture{{TargetKey: "local", Generation: 1, AppliedGeneration: 1, Status: "ready", UpdatedAt: time.Now().UTC()}}
	if findings = deterministicAuditFindings(snapshot, time.Now().UTC()); len(findings) != 0 {
		t.Fatalf("ready custom TLS edge target produced findings=%#v", findings)
	}
}

func TestDeterministicAuditDetectsManagedNetworkLifecycleRisks(t *testing.T) {
	now := time.Date(2026, 8, 31, 12, 0, 0, 0, time.UTC)
	failedID, stalledID, freshID, readyID, clusterID := uuid.New(), uuid.New(), uuid.New(), uuid.New(), uuid.New()
	snapshot := store.AIAuditSnapshot{
		Organization:        uuid.New(),
		IdentityPosture:     store.AIAuditIdentityPosture{RequireSSO: true, ActiveOwners: 1},
		NotificationPosture: fullyCoveredNotifications(),
		ManagedNetworks: []store.AIAuditManagedNetworkInfo{
			{ID: failedID, ClusterID: &clusterID, Driver: "overlay", Status: "error", UpdatedAt: now},
			{ID: stalledID, Driver: "overlay", Status: "provisioning", UpdatedAt: now.Add(-16 * time.Minute)},
			{ID: freshID, Driver: "overlay", Status: "provisioning", UpdatedAt: now.Add(-time.Minute)},
			{ID: readyID, Driver: "overlay", Status: "ready", UpdatedAt: now.Add(-24 * time.Hour)},
		},
	}
	findings := deterministicAuditFindings(snapshot, now)
	if len(findings) != 2 || findings[0].Title != "Managed network provisioning failed" || findings[0].ResourceID != failedID.String() || findings[0].Evidence["scope"] != "remote" || findings[1].Title != "Managed network provisioning is stalled" || findings[1].ResourceID != stalledID.String() || findings[1].Evidence["scope"] != "local" {
		t.Fatalf("managed network findings=%#v", findings)
	}
}

func TestDeterministicAuditDetectsWorkloadImageProvenanceGaps(t *testing.T) {
	invalidID, missingSnapshotID, invalidRuntimeID, mutableID, incompleteID, healthyID := uuid.New(), uuid.New(), uuid.New(), uuid.New(), uuid.New(), uuid.New()
	snapshot := store.AIAuditSnapshot{
		Organization:        uuid.New(),
		IdentityPosture:     store.AIAuditIdentityPosture{RequireSSO: true, ActiveOwners: 1},
		NotificationPosture: fullyCoveredNotifications(),
		WorkloadPosture: []store.AIAuditWorkloadPosture{
			{ServiceID: invalidID},
			{ServiceID: missingSnapshotID, DefinitionParseable: true, ContainerCount: 1, MutableImages: 1, SuccessfulDeployment: true},
			{ServiceID: invalidRuntimeID, DefinitionParseable: true, ContainerCount: 1, MutableImages: 1, SuccessfulDeployment: true, RuntimeSnapshotAvailable: true},
			{ServiceID: mutableID, DefinitionParseable: true, ContainerCount: 2, MutableImages: 2, SuccessfulDeployment: true, RuntimeSnapshotAvailable: true, RuntimeDefinitionParseable: true, RuntimeContainerCount: 2, RuntimeMutableImages: 1, RuntimeDigestPinnedImages: 1},
			{ServiceID: incompleteID, DefinitionParseable: true, ContainerCount: 1, MissingImageOrBuild: 1},
			{ServiceID: healthyID, DefinitionParseable: true, ContainerCount: 2, MutableImages: 1, BuildOnlyServices: 1, SuccessfulDeployment: true, RuntimeSnapshotAvailable: true, RuntimeDefinitionParseable: true, RuntimeContainerCount: 2, RuntimeDigestPinnedImages: 2},
		},
	}
	findings := deterministicAuditFindings(snapshot, time.Now().UTC())
	want := []struct {
		title string
		id    uuid.UUID
	}{
		{title: "Workload definition cannot be audited", id: invalidID},
		{title: "Successful deployment lacks immutable runtime snapshot", id: missingSnapshotID},
		{title: "Deployed runtime snapshot cannot be audited", id: invalidRuntimeID},
		{title: "Deployed workload uses mutable container images", id: mutableID},
		{title: "Workload services lack an image or build source", id: incompleteID},
	}
	if len(findings) != len(want) {
		t.Fatalf("workload findings=%#v", findings)
	}
	for index := range want {
		if findings[index].Title != want[index].title || findings[index].ResourceID != want[index].id.String() {
			t.Fatalf("workload findings=%#v", findings)
		}
	}
}

func TestDeterministicAuditDetectsSourceBuildTrustGaps(t *testing.T) {
	invalidID, sshID, dropID, pendingID, provenanceID, healthyID := uuid.New(), uuid.New(), uuid.New(), uuid.New(), uuid.New(), uuid.New()
	snapshot := store.AIAuditSnapshot{
		Organization:        uuid.New(),
		IdentityPosture:     store.AIAuditIdentityPosture{RequireSSO: true, ActiveOwners: 1},
		NotificationPosture: fullyCoveredNotifications(),
		SourceBuildPosture: []store.AIAuditSourceBuildPosture{
			{ServiceID: invalidID, SourceType: "git", BuildType: "dockerfile", RepositoryTransport: "invalid", CurrentSourceDeployed: true, DeploymentCommitRecorded: true},
			{ServiceID: sshID, SourceType: "git", BuildType: "dockerfile", RepositoryTransport: "ssh", CurrentSourceDeployed: true, DeploymentCommitRecorded: true},
			{ServiceID: dropID, SourceType: "drop", BuildType: "static", CurrentSourceDeployed: true},
			{ServiceID: pendingID, SourceType: "git", BuildType: "railpack", RepositoryTransport: "https", GitCredentialConfigured: true},
			{ServiceID: provenanceID, SourceType: "git", BuildType: "nixpacks", RepositoryTransport: "https", CurrentSourceDeployed: true},
			{ServiceID: healthyID, SourceType: "git", BuildType: "buildpacks", RepositoryTransport: "https", CurrentSourceDeployed: true, DeploymentCommitRecorded: true},
		},
	}
	findings := deterministicAuditFindings(snapshot, time.Now().UTC())
	want := []struct {
		title string
		id    uuid.UUID
	}{
		{title: "Source repository transport is invalid", id: invalidID},
		{title: "SSH source has no pinned-host credential", id: sshID},
		{title: "Uploaded source artifact is unavailable", id: dropID},
		{title: "Current source configuration has not been deployed", id: pendingID},
		{title: "Source deployment lacks commit provenance", id: provenanceID},
	}
	if len(findings) != len(want) {
		t.Fatalf("source findings=%#v", findings)
	}
	for index := range want {
		if findings[index].Title != want[index].title || findings[index].ResourceID != want[index].id.String() {
			t.Fatalf("source finding %d=%#v, want %#v", index, findings[index], want[index])
		}
	}
}

func TestDeterministicAuditDetectsElevatedOperationalFailureRates(t *testing.T) {
	organizationID := uuid.New()
	snapshot := store.AIAuditSnapshot{
		Organization:        organizationID,
		IdentityPosture:     store.AIAuditIdentityPosture{RequireSSO: true, ActiveOwners: 1},
		NotificationPosture: fullyCoveredNotifications(),
		Signals: []store.AIAuditSignal{
			{Kind: "deployment", Status: "succeeded", Count: 3},
			{Kind: "deployment", Status: "failed", Count: 1},
			{Kind: "deployment", Status: "cancelled", Count: 100},
			{Kind: "backup", Status: "succeeded", Count: 2},
			{Kind: "backup", Status: "failed", Count: 2},
			{Kind: "restore", Status: "succeeded", Count: 4},
			{Kind: "notification", Status: "failed", Count: 3},
			{Kind: "ai_audit", Status: "succeeded", Count: 1},
			{Kind: "ai_audit", Status: "failed", Count: 3},
		},
	}
	findings := deterministicAuditFindings(snapshot, time.Now().UTC())
	if len(findings) != 3 || findings[0].Title != "Deployments have an elevated failure rate" || findings[0].Severity != "medium" || findings[1].Title != "Database backups have an elevated failure rate" || findings[1].Severity != "high" || findings[2].Title != "AI audit runs have an elevated failure rate" || findings[2].Severity != "high" {
		t.Fatalf("operational signal findings=%#v", findings)
	}
}

func TestDeterministicAuditDetectsExhaustedNotificationDelivery(t *testing.T) {
	now := time.Now().UTC()
	endpointID := uuid.New()
	posture := fullyCoveredNotifications()
	posture[0].ID = endpointID
	posture[0].Kind = "webhook"
	posture[0].ExhaustedFailures = 2
	oldest := now.Add(-time.Hour)
	posture[0].OldestExhaustedFailureAt = &oldest
	snapshot := store.AIAuditSnapshot{Organization: uuid.New(), IdentityPosture: store.AIAuditIdentityPosture{RequireSSO: true, ActiveOwners: 1}, NotificationPosture: posture}
	findings := deterministicAuditFindings(snapshot, now)
	if len(findings) != 1 || findings[0].Title != "Notification delivery requires intervention" || findings[0].Severity != "high" || findings[0].ResourceType != "notification_endpoint" || findings[0].ResourceID != endpointID.String() || findings[0].Evidence["exhaustedFailures"] != int64(2) {
		t.Fatalf("notification delivery findings=%#v", findings)
	}
	posture[0].ExhaustedFailures = 0
	posture[0].ActiveDeliveries = 1
	posture[0].OldestExhaustedFailureAt = nil
	snapshot.NotificationPosture = posture
	if findings = deterministicAuditFindings(snapshot, now); len(findings) != 0 {
		t.Fatalf("active retry produced terminal finding=%#v", findings)
	}
}

func TestDeterministicAuditDetectsExhaustedCommitStatusDelivery(t *testing.T) {
	now := time.Now().UTC()
	deploymentID, serviceID := uuid.New(), uuid.New()
	snapshot := store.AIAuditSnapshot{
		Organization:        uuid.New(),
		IdentityPosture:     store.AIAuditIdentityPosture{RequireSSO: true, ActiveOwners: 1},
		NotificationPosture: fullyCoveredNotifications(),
		CommitStatusPosture: []store.AIAuditCommitStatusPosture{{DeploymentID: deploymentID, ServiceID: serviceID, Provider: "github", State: "failure", ExhaustedFailures: 1, OldestExhaustedFailureAt: now.Add(-time.Hour)}},
	}
	findings := deterministicAuditFindings(snapshot, now)
	if len(findings) != 1 || findings[0].Title != "Commit status delivery requires intervention" || findings[0].Severity != "high" || findings[0].ResourceType != "deployment" || findings[0].ResourceID != deploymentID.String() || findings[0].Evidence["serviceId"] != serviceID.String() {
		t.Fatalf("commit status delivery findings=%#v", findings)
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
		Databases:           []store.AIAuditDatabaseInfo{{ID: unsupportedID, Engine: "custom", Version: "1", DriverSource: "external", DriverDigest: digest}, {ID: missingID, Engine: "removed", Version: "2", DriverSource: "external", DriverDigest: digest}, {ID: protectedID, Engine: "postgres", Version: "17", DriverSource: "built-in"}},
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
		Databases:           []store.AIAuditDatabaseInfo{{ID: unboundID, Engine: "custom", Version: "1", DriverSource: "unbound"}, {ID: mismatchID, Engine: "custom", Version: "1", DriverSource: "external", DriverDigest: "sha256:" + strings.Repeat("b", 64)}},
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

func TestDeterministicAuditDetectsUnhealthyManagedDatabase(t *testing.T) {
	errorID := uuid.New()
	snapshot := store.AIAuditSnapshot{
		Organization:        uuid.New(),
		IdentityPosture:     store.AIAuditIdentityPosture{RequireSSO: true, ActiveOwners: 1},
		NotificationPosture: fullyCoveredNotifications(),
		Databases: []store.AIAuditDatabaseInfo{
			{ID: errorID, Engine: "postgres", Version: "17", Status: "error"},
			{ID: uuid.New(), Engine: "redis", Version: "8", Status: "pending"},
			{ID: uuid.New(), Engine: "mysql", Version: "9", Status: "running"},
			{ID: uuid.New(), Engine: "mariadb", Version: "11", Status: "ready"},
		},
	}
	findings := deterministicAuditFindings(snapshot, time.Now().UTC())
	if len(findings) != 1 || findings[0].Title != "Managed database deployment is unhealthy" || findings[0].ResourceID != errorID.String() || findings[0].Severity != "high" {
		t.Fatalf("database lifecycle findings=%#v", findings)
	}
}

func TestDeterministicAuditDetectsRemoteClusterCapacityAndCapabilityFailures(t *testing.T) {
	now := time.Date(2026, 8, 31, 12, 0, 0, 0, time.UTC)
	clusterID, environmentID := uuid.New(), uuid.New()
	snapshot := store.AIAuditSnapshot{
		Organization:        uuid.New(),
		IdentityPosture:     store.AIAuditIdentityPosture{RequireSSO: true, ActiveOwners: 1},
		NotificationPosture: fullyCoveredNotifications(),
		Clusters: []store.AIAuditClusterInfo{{
			ID: clusterID, State: "active", AgentImage: "registry.example/dockyard@sha256:" + strings.Repeat("a", 64), LastSeenAt: &now,
			Nodes: 3, ReadyNodes: 2, ActiveNodes: 1, SchedulableNodes: 0, Managers: 0,
			NanoCPUs: 2_000_000_000, MemoryBytes: 4_000_000_000,
			EdgeProxyConfigured: true, EdgeProxyStatus: "network_missing",
		}},
		Environments: []store.AIAuditEnvironmentInfo{{
			ID: environmentID, ClusterID: &clusterID, MinimumNodes: 2, MinimumNanoCPUs: 4_000_000_000, MinimumMemoryBytes: 8_000_000_000,
		}},
	}
	findings := deterministicAuditFindings(snapshot, now)
	titles := map[string]modelFinding{}
	for _, finding := range findings {
		titles[finding.Title] = finding
	}
	for _, title := range []string{
		"Remote cluster has no manager",
		"Remote cluster has no schedulable node",
		"Remote cluster nodes are not ready",
		"Remote cluster nodes are drained",
		"Remote cluster capability contract is incomplete",
		"Remote edge proxy is not ready",
		"Remote cluster does not meet environment capacity requirements",
	} {
		if _, exists := titles[title]; !exists {
			t.Errorf("missing %q in %#v", title, findings)
		}
	}
	if len(findings) != 7 {
		t.Fatalf("capacity findings=%d, want 7: %#v", len(findings), findings)
	}
	if finding := titles["Remote cluster does not meet environment capacity requirements"]; finding.ResourceID != environmentID.String() || finding.Evidence["clusterId"] != clusterID.String() {
		t.Fatalf("environment capacity evidence=%#v", finding)
	}
}

func TestDeterministicAuditDetectsLocalClusterFailures(t *testing.T) {
	now := time.Date(2026, 8, 31, 12, 0, 0, 0, time.UTC)
	snapshot := store.AIAuditSnapshot{
		Organization:        uuid.New(),
		IdentityPosture:     store.AIAuditIdentityPosture{RequireSSO: true, ActiveOwners: 1},
		NotificationPosture: fullyCoveredNotifications(),
		LocalCluster: &clustercontract.LocalPosture{
			ObservedAt: now, InspectionStatus: clustercontract.LocalInspectionReady,
			Nodes: 3, ReadyNodes: 2, ActiveNodes: 1, SchedulableNodes: 0,
			EdgeProxyConfigured: true, EdgeProxyStatus: "inspection_failed",
		},
	}
	findings := deterministicAuditFindings(snapshot, now)
	titles := map[string]bool{}
	for _, finding := range findings {
		titles[finding.Title] = true
		if finding.ResourceType == "local_cluster" && finding.ResourceID != "local" {
			t.Fatalf("local finding exposed an unexpected identity: %#v", finding)
		}
	}
	for _, title := range []string{"Local Swarm has no manager", "Local Swarm has no schedulable node", "Local Swarm nodes are not ready", "Local Swarm nodes are drained", "Local runtime capability is missing", "Local edge proxy is not ready"} {
		if !titles[title] {
			t.Errorf("missing %q in %#v", title, findings)
		}
	}
	if len(findings) != 6 {
		t.Fatalf("local cluster findings=%d, want 6: %#v", len(findings), findings)
	}
}

func TestDeterministicAuditDoesNotTrustFailedOrStaleLocalInspection(t *testing.T) {
	now := time.Date(2026, 8, 31, 12, 0, 0, 0, time.UTC)
	base := store.AIAuditSnapshot{Organization: uuid.New(), IdentityPosture: store.AIAuditIdentityPosture{RequireSSO: true, ActiveOwners: 1}, NotificationPosture: fullyCoveredNotifications()}
	failed := base
	failed.LocalCluster = &clustercontract.LocalPosture{ObservedAt: now, InspectionStatus: clustercontract.LocalInspectionFailed}
	if findings := deterministicAuditFindings(failed, now); len(findings) != 1 || findings[0].Title != "Local Swarm inspection failed" {
		t.Fatalf("failed local inspection findings=%#v", findings)
	}
	stale := base
	stale.LocalCluster = &clustercontract.LocalPosture{ObservedAt: now.Add(-3 * time.Minute), InspectionStatus: clustercontract.LocalInspectionReady, Nodes: 1, ReadyNodes: 1, ActiveNodes: 1, SchedulableNodes: 1, Managers: 1, DockerSwarm: true, DockerCompose: true}
	if findings := deterministicAuditFindings(stale, now); len(findings) != 1 || findings[0].Title != "Local Swarm posture is stale" {
		t.Fatalf("stale local posture findings=%#v", findings)
	}
}

func TestDeterministicAuditDoesNotTrustStaleClusterCapacity(t *testing.T) {
	now := time.Date(2026, 8, 31, 12, 0, 0, 0, time.UTC)
	stale := now.Add(-3 * time.Minute)
	snapshot := store.AIAuditSnapshot{
		Organization:        uuid.New(),
		IdentityPosture:     store.AIAuditIdentityPosture{RequireSSO: true, ActiveOwners: 1},
		NotificationPosture: fullyCoveredNotifications(),
		Clusters:            []store.AIAuditClusterInfo{{ID: uuid.New(), State: "active", AgentImage: "registry.example/dockyard@sha256:" + strings.Repeat("a", 64), LastSeenAt: &stale}},
	}
	findings := deterministicAuditFindings(snapshot, now)
	if len(findings) != 1 || findings[0].Title != "Remote cluster heartbeat is stale" {
		t.Fatalf("stale cluster findings=%#v", findings)
	}
}

func TestDeterministicAuditAcceptsClusterOnActiveCertificateAuthority(t *testing.T) {
	now := time.Now().UTC()
	snapshot := store.AIAuditSnapshot{
		Organization:    uuid.New(),
		IdentityPosture: store.AIAuditIdentityPosture{RequireSSO: true, ActiveOwners: 1},
		AgentCAPosture:  store.AIAuditAgentCAPosture{Configured: true, ActiveFingerprint: "sha256:active"},
		Clusters:        []store.AIAuditClusterInfo{{ID: uuid.New(), State: "active", AgentImage: "registry.example/dockyard@sha256:" + strings.Repeat("a", 64), CertificateAuthorityFingerprint: "sha256:active", LastSeenAt: &now, Nodes: 1, ReadyNodes: 1, ActiveNodes: 1, SchedulableNodes: 1, Managers: 1, DockerSwarm: true, DockerCompose: true}},
	}
	for _, finding := range deterministicAuditFindings(snapshot, now) {
		if finding.Title == "Remote cluster uses a non-active certificate authority" || finding.Title == "Previous agent certificate authority remains trusted" {
			t.Fatalf("healthy CA posture produced finding: %#v", finding)
		}
	}
}

func TestDeterministicAuditFindingsAreBounded(t *testing.T) {
	organizationID := uuid.New()
	snapshot := store.AIAuditSnapshot{Organization: organizationID, IdentityPosture: store.AIAuditIdentityPosture{RequireSSO: true, ActiveOwners: 1}, NotificationPosture: fullyCoveredNotifications()}
	for range maxDeterministicAuditFindings + 10 {
		snapshot.BackupPosture = append(snapshot.BackupPosture, store.AIAuditBackupPosture{DatabaseID: uuid.New(), Engine: "postgres"})
	}
	criticalID := uuid.New()
	snapshot.VolumeRestorePosture = append(snapshot.VolumeRestorePosture, store.AIAuditVolumeRestorePosture{ID: criticalID, ServiceID: uuid.New(), Status: "failed", CreatedAt: time.Now().Add(-time.Hour)})
	findings := deterministicAuditFindings(snapshot, time.Now())
	if len(findings) != maxDeterministicAuditFindings || findings[0].Title != "Offline volume recovery failed" || findings[0].ResourceID != criticalID.String() || findings[len(findings)-1].Title != "Deterministic audit findings were truncated" {
		t.Fatalf("bounded findings=%d last=%#v", len(findings), findings[len(findings)-1])
	}
	overflow := findings[len(findings)-1]
	if overflow.Severity != "high" || overflow.ResourceID != organizationID.String() || overflow.Evidence["detected"] != maxDeterministicAuditFindings+11 || overflow.Evidence["omitted"] != 12 {
		t.Fatalf("overflow finding=%#v", overflow)
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
				"notificationPosture": []map[string]any{{"enabled": true, "events": []string{"deployment.failed", "service.stop.failed", "service.schedule.failed", "backup.failed", "restore.failed", "restore.drill.failed", "database.migration.failed", "commit.status.failed", "network.provision.failed", "network.delete.failed", "resource.delete.failed", "edge.certificate.reconcile.failed", "template.sync.failed", "agent.upgrade.failed", "audit.archive.failed", "ai.audit.failed", "ai.finding.critical"}}},
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

func TestPerformAIAuditRejectsOversizedSnapshotBeforeCreatingRun(t *testing.T) {
	var runRequests, modelRequests int
	platform := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/ai/audit-snapshot":
			_, _ = w.Write([]byte(`{"projects":[{"description":"` + strings.Repeat("x", maxAuditSnapshotBytes) + `"}]}`))
		case "/v1/ai/audit-runs":
			runRequests++
			w.WriteHeader(http.StatusCreated)
		default:
			t.Fatalf("unexpected platform request %s %s", r.Method, r.URL.Path)
		}
	}))
	defer platform.Close()
	model := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		modelRequests++
	}))
	defer model.Close()

	err := performAIAudit(context.Background(), platform.Client(), auditorConfig{
		DockyardURL: platform.URL, DockyardToken: "auditor-token",
		ModelURL: model.URL, Model: "test", Focus: "security",
	})
	if err == nil || !strings.Contains(err.Error(), "snapshot exceeds 8 MiB") {
		t.Fatalf("oversized snapshot error=%v", err)
	}
	if runRequests != 0 || modelRequests != 0 {
		t.Fatalf("oversized snapshot created %d run(s) and %d model request(s)", runRequests, modelRequests)
	}
}

func TestPerformAIAuditDoesNotPersistControlPlaneErrorBody(t *testing.T) {
	const responseSecret = "upstream-response-secret"
	completion := map[string]string{}
	platform := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/v1/ai/audit-snapshot":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"identityPosture":     map[string]any{"requireSso": true, "activeOwners": 1},
				"notificationPosture": fullyCoveredNotifications(),
			})
		case r.URL.Path == "/v1/ai/audit-runs":
			w.WriteHeader(http.StatusCreated)
			_ = json.NewEncoder(w).Encode(map[string]string{"id": "00000000-0000-0000-0000-000000000001"})
		case r.Method == http.MethodPost:
			http.Error(w, responseSecret, http.StatusInternalServerError)
		case r.Method == http.MethodPatch:
			if err := json.NewDecoder(r.Body).Decode(&completion); err != nil {
				t.Error(err)
			}
			w.WriteHeader(http.StatusNoContent)
		}
	}))
	defer platform.Close()
	model := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{"choices": []any{map[string]any{"message": map[string]string{"content": `{"summary":"issue found","findings":[{"severity":"low","category":"capacity","title":"Issue","description":"Description","evidence":{},"remediation":"Review"}]}`}}}})
	}))
	defer model.Close()

	err := performAIAudit(context.Background(), platform.Client(), auditorConfig{
		DockyardURL: platform.URL, DockyardToken: "auditor-token",
		ModelURL: model.URL, Model: "test", Focus: "security",
	})
	if err == nil || !strings.Contains(err.Error(), "HTTP 500") {
		t.Fatalf("control-plane failure=%v", err)
	}
	if completion["status"] != "failed" || strings.Contains(completion["summary"], responseSecret) {
		t.Fatalf("failed completion leaked upstream body: %#v", completion)
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
		"deployment.failed", "service.stop.failed", "service.schedule.failed", "backup.failed", "restore.failed", "restore.drill.failed", "database.migration.failed", "commit.status.failed", "network.provision.failed", "network.delete.failed", "resource.delete.failed", "edge.certificate.reconcile.failed", "template.sync.failed", "agent.upgrade.failed", "audit.archive.failed", "ai.audit.failed", "ai.finding.critical",
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
