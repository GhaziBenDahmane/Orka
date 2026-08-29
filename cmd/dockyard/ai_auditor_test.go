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
			_ = json.NewEncoder(w).Encode(map[string]any{"projects": []any{}})
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
