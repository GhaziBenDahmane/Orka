package main

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestWaitForAIAuditorRunRequiresFreshCompletedNamedRun(t *testing.T) {
	since := time.Now().UTC().Truncate(time.Second)
	var requests atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/ai/audit-runs/self" || r.Header.Get("Authorization") != "Bearer verifier-token" {
			t.Errorf("request path=%s authorization=%q", r.URL.Path, r.Header.Get("Authorization"))
		}
		attempt := requests.Add(1)
		items := []map[string]any{
			{"agentName": "security-auditor", "status": "completed", "startedAt": since.Add(-time.Second)},
			{"agentName": "reliability-auditor", "status": "failed", "startedAt": since.Add(time.Second)},
		}
		if attempt >= 2 {
			items = []map[string]any{
				{"agentName": "security-auditor", "status": "completed", "startedAt": since.Add(time.Second)},
			}
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"items": items})
	}))
	defer server.Close()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := waitForAIAuditorRun(ctx, server.Client(), server.URL, "verifier-token", "security-auditor", since, time.Millisecond); err != nil {
		t.Fatal(err)
	}
	if requests.Load() != 2 {
		t.Fatalf("requests=%d, want 2", requests.Load())
	}
}

func TestWaitForAIAuditorRunFailsClosedForWrongIdentity(t *testing.T) {
	since := time.Now().UTC()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{"items": []map[string]any{{"agentName": "security-auditor", "status": "completed", "startedAt": since.Add(time.Second)}}})
	}))
	defer server.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	err := waitForAIAuditorRun(ctx, server.Client(), server.URL, "token", "reliability-auditor", since, time.Millisecond)
	if err == nil || !strings.Contains(err.Error(), "reliability-auditor") {
		t.Fatalf("error=%v", err)
	}
}

func TestVerifyAIAuditorRunsRejectsTokenLineBreaks(t *testing.T) {
	err := verifyAIAuditorRuns([]string{"--control-plane-url", "https://dockyard.example.test", "--agent-name", "security-auditor", "--since", time.Now().UTC().Format(time.RFC3339), "--timeout", "1s", "--poll-interval", "1ms"}, strings.NewReader("token\nsecond"))
	if err == nil || !strings.Contains(err.Error(), "without line breaks") {
		t.Fatalf("error=%v", err)
	}
}
