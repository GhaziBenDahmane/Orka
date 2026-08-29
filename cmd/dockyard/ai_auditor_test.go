package main

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"
)

func TestPerformAIAuditLifecycle(t *testing.T) {
	var mutex sync.Mutex
	paths := []string{}
	platform := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer auditor-token" { t.Errorf("missing auditor token") }
		mutex.Lock(); paths = append(paths, r.Method+" "+r.URL.Path); mutex.Unlock()
		switch r.URL.Path {
		case "/v1/ai/audit-snapshot":
			_ = json.NewEncoder(w).Encode(map[string]any{"projects": []any{}})
		case "/v1/ai/audit-runs":
			w.WriteHeader(http.StatusCreated); _ = json.NewEncoder(w).Encode(map[string]string{"id":"00000000-0000-0000-0000-000000000001"})
		default:
			if r.Method==http.MethodPost { w.WriteHeader(http.StatusCreated) } else { w.WriteHeader(http.StatusNoContent) }
		}
	})); defer platform.Close()
	model := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter,r *http.Request){
		if r.URL.Path!="/v1/chat/completions"{t.Errorf("model path=%s",r.URL.Path)}
		_ = json.NewEncoder(w).Encode(map[string]any{"choices":[]any{map[string]any{"message":map[string]string{"content":`{"summary":"healthy","findings":[{"severity":"low","category":"capacity","title":"No projects","description":"Inventory is empty","resourceType":"organization","resourceId":"org","evidence":{},"remediation":"Create a project"}]}`}}}})
	}));defer model.Close()
	cfg:=auditorConfig{DockyardURL:platform.URL,DockyardToken:"auditor-token",ModelURL:model.URL+"/v1",Model:"test",AgentName:"test-agent",Focus:"capacity",Interval:time.Hour}
	if err:=performAIAudit(context.Background(),&http.Client{Timeout:time.Second},cfg);err!=nil{t.Fatal(err)}
	want:=[]string{"GET /v1/ai/audit-snapshot","POST /v1/ai/audit-runs","POST /v1/ai/audit-runs/00000000-0000-0000-0000-000000000001/findings","PATCH /v1/ai/audit-runs/00000000-0000-0000-0000-000000000001"}
	if len(paths)!=len(want){t.Fatalf("paths=%v",paths)};for i:=range want{if paths[i]!=want[i]{t.Fatalf("paths=%v",paths)}}
}
