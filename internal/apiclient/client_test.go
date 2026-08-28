package apiclient

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestClientScopesAndEncodesRequest(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/prefix/v1/projects" || r.Header.Get("Authorization") != "Bearer secret" || r.Header.Get("X-Organization-ID") != "org" {
			t.Errorf("unexpected request: %s %#v", r.URL.Path, r.Header)
		}
		var input map[string]string
		_ = json.NewDecoder(r.Body).Decode(&input)
		_ = json.NewEncoder(w).Encode(input)
	}))
	defer server.Close()
	client, err := New(server.URL+"/prefix", "secret", "org")
	if err != nil {
		t.Fatal(err)
	}
	var output strings.Builder
	if err := client.Do(context.Background(), http.MethodPost, "/v1/projects", map[string]string{"name": "Demo"}, &output); err != nil || !strings.Contains(output.String(), "Demo") {
		t.Fatalf("output=%q err=%v", output.String(), err)
	}
}

func TestClientReturnsStructuredAPIError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusConflict)
		_, _ = io.WriteString(w, `{"error":{"code":"quota_exceeded","message":"limit reached"}}`)
	}))
	defer server.Close()
	client, _ := New(server.URL, "", "")
	err := client.Do(context.Background(), http.MethodGet, "/v1/projects", nil, io.Discard)
	var apiErr *APIError
	if !errors.As(err, &apiErr) || apiErr.Status != http.StatusConflict || apiErr.Code != "quota_exceeded" {
		t.Fatalf("error=%v", err)
	}
}

func TestClientRejectsHostOverride(t *testing.T) {
	client, _ := New("https://dockyard.example", "", "")
	if err := client.Do(context.Background(), http.MethodGet, "https://evil.example/path", nil, io.Discard); err == nil {
		t.Fatal("expected absolute API path rejection")
	}
}
