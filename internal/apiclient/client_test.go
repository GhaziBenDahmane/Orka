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
	for _, path := range []string{"https://evil.example/path", "//evil.example/path", "/v1/../admin", "/v1//projects", "/v1/projects#fragment", "/v1/%2e%2e/admin"} {
		if err := client.Do(context.Background(), http.MethodGet, path, nil, io.Discard); err == nil {
			t.Errorf("unsafe API path %q was accepted", path)
		}
	}
}

func TestClientValidatesBaseURLAndHeaders(t *testing.T) {
	for _, rawURL := range []string{
		"ftp://dockyard.example.test",
		"https://user@dockyard.example.test",
		"https://bad_label.example.test",
		"https://-bad.example.test",
		"https://dockyard.example.test:",
		"https://dockyard.example.test:0",
		"https://dockyard.example.test:65536",
		"https://dockyard.example.test?token=secret",
		"https://dockyard.example.test#fragment",
		"https://dockyard.example.test/a/../b",
		"https://dockyard.example.test/a//b",
		"http://dockyard.example.test",
	} {
		if _, err := New(rawURL, "", ""); err == nil {
			t.Errorf("unsafe base URL %q was accepted", rawURL)
		}
	}
	for _, rawURL := range []string{"https://dockyard.example.test", "https://dockyard.example.test:8443/prefix/", "http://localhost:8080", "http://api.dev.localhost", "http://127.0.0.2", "http://[::1]:8080"} {
		if _, err := New(rawURL, "", ""); err != nil {
			t.Errorf("valid base URL %q was rejected: %v", rawURL, err)
		}
	}
	if _, err := New("https://dockyard.example.test", "token\nheader", "org"); err == nil {
		t.Fatal("token containing a line break was accepted")
	}
	if _, err := New("https://dockyard.example.test", "token", strings.Repeat("o", maxOrganizationIDBytes+1)); err == nil {
		t.Fatal("oversized organization ID was accepted")
	}
}

func TestClientBoundsSuccessfulResponses(t *testing.T) {
	t.Run("content length", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Length", "32")
			_, _ = io.WriteString(w, strings.Repeat("x", 32))
		}))
		defer server.Close()
		client, _ := New(server.URL, "", "")
		client.MaxResponseBytes = 16
		var output strings.Builder
		err := client.Do(context.Background(), http.MethodGet, "/large", nil, &output)
		if !errors.Is(err, ErrResponseTooLarge) || output.Len() != 0 {
			t.Fatalf("error=%v output bytes=%d", err, output.Len())
		}
	})
	t.Run("chunked", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			flusher := w.(http.Flusher)
			_, _ = io.WriteString(w, strings.Repeat("x", 12))
			flusher.Flush()
			_, _ = io.WriteString(w, strings.Repeat("y", 12))
		}))
		defer server.Close()
		client, _ := New(server.URL, "", "")
		client.MaxResponseBytes = 16
		var output strings.Builder
		err := client.Do(context.Background(), http.MethodGet, "/large", nil, &output)
		if !errors.Is(err, ErrResponseTooLarge) || output.Len() != 17 {
			t.Fatalf("error=%v output bytes=%d", err, output.Len())
		}
	})
}
