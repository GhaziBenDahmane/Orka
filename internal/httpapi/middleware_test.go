package httpapi

import (
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestRequestIDMiddleware(t *testing.T) {
	server := &Server{Logger: slog.New(slog.NewTextHandler(io.Discard, nil))}
	handler := server.Handler()

	request := httptest.NewRequest(http.MethodGet, "/not-found", nil)
	request.Header.Set("X-Request-ID", "caller-123")
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if got := response.Header().Get("X-Request-ID"); got != "caller-123" {
		t.Fatalf("request id = %q", got)
	}

	request = httptest.NewRequest(http.MethodGet, "/not-found", nil)
	request.Header.Set("X-Request-ID", "invalid request id")
	response = httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if got := response.Header().Get("X-Request-ID"); got == "" || got == "invalid request id" {
		t.Fatalf("expected generated request id, got %q", got)
	}
}

func TestHandlerSetsSecurityHeadersOnAPIAndConsole(t *testing.T) {
	server := &Server{Logger: slog.New(slog.NewTextHandler(io.Discard, nil))}
	for _, route := range []string{"/v1/projects", "/"} {
		request := httptest.NewRequest(http.MethodGet, route, nil)
		request.Header.Set("X-Forwarded-Proto", "https")
		response := httptest.NewRecorder()
		server.Handler().ServeHTTP(response, request)
		for _, header := range []string{
			"Content-Security-Policy",
			"Cross-Origin-Opener-Policy",
			"Permissions-Policy",
			"Referrer-Policy",
			"Strict-Transport-Security",
			"X-Content-Type-Options",
			"X-Frame-Options",
		} {
			if response.Header().Get(header) == "" {
				t.Errorf("%s: missing %s", route, header)
			}
		}
	}
}

func TestMetricsRequiresAuthentication(t *testing.T) {
	server := &Server{Logger: slog.New(slog.NewTextHandler(io.Discard, nil))}
	response := httptest.NewRecorder()
	server.Handler().ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	if response.Code != http.StatusUnauthorized {
		t.Fatalf("metrics status=%d, want 401", response.Code)
	}
}
