package httpapi

import (
	"bytes"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/bendahma/dokploy-go/internal/observability"
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
		csp := response.Header().Get("Content-Security-Policy")
		if route == "/" && (!strings.Contains(csp, "script-src 'self'") || !strings.Contains(csp, "style-src 'self'")) {
			t.Errorf("console CSP blocks embedded assets: %q", csp)
		}
		if route == "/v1/projects" && (!strings.Contains(csp, "default-src 'none'") || response.Header().Get("Cache-Control") != "no-store") {
			t.Errorf("API response is not locked down: CSP=%q cache=%q", csp, response.Header().Get("Cache-Control"))
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

func TestInternalErrorsDoNotLeakDetails(t *testing.T) {
	var logs bytes.Buffer
	server := &Server{Logger: slog.New(slog.NewJSONHandler(&logs, nil))}
	response := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodGet, "/v1/test", nil)
	server.writeInternalError(response, request, http.StatusBadGateway, "dependency_failed", "dependency is unavailable", errors.New("password=secret-value host=private.internal"))

	if response.Code != http.StatusBadGateway || !strings.Contains(response.Body.String(), `"message":"dependency is unavailable"`) || strings.Contains(response.Body.String(), "secret-value") || strings.Contains(response.Body.String(), "private.internal") {
		t.Fatalf("unsafe internal error response: status=%d body=%s", response.Code, response.Body.String())
	}
	if strings.Contains(logs.String(), "secret-value") || strings.Contains(logs.String(), "private.internal") || !strings.Contains(logs.String(), `"operation":"dependency_failed"`) || !strings.Contains(logs.String(), `"error_type":"*errors.errorString"`) {
		t.Fatalf("unsafe or incomplete internal error log: %s", logs.String())
	}
}

func TestAgentHandlerAppliesAPIProtectionBeforeCertificateAuthentication(t *testing.T) {
	server := &Server{Logger: slog.New(slog.NewTextHandler(io.Discard, nil))}
	request := httptest.NewRequest(http.MethodPost, "/v1/agent/heartbeat", strings.NewReader(`{}`))
	response := httptest.NewRecorder()
	server.AgentHandler().ServeHTTP(response, request)

	if response.Code != http.StatusUnauthorized {
		t.Fatalf("agent API status=%d, want 401", response.Code)
	}
	if response.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("agent API cache policy=%q, want no-store", response.Header().Get("Cache-Control"))
	}
	for _, header := range []string{"Content-Security-Policy", "X-Content-Type-Options", "X-Frame-Options", "X-Request-ID"} {
		if response.Header().Get(header) == "" {
			t.Errorf("agent API response is missing %s", header)
		}
	}
}

func TestMiddlewareRedactsRecoveredPanic(t *testing.T) {
	var logs bytes.Buffer
	server := &Server{Logger: slog.New(slog.NewJSONHandler(&logs, nil)), Metrics: observability.NewMetrics()}
	handler := server.requestIDMiddleware(server.middleware(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		panic(errors.New("password=secret-value host=private.internal"))
	})))
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/v1/test", nil))

	if response.Code != http.StatusInternalServerError || strings.Contains(response.Body.String(), "secret-value") {
		t.Fatalf("unsafe panic response: status=%d body=%s", response.Code, response.Body.String())
	}
	if strings.Contains(logs.String(), "secret-value") || strings.Contains(logs.String(), "private.internal") || !strings.Contains(logs.String(), `"panic_type":"*errors.errorString"`) {
		t.Fatalf("unsafe or incomplete panic log: %s", logs.String())
	}
}
