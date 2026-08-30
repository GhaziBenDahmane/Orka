package httpapi

import (
	"bytes"
	"crypto/sha256"
	"crypto/tls"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/bendahma/dokploy-go/internal/cryptox"
	"github.com/bendahma/dokploy-go/internal/observability"
	"github.com/bendahma/dokploy-go/internal/store"
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
		request.TLS = &tls.ConnectionState{}
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

func TestMetricsUsesDedicatedOperatorCredential(t *testing.T) {
	const token = "metrics-operator-token-at-least-32-bytes"
	server := &Server{
		Logger:           slog.New(slog.NewTextHandler(io.Discard, nil)),
		MetricsTokenHash: cryptox.Digest(token),
	}
	called := false
	handler := server.requireMetricsAuth(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		called = true
		w.WriteHeader(http.StatusNoContent)
	}))

	for name, authorization := range map[string]string{
		"missing":      "",
		"wrong":        "Bearer tenant-session-token",
		"malformed":    "Basic " + token,
		"extra_fields": "Bearer " + token + " trailing",
	} {
		t.Run(name, func(t *testing.T) {
			called = false
			request := httptest.NewRequest(http.MethodGet, "/metrics", nil)
			if authorization != "" {
				request.Header.Set("Authorization", authorization)
			}
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, request)
			if response.Code != http.StatusUnauthorized || called || !strings.Contains(response.Body.String(), `"message":"unauthorized"`) || strings.Contains(response.Body.String(), token) {
				t.Fatalf("status=%d called=%v body=%s", response.Code, called, response.Body.String())
			}
		})
	}

	request := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	request.Header.Set("Authorization", "bearer "+token)
	request.Header.Set("X-Organization-ID", "not-an-organization")
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusNoContent || !called {
		t.Fatalf("status=%d called=%v", response.Code, called)
	}

	request = httptest.NewRequest(http.MethodGet, "/metrics", nil)
	request.Header.Add("Authorization", "Bearer "+token)
	request.Header.Add("Authorization", "Bearer "+token)
	response = httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusUnauthorized {
		t.Fatalf("duplicate authorization status=%d", response.Code)
	}
}

func TestMetricsAuthenticationFailsClosedWithoutConfiguredHash(t *testing.T) {
	server := &Server{}
	request := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	request.Header.Set("Authorization", "Bearer any-tenant-or-operator-token")
	response := httptest.NewRecorder()
	server.requireMetricsAuth(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		t.Fatal("unconfigured metrics authentication passed")
	})).ServeHTTP(response, request)
	if response.Code != http.StatusUnauthorized || len(server.MetricsTokenHash) == sha256.Size {
		t.Fatalf("status=%d hash length=%d", response.Code, len(server.MetricsTokenHash))
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

func TestStoreErrorsExposeOnlyTypedPublicFailures(t *testing.T) {
	response := httptest.NewRecorder()
	writeStoreError(response, errors.New("password=secret-value host=private.internal"))
	if response.Code != http.StatusInternalServerError || !strings.Contains(response.Body.String(), `"code":"internal_error"`) || strings.Contains(response.Body.String(), "secret-value") || strings.Contains(response.Body.String(), "private.internal") {
		t.Fatalf("unsafe unexpected store error: status=%d body=%s", response.Code, response.Body.String())
	}

	response = httptest.NewRecorder()
	writeStoreError(response, store.ErrAlreadyBootstrapped)
	if response.Code != http.StatusConflict || !strings.Contains(response.Body.String(), `"code":"already_bootstrapped"`) || !strings.Contains(response.Body.String(), "instance is already bootstrapped") {
		t.Fatalf("unexpected bootstrap conflict: status=%d body=%s", response.Code, response.Body.String())
	}
}

func TestAgentHandlerAppliesAPIProtectionBeforeCertificateAuthentication(t *testing.T) {
	_, trusted, _ := net.ParseCIDR("192.0.2.0/24")
	server := &Server{Logger: slog.New(slog.NewTextHandler(io.Discard, nil)), TrustedProxyCIDRs: []*net.IPNet{trusted}}
	request := httptest.NewRequest(http.MethodPost, "/v1/agent/heartbeat", strings.NewReader(`{}`))
	request.Header.Set("X-Forwarded-Proto", "https")
	response := httptest.NewRecorder()
	server.AgentHandler().ServeHTTP(response, request)

	if response.Code != http.StatusUnauthorized {
		t.Fatalf("agent API status=%d, want 401", response.Code)
	}
	if response.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("agent API cache policy=%q, want no-store", response.Header().Get("Cache-Control"))
	}
	if response.Header().Get("Strict-Transport-Security") != "" {
		t.Fatal("agent API trusted a proxy header on the direct mTLS listener")
	}
	for _, header := range []string{"Content-Security-Policy", "X-Content-Type-Options", "X-Frame-Options", "X-Request-ID"} {
		if response.Header().Get(header) == "" {
			t.Errorf("agent API response is missing %s", header)
		}
	}
}

func TestTrustedProxyMiddlewareCanonicalizesForwardedClient(t *testing.T) {
	_, trusted, _ := net.ParseCIDR("10.255.250.0/24")
	server := &Server{TrustedProxyCIDRs: []*net.IPNet{trusted}}
	tests := []struct {
		name, remote, forwarded, proto, wantRemote string
		wantHTTPS                                  bool
	}{
		{name: "trusted proxy chain", remote: "10.255.250.2:4321", forwarded: "198.51.100.7, 10.255.250.3", proto: "http, https", wantRemote: "198.51.100.7", wantHTTPS: true},
		{name: "untrusted peer", remote: "203.0.113.8:4321", forwarded: "198.51.100.9", proto: "https", wantRemote: "203.0.113.8:4321"},
		{name: "malformed chain", remote: "10.255.250.2:4321", forwarded: "198.51.100.9, invalid", proto: "http", wantRemote: "10.255.250.2:4321"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var gotRemote string
			var gotHTTPS bool
			handler := server.trustedProxyMiddleware(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
				gotRemote = r.RemoteAddr
				gotHTTPS, _ = r.Context().Value(forwardedHTTPSKey).(bool)
			}))
			request := httptest.NewRequest(http.MethodGet, "/", nil)
			request.RemoteAddr = test.remote
			request.Header.Set("X-Forwarded-For", test.forwarded)
			request.Header.Set("X-Forwarded-Proto", test.proto)
			handler.ServeHTTP(httptest.NewRecorder(), request)
			if gotRemote != test.wantRemote || gotHTTPS != test.wantHTTPS {
				t.Fatalf("remote=%q https=%t, want remote=%q https=%t", gotRemote, gotHTTPS, test.wantRemote, test.wantHTTPS)
			}
		})
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
