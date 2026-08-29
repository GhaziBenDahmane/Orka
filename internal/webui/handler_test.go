package webui

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestHandlerServesConsoleAndClientRoutes(t *testing.T) {
	for _, route := range []string{"/", "/services/example"} {
		recorder := httptest.NewRecorder()
		Handler().ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, route, nil))
		if recorder.Code != http.StatusOK || !strings.Contains(recorder.Body.String(), `<div id="root"></div>`) {
			t.Fatalf("%s: expected console, got %d %q", route, recorder.Code, recorder.Body.String())
		}
		if recorder.Header().Get("Content-Security-Policy") == "" {
			t.Fatalf("%s: content security policy missing", route)
		}
	}
}

func TestHandlerDoesNotMaskAPIRoutes(t *testing.T) {
	for _, route := range []string{"/v1/does-not-exist", "/healthz", "/readyz", "/metrics"} {
		recorder := httptest.NewRecorder()
		Handler().ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, route, nil))
		if recorder.Code != http.StatusNotFound || strings.Contains(recorder.Body.String(), `<div id="root"></div>`) {
			t.Fatalf("%s: expected API 404, got %d %q", route, recorder.Code, recorder.Body.String())
		}
	}
}
