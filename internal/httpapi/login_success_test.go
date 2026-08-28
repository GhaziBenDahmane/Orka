package httpapi

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestWriteLoginSuccessNegotiatesBrowserRedirect(t *testing.T) {
	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodGet, "/v1/auth/sso/callback", nil)
	request.Header.Set("Accept", "text/html,application/xhtml+xml")
	writeLoginSuccess(recorder, request, "secret/token+")
	if recorder.Code != http.StatusSeeOther {
		t.Fatalf("status = %d", recorder.Code)
	}
	if location := recorder.Header().Get("Location"); !strings.HasPrefix(location, "/#session=") || strings.Contains(location, "secret/token+") {
		t.Fatalf("unsafe or missing redirect location %q", location)
	}
	if recorder.Header().Get("Cache-Control") != "no-store" {
		t.Fatal("login response must not be cached")
	}
}

func TestWriteLoginSuccessPreservesJSONAPI(t *testing.T) {
	recorder := httptest.NewRecorder()
	writeLoginSuccess(recorder, httptest.NewRequest(http.MethodGet, "/", nil), "secret")
	if recorder.Code != http.StatusOK || !strings.Contains(recorder.Body.String(), `"token":"secret"`) {
		t.Fatalf("unexpected API response: %d %q", recorder.Code, recorder.Body.String())
	}
}
