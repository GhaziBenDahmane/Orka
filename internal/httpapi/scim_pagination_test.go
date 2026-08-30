package httpapi

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestSCIMPage(t *testing.T) {
	for _, test := range []struct {
		name                 string
		query                string
		wantStart, wantCount int
		wantError            bool
	}{
		{name: "defaults", wantStart: 1, wantCount: 100},
		{name: "bounded page", query: "?startIndex=201&count=25", wantStart: 201, wantCount: 25},
		{name: "count only", query: "?startIndex=1&count=0", wantStart: 1, wantCount: 0},
		{name: "zero start", query: "?startIndex=0", wantError: true},
		{name: "negative count", query: "?count=-1", wantError: true},
		{name: "oversized count", query: "?count=101", wantError: true},
		{name: "malformed", query: "?startIndex=first", wantError: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			start, count, err := scimPage(httptest.NewRequest("GET", "/scim/v2/Users"+test.query, nil))
			if (err != nil) != test.wantError {
				t.Fatalf("scimPage error=%v, wantError=%v", err, test.wantError)
			}
			if err == nil && (start != test.wantStart || count != test.wantCount) {
				t.Fatalf("scimPage=(%d,%d), want (%d,%d)", start, count, test.wantStart, test.wantCount)
			}
		})
	}
}

func TestSCIMJSONUsesSCIMMediaType(t *testing.T) {
	recorder := httptest.NewRecorder()
	scimError(recorder, http.StatusBadRequest, "invalid")
	if got := recorder.Header().Get("Content-Type"); got != "application/scim+json" {
		t.Fatalf("Content-Type=%q", got)
	}
	if !strings.Contains(recorder.Body.String(), `"detail":"invalid"`) {
		t.Fatalf("unexpected body %q", recorder.Body.String())
	}
	if !strings.Contains(recorder.Body.String(), `"status":"400"`) {
		t.Fatalf("SCIM error status is not encoded as a string: %q", recorder.Body.String())
	}
}
