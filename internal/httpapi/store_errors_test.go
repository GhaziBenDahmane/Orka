package httpapi

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/bendahma/dokploy-go/internal/store"
)

func TestWriteStoreErrorClassifiesRemoteClusterAvailability(t *testing.T) {
	tests := []struct {
		name       string
		err        error
		status     int
		code       string
		retryAfter string
	}{
		{name: "partitioned", err: store.ErrClusterUnavailable, status: http.StatusServiceUnavailable, code: "cluster_unavailable", retryAfter: "30"},
		{name: "capacity", err: store.ErrNoCapacity, status: http.StatusConflict, code: "no_cluster_capacity"},
		{name: "AI finding limit", err: store.ErrAIAuditFindingLimit, status: http.StatusConflict, code: "ai_audit_finding_limit"},
		{name: "rollback unavailable", err: store.ErrRollbackUnavailable, status: http.StatusConflict, code: "rollback_unavailable"},
		{name: "SSO provider required", err: store.ErrSSOProviderRequired, status: http.StatusConflict, code: "sso_provider_required"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			recorder := httptest.NewRecorder()
			writeStoreError(recorder, test.err)
			if recorder.Code != test.status || !strings.Contains(recorder.Body.String(), `"code":"`+test.code+`"`) {
				t.Fatalf("status=%d body=%s", recorder.Code, recorder.Body.String())
			}
			if got := recorder.Header().Get("Retry-After"); got != test.retryAfter {
				t.Fatalf("Retry-After=%q, want %q", got, test.retryAfter)
			}
		})
	}
}
