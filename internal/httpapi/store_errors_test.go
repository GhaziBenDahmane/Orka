package httpapi

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/GhaziBenDahmane/Orka/internal/store"
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
		{name: "AI audit active", err: store.ErrAIAuditRunActive, status: http.StatusConflict, code: "ai_audit_run_active", retryAfter: "60"},
		{name: "rollback unavailable", err: store.ErrRollbackUnavailable, status: http.StatusConflict, code: "rollback_unavailable"},
		{name: "SSO provider required", err: store.ErrSSOProviderRequired, status: http.StatusConflict, code: "sso_provider_required"},
		{name: "stale authority", err: store.ErrInsufficientRole, status: http.StatusForbidden, code: "forbidden"},
		{name: "protected volume removed", err: store.ErrProtectedVolumeRemoved, status: http.StatusConflict, code: "protected_volume_removed"},
		{name: "volume not declared", err: store.ErrVolumeNotDeclared, status: http.StatusConflict, code: "volume_not_declared"},
		{name: "resource deleting", err: store.ErrDeleting, status: http.StatusConflict, code: "resource_deleting"},
		{name: "cross-cluster move", err: store.ErrCrossClusterMove, status: http.StatusConflict, code: "cross_cluster_move"},
		{name: "managed database move", err: store.ErrManagedDatabaseMove, status: http.StatusConflict, code: "managed_database_move"},
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
