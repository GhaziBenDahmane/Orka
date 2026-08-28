package observability

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/bendahma/dokploy-go/internal/store"
)

func TestRuntimeMetricsUseBoundedLabelsAndCumulativeBuckets(t *testing.T) {
	m := NewMetrics()
	m.ObserveHTTP("GET", "/v1/services/{serviceID}", 200, 20*time.Millisecond)
	m.ObserveHTTP("GET", "/v1/services/{serviceID}", 200, 2*time.Second)
	m.ObserveOperation("deploy.compose", "succeeded", 10*time.Second)
	var output bytes.Buffer
	m.renderRuntime(&output)
	text := output.String()
	for _, expected := range []string{
		`dockyard_http_requests_total{method="GET",route="/v1/services/{serviceID}",status="200"} 2`,
		`dockyard_http_request_duration_seconds_count{method="GET",route="/v1/services/{serviceID}",status="200"} 2`,
		`dockyard_http_request_duration_seconds_bucket{method="GET",route="/v1/services/{serviceID}",status="200",le="2.5"} 2`,
		`dockyard_operation_duration_seconds_count{kind="deploy.compose",status="succeeded"} 1`,
	} {
		if !strings.Contains(text, expected) {
			t.Fatalf("missing %q in metrics:\n%s", expected, text)
		}
	}
}

func TestDatabaseMetricsQueriesRemainValid(t *testing.T) {
	databaseURL := os.Getenv("DOCKYARD_TEST_DATABASE_URL")
	if databaseURL == "" {
		t.Skip("DOCKYARD_TEST_DATABASE_URL is not set")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	db, err := store.Open(ctx, databaseURL)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Pool.Close()
	recorder := httptest.NewRecorder()
	NewMetrics().Handler(db.Pool).ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	if recorder.Code != http.StatusOK {
		t.Fatalf("metrics status=%d body=%q", recorder.Code, recorder.Body.String())
	}
	for _, metric := range []string{"dockyard_restore_drill_last_duration_seconds", "dockyard_restore_drill_overdue", "dockyard_database_migrations", "dockyard_database_migration_active_age_seconds", "dockyard_database_migration_last_duration_seconds", "dockyard_database_migration_last_failure_age_seconds"} {
		if !strings.Contains(recorder.Body.String(), "# HELP "+metric) {
			t.Errorf("missing metric family %s", metric)
		}
	}
}

func TestPrometheusEscape(t *testing.T) {
	if got := prometheusEscape("a\\b\n\"c"); got != `a\\b\n\"c` {
		t.Fatalf("unexpected escaped label %q", got)
	}
}
