package observability

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/bendahma/dokploy-go/internal/store"
	"github.com/google/uuid"
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
	tx, err := db.Pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	organizationA := uuid.New()
	organizationB := uuid.New()
	currentCluster := uuid.New()
	staleCluster := uuid.New()
	missingCluster := uuid.New()
	upgradeID := uuid.New()
	statements := []struct {
		query string
		args  []any
	}{
		{`INSERT INTO organizations(id,name,slug) VALUES($1,'Metrics A',$2)`, []any{organizationA, "metrics-a-" + organizationA.String()}},
		{`INSERT INTO organizations(id,name,slug) VALUES($1,'Metrics B',$2)`, []any{organizationB, "metrics-b-" + organizationB.String()}},
		{`INSERT INTO clusters(id,organization_id,name,slug,state,last_seen_at) VALUES($1,$2,'Shared A','shared','active',now())`, []any{currentCluster, organizationA}},
		{`INSERT INTO clusters(id,organization_id,name,slug,state,last_seen_at) VALUES($1,$2,'Shared B','shared','active',now()-interval '10 minutes')`, []any{staleCluster, organizationB}},
		{`INSERT INTO clusters(id,organization_id,name,slug,state,last_seen_at,agent_update_state) VALUES($1,$2,'Never connected','never-connected','draining',NULL,'rollback_completed')`, []any{missingCluster, organizationB}},
		{`INSERT INTO cluster_commands(id,cluster_id,kind,encrypted_payload,status,target_image,created_at,run_after) VALUES($1,$2,'agent.upgrade','encrypted','verifying',$3,now()-interval '20 minutes',now()-interval '5 minutes')`, []any{upgradeID, currentCluster, "registry.example/dockyard@sha256:" + strings.Repeat("a", 64)}},
	}
	for _, statement := range statements {
		if _, err = tx.Exec(ctx, statement.query, statement.args...); err != nil {
			t.Fatal(err)
		}
	}
	recorder := httptest.NewRecorder()
	NewMetrics().Handler(tx).ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	if recorder.Code != http.StatusOK {
		t.Fatalf("metrics status=%d body=%q", recorder.Code, recorder.Body.String())
	}
	for _, metric := range []string{"dockyard_restore_drill_last_duration_seconds", "dockyard_restore_drill_overdue", "dockyard_database_migrations", "dockyard_database_migration_active_age_seconds", "dockyard_database_migration_last_duration_seconds", "dockyard_database_migration_last_failure_age_seconds", "dockyard_service_reconciliation", "dockyard_service_reconciliation_age_seconds", "dockyard_cluster_heartbeat_missing", "dockyard_cluster_agent_update_failure", "dockyard_agent_upgrade_verification_overdue", "dockyard_agent_upgrade_active_age_seconds"} {
		if !strings.Contains(recorder.Body.String(), "# HELP "+metric) {
			t.Errorf("missing metric family %s", metric)
		}
	}
	metrics := recorder.Body.String()
	for _, expected := range []string{
		`dockyard_cluster_heartbeat_age_seconds{organization="` + organizationA.String() + `",cluster="shared"}`,
		`dockyard_cluster_heartbeat_age_seconds{organization="` + organizationB.String() + `",cluster="shared"}`,
		`dockyard_cluster_heartbeat_missing{organization="` + organizationA.String() + `",cluster="shared"} 0`,
		`dockyard_cluster_heartbeat_missing{organization="` + organizationB.String() + `",cluster="shared"} 1`,
		`dockyard_cluster_heartbeat_missing{organization="` + organizationB.String() + `",cluster="never-connected"} 1`,
		`dockyard_cluster_agent_update_failure{organization="` + organizationB.String() + `",cluster="never-connected",state="rollback_completed"} 1`,
		`dockyard_agent_upgrade_verification_overdue{organization="` + organizationA.String() + `",cluster="shared"} 1`,
		`dockyard_agent_upgrade_active_age_seconds{organization="` + organizationA.String() + `",cluster="shared",status="verifying"}`,
	} {
		if !strings.Contains(metrics, expected) {
			t.Errorf("missing %q in metrics output", expected)
		}
	}
}

func TestPrometheusAlertsCoverRemoteClusterUpgradeHealth(t *testing.T) {
	contents, err := os.ReadFile(filepath.Join("..", "..", "deploy", "prometheus-alerts.yml"))
	if err != nil {
		t.Fatal(err)
	}
	text := string(contents)
	for _, expected := range []string{
		"alert: DockyardRemoteClusterHeartbeatMissing",
		"expr: dockyard_cluster_heartbeat_missing == 1",
		"alert: DockyardAgentUpgradeRollback",
		"expr: dockyard_cluster_agent_update_failure == 1",
		"alert: DockyardAgentUpgradeVerificationOverdue",
		"expr: dockyard_agent_upgrade_verification_overdue > 0",
		"alert: DockyardAgentUpgradeStalled",
		`expr: dockyard_agent_upgrade_active_age_seconds{status=~"pending|leased"} > 900`,
	} {
		if !strings.Contains(text, expected) {
			t.Errorf("missing alert configuration %q", expected)
		}
	}
}

func TestPrometheusEscape(t *testing.T) {
	if got := prometheusEscape("a\\b\n\"c"); got != `a\\b\n\"c` {
		t.Fatalf("unexpected escaped label %q", got)
	}
}
