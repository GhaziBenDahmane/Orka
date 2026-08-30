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
	m.SetCertificateExpiry("agent_ca", time.Now().Add(24*time.Hour))
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
		`dockyard_control_plane_certificate_expiry_seconds{certificate="agent_ca"}`,
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
	auditorA := uuid.New()
	auditorB := uuid.New()
	projectID, environmentID, serviceID := uuid.New(), uuid.New(), uuid.New()
	statements := []struct {
		query string
		args  []any
	}{
		{`INSERT INTO organizations(id,name,slug) VALUES($1,'Metrics A',$2)`, []any{organizationA, "metrics-a-" + organizationA.String()}},
		{`INSERT INTO organizations(id,name,slug) VALUES($1,'Metrics B',$2)`, []any{organizationB, "metrics-b-" + organizationB.String()}},
		{`INSERT INTO projects(id,organization_id,name,slug) VALUES($1,$2,'Metrics project','metrics-project')`, []any{projectID, organizationA}},
		{`INSERT INTO environments(id,project_id,name,slug) VALUES($1,$2,'Metrics environment','metrics-environment')`, []any{environmentID, projectID}},
		{`INSERT INTO compose_services(id,environment_id,name,slug,stack_name,compose_yaml) VALUES($1,$2,'Metrics service','metrics-service',$3,'services: {}')`, []any{serviceID, environmentID, "metrics-" + serviceID.String()}},
		{`INSERT INTO service_reconciliations(compose_service_id,state,consecutive_failures,detail,last_checked_at) VALUES($1,'degraded',2,'replica shortfall',now()-interval '30 seconds')`, []any{serviceID}},
		{`INSERT INTO service_accounts(id,organization_id,name,role,created_at) VALUES($1,$2,'metrics-a-auditor','auditor',now()-interval '3 days')`, []any{auditorA, organizationA}},
		{`INSERT INTO service_accounts(id,organization_id,name,role,created_at) VALUES($1,$2,'metrics-b-auditor','auditor',now()-interval '3 days')`, []any{auditorB, organizationB}},
		{`INSERT INTO service_account_tokens(id,service_account_id,token_hash,expires_at,created_at) VALUES($1,$2,$3,now()+interval '7 days',now()-interval '3 days')`, []any{uuid.New(), auditorA, []byte("metrics-token-a-" + auditorA.String())}},
		{`INSERT INTO service_account_tokens(id,service_account_id,token_hash,expires_at,created_at) VALUES($1,$2,$3,now()+interval '7 days',now()-interval '3 days')`, []any{uuid.New(), auditorB, []byte("metrics-token-b-" + auditorB.String())}},
		{`INSERT INTO ai_audit_runs(id,organization_id,service_account_id,agent_name,status,started_at,completed_at) VALUES($1,$2,$3,'metrics-agent','completed',now()-interval '65 minutes',now()-interval '1 hour')`, []any{uuid.New(), organizationA, auditorA}},
		{`INSERT INTO ai_audit_runs(id,organization_id,service_account_id,agent_name,status,started_at,completed_at) VALUES($1,$2,$3,'metrics-agent','failed',now()-interval '10 minutes',now()-interval '5 minutes')`, []any{uuid.New(), organizationA, auditorA}},
		{`INSERT INTO ai_audit_runs(id,organization_id,service_account_id,agent_name,status,started_at) VALUES($1,$2,$3,'metrics-agent','running',now()-interval '20 minutes')`, []any{uuid.New(), organizationA, auditorA}},
		{`INSERT INTO clusters(id,organization_id,name,slug,state,last_seen_at,certificate_serial,certificate_not_after,pending_certificate_serial,pending_certificate_not_after,pending_certificate_created_at) VALUES($1,$2,'Shared A','shared','active',now(),'current',now()+interval '1 hour','pending',now()+interval '7 days',now()-interval '10 minutes')`, []any{currentCluster, organizationA}},
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
	for _, metric := range []string{"dockyard_restore_drill_last_duration_seconds", "dockyard_restore_drill_overdue", "dockyard_database_migrations", "dockyard_database_migration_active_age_seconds", "dockyard_database_migration_last_duration_seconds", "dockyard_database_migration_last_failure_age_seconds", "dockyard_service_reconciliation", "dockyard_service_reconciliation_age_seconds", "dockyard_cluster_heartbeat_missing", "dockyard_cluster_agent_update_failure", "dockyard_agent_upgrade_verification_overdue", "dockyard_agent_upgrade_active_age_seconds", "dockyard_cluster_certificate_expiry_seconds", "dockyard_cluster_certificate_rotation_pending_age_seconds", "dockyard_service_account_token_expiry_seconds", "dockyard_ai_audit_runs", "dockyard_ai_audit_last_completed_age_seconds", "dockyard_ai_audit_last_failure_age_seconds", "dockyard_ai_audit_running_age_seconds", "dockyard_ai_audit_completion_overdue"} {
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
		`dockyard_cluster_certificate_expiry_seconds{organization="` + organizationA.String() + `",cluster="shared"}`,
		`dockyard_cluster_certificate_rotation_pending_age_seconds{organization="` + organizationA.String() + `",cluster="shared"}`,
		`dockyard_service_account_token_expiry_seconds{organization="` + organizationA.String() + `",account="` + auditorA.String() + `",role="auditor"}`,
		`dockyard_service_account_token_expiry_seconds{organization="` + organizationB.String() + `",account="` + auditorB.String() + `",role="auditor"}`,
		`dockyard_service_reconciliation{state="degraded"} 1`,
		`dockyard_service_reconciliation_age_seconds{service="` + serviceID.String() + `"}`,
		`dockyard_ai_audit_runs{status="running"}`,
		`dockyard_ai_audit_runs{status="completed"}`,
		`dockyard_ai_audit_runs{status="failed"}`,
		`dockyard_ai_audit_last_completed_age_seconds{organization="` + organizationA.String() + `"}`,
		`dockyard_ai_audit_last_failure_age_seconds{organization="` + organizationA.String() + `"}`,
		`dockyard_ai_audit_running_age_seconds{organization="` + organizationA.String() + `"}`,
		`dockyard_ai_audit_completion_overdue{organization="` + organizationA.String() + `"} 0`,
		`dockyard_ai_audit_completion_overdue{organization="` + organizationB.String() + `"} 1`,
	} {
		if !strings.Contains(metrics, expected) {
			t.Errorf("missing %q in metrics output", expected)
		}
	}
}

func TestPrometheusAlertsCoverAIAuditHealth(t *testing.T) {
	contents, err := os.ReadFile(filepath.Join("..", "..", "deploy", "prometheus-alerts.yml"))
	if err != nil {
		t.Fatal(err)
	}
	text := string(contents)
	for _, expected := range []string{
		"alert: DockyardAIAuditFailed",
		"expr: dockyard_ai_audit_last_failure_age_seconds < 900",
		"alert: DockyardAIAuditOverdue",
		"expr: dockyard_ai_audit_completion_overdue == 1",
		"alert: DockyardAIAuditStuck",
		"expr: dockyard_ai_audit_running_age_seconds > 600",
	} {
		if !strings.Contains(text, expected) {
			t.Errorf("missing alert configuration %q", expected)
		}
	}
}

func TestPrometheusAlertsCoverServiceAccountExpiry(t *testing.T) {
	contents, err := os.ReadFile(filepath.Join("..", "..", "deploy", "prometheus-alerts.yml"))
	if err != nil {
		t.Fatal(err)
	}
	text := string(contents)
	for _, expected := range []string{
		"alert: DockyardServiceAccountTokenExpiring",
		"expr: dockyard_service_account_token_expiry_seconds > 0 and dockyard_service_account_token_expiry_seconds < 604800",
		"alert: DockyardServiceAccountTokenExpired",
		"expr: dockyard_service_account_token_expiry_seconds <= 0",
	} {
		if !strings.Contains(text, expected) {
			t.Errorf("missing alert configuration %q", expected)
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
		"alert: DockyardAgentCertificateExpiring",
		"expr: dockyard_cluster_certificate_expiry_seconds > 0 and dockyard_cluster_certificate_expiry_seconds < 79200",
		"alert: DockyardAgentCertificateExpired",
		"expr: dockyard_cluster_certificate_expiry_seconds <= 0",
		"alert: DockyardAgentCertificateRotationStalled",
		"expr: dockyard_cluster_certificate_rotation_pending_age_seconds > 300",
		"alert: DockyardControlPlaneCertificateExpiring",
		"expr: dockyard_control_plane_certificate_expiry_seconds > 0 and dockyard_control_plane_certificate_expiry_seconds < 604800",
		"alert: DockyardControlPlaneCertificateExpired",
		"expr: dockyard_control_plane_certificate_expiry_seconds <= 0",
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
