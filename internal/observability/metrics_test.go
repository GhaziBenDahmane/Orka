package observability

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/bendahma/dokploy-go/internal/store"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

func TestRuntimeMetricsUseBoundedLabelsAndCumulativeBuckets(t *testing.T) {
	m := NewMetrics()
	m.SetCertificateExpiry("agent_ca", time.Now().Add(24*time.Hour))
	m.ObserveHTTP("GET", "/v1/services/{serviceID}", 200, 20*time.Millisecond)
	m.ObserveHTTP("GET", "/v1/services/{serviceID}", 200, 2*time.Second)
	m.ObserveOperation("deploy.compose", "succeeded", 10*time.Second)
	m.ObserveBuildWorkspaceLimitRejection()
	var output bytes.Buffer
	m.renderRuntime(&output)
	text := output.String()
	for _, expected := range []string{
		`dockyard_http_requests_total{method="GET",route="/v1/services/{serviceID}",status="200"} 2`,
		`dockyard_http_request_duration_seconds_count{method="GET",route="/v1/services/{serviceID}",status="200"} 2`,
		`dockyard_http_request_duration_seconds_bucket{method="GET",route="/v1/services/{serviceID}",status="200",le="2.5"} 2`,
		`dockyard_operation_duration_seconds_count{kind="deploy.compose",status="succeeded"} 1`,
		`dockyard_build_workspace_limit_rejections_total 1`,
		`dockyard_control_plane_certificate_expiry_seconds{certificate="agent_ca"}`,
	} {
		if !strings.Contains(text, expected) {
			t.Fatalf("missing %q in metrics:\n%s", expected, text)
		}
	}
}

func TestDatabaseDriverInventoryIsStableAndDoesNotExposePaths(t *testing.T) {
	m := NewMetrics()
	m.SetDatabaseDrivers([]DatabaseDriverInfo{
		{Engine: "postgres", Source: "built-in", Digest: "/usr/local/bin/should-not-leak", BackupCapable: true},
		{Engine: "cockroach", Source: "external", Digest: "sha256:" + strings.Repeat("a", 64), BackupCapable: true},
		{Engine: "unsafe", Source: "external", Digest: "/opt/drivers/unsafe", BackupCapable: false},
	})
	drivers, _, digest := m.databaseDriverSnapshot()
	var output bytes.Buffer
	renderDatabaseDriverInventory(&output, drivers, digest)
	text := output.String()
	for _, expected := range []string{
		`dockyard_database_driver_inventory_info{digest="sha256:`,
		`dockyard_database_driver_info{engine="postgres",source="built-in",digest="built-in",backup_capable="true"} 1`,
		`dockyard_database_driver_info{engine="cockroach",source="external",digest="sha256:` + strings.Repeat("a", 64) + `",backup_capable="true"} 1`,
		`dockyard_database_driver_info{engine="unsafe",source="external",digest="invalid",backup_capable="false"} 1`,
	} {
		if !strings.Contains(text, expected) {
			t.Fatalf("missing %q in metrics:\n%s", expected, text)
		}
	}
	if strings.Contains(text, "/usr/") || strings.Contains(text, "/opt/") {
		t.Fatalf("driver filesystem path leaked in metrics:\n%s", text)
	}
}

func TestDatabaseMetricsQueriesRemainValid(t *testing.T) {
	databaseURL := os.Getenv("DOCKYARD_TEST_DATABASE_URL")
	if databaseURL == "" {
		t.Skip("DOCKYARD_TEST_DATABASE_URL is not set")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	db := isolatedMetricsStore(t, ctx, databaseURL)
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
	deployTokenID, sourceCredentialID, finalizerClusterID := uuid.New(), uuid.New(), uuid.New()
	failedNetworkID, deletingNetworkID := uuid.New(), uuid.New()
	auditorA := uuid.New()
	auditorB := uuid.New()
	scimToken := uuid.New()
	expiredSCIMToken := uuid.New()
	samlProvider := uuid.New()
	templatePending, templateRunning, templateFailed := uuid.New(), uuid.New(), uuid.New()
	samlMetadata, samlCertificate := testSAMLMetricMaterial(t, time.Now().Add(90*24*time.Hour))
	projectID, environmentID, serviceID, destinationID, volumePolicyID, missingVolumePolicyID, volumeBackupID, artifactDeletionID := uuid.New(), uuid.New(), uuid.New(), uuid.New(), uuid.New(), uuid.New(), uuid.New(), uuid.New()
	databaseDigest := "sha256:" + strings.Repeat("a", 64)
	statements := []struct {
		query string
		args  []any
	}{
		{`INSERT INTO organizations(id,name,slug) VALUES($1,'Metrics A',$2)`, []any{organizationA, "metrics-a-" + organizationA.String()}},
		{`INSERT INTO organizations(id,name,slug) VALUES($1,'Metrics B',$2)`, []any{organizationB, "metrics-b-" + organizationB.String()}},
		{`INSERT INTO managed_networks(id,organization_id,name,driver,status,last_error) VALUES($1,$2,'failed-overlay','overlay','error','metrics-network-error')`, []any{failedNetworkID, organizationA}},
		{`INSERT INTO managed_networks(id,organization_id,name,driver,status,deletion_requested_at) VALUES($1,$2,'deleting-overlay','overlay','deleting',now()-interval '25 minutes')`, []any{deletingNetworkID, organizationA}},
		{`INSERT INTO jobs(id,kind,payload,status,last_error,finished_at) VALUES($1,'network.delete',$2,'failed','metrics-network-finalizer-error',now()-interval '10 minutes')`, []any{uuid.New(), `{"networkId":"` + deletingNetworkID.String() + `"}`}},
		{`INSERT INTO template_repositories(id,organization_id,name,slug,repository_url,git_ref,sync_requested_at) VALUES($1,$2,'Pending catalog','pending','https://github.com/acme/pending','main',now()-interval '10 minutes')`, []any{templatePending, organizationA}},
		{`INSERT INTO template_repositories(id,organization_id,name,slug,repository_url,git_ref,last_sync_status,sync_started_at) VALUES($1,$2,'Running catalog','running','https://github.com/acme/running','main','running',now()-interval '11 minutes')`, []any{templateRunning, organizationB}},
		{`INSERT INTO template_repositories(id,organization_id,name,slug,repository_url,git_ref,last_sync_status) VALUES($1,$2,'Failed catalog','failed','https://github.com/acme/failed','main','failed')`, []any{templateFailed, organizationA}},
		{`INSERT INTO projects(id,organization_id,name,slug) VALUES($1,$2,'Metrics project','metrics-project')`, []any{projectID, organizationA}},
		{`INSERT INTO environments(id,project_id,name,slug) VALUES($1,$2,'Metrics environment','metrics-environment')`, []any{environmentID, projectID}},
		{`INSERT INTO compose_services(id,environment_id,name,slug,stack_name,compose_yaml) VALUES($1,$2,'Metrics service','metrics-service',$3,'services: {}')`, []any{serviceID, environmentID, "metrics-" + serviceID.String()}},
		{`INSERT INTO deploy_tokens(id,compose_service_id,token_hash,name,expires_at) VALUES($1,$2,$3,'metrics-deploy-hook',now()+interval '1 day')`, []any{deployTokenID, serviceID, []byte("metrics-deploy-token-" + deployTokenID.String())}},
		{`INSERT INTO source_credentials(id,organization_id,kind,name,server,username,encrypted_secret,created_at,updated_at) VALUES($1,$2,'registry','Metrics registry','registry.example.test','builder','encrypted',now()-interval '1 year',now()-interval '181 days')`, []any{sourceCredentialID, organizationA}},
		{`INSERT INTO application_sources(compose_service_id,repository_url,target_service,registry_image,registry_credential_id) VALUES($1,'https://example.test/metrics.git','app','registry.example.test/metrics/app',$2)`, []any{serviceID, sourceCredentialID}},
		{`INSERT INTO backup_destinations(id,organization_id,name,endpoint,bucket,encrypted_credentials) VALUES($1,$2,'Metrics destination','https://s3.example.test','backups','encrypted')`, []any{destinationID, organizationA}},
		{`INSERT INTO volume_backup_policies(id,compose_service_id,volume_name,destination_id,interval_seconds,retention_count,quiesce,enabled,next_run_at) VALUES($1,$2,'uploads',$3,3600,7,true,true,now()+interval '1 hour')`, []any{volumePolicyID, serviceID, destinationID}},
		{`INSERT INTO volume_backup_policies(id,compose_service_id,volume_name,destination_id,interval_seconds,retention_count,quiesce,enabled,next_run_at) VALUES($1,$2,'cache',$3,3600,7,true,true,now()+interval '1 hour')`, []any{missingVolumePolicyID, serviceID, destinationID}},
		{`INSERT INTO volume_backups(id,volume_backup_policy_id,compose_service_id,volume_name,storage_node_id,destination_id,quiesce,status,object_key,size_bytes,sha256,plaintext_sha256,encrypted_data_key,started_at,finished_at) VALUES($1,$2,$3,'uploads','nodeabc123',$4,true,'succeeded','volume.enc',42,$5,$6,'encrypted',now()-interval '2 hours',now()-interval '1 hour')`, []any{volumeBackupID, volumePolicyID, serviceID, destinationID, strings.Repeat("a", 64), strings.Repeat("b", 64)}},
		{`INSERT INTO volume_restores(id,volume_backup_id,status,started_at,finished_at) VALUES($1,$2,'succeeded',now()-interval '30 minutes',now()-interval '29 minutes')`, []any{uuid.New(), volumeBackupID}},
		{`INSERT INTO backup_artifact_deletions(id,destination_id,object_key,source_kind,source_id,created_at) VALUES($1,$2,'expired/object.enc','volume',$3,now()-interval '5 minutes')`, []any{artifactDeletionID, destinationID, volumeBackupID}},
		{`INSERT INTO database_instances(id,environment_id,name,slug,engine,version,driver_source,driver_artifact_digest,encrypted_credentials) VALUES($1,$2,'Matching','matching','cockroach','v25.2','external',$3,'encrypted')`, []any{uuid.New(), environmentID, databaseDigest}},
		{`INSERT INTO database_instances(id,environment_id,name,slug,engine,version,driver_source,driver_artifact_digest,encrypted_credentials) VALUES($1,$2,'Mismatch','mismatch','cockroach','v25.2','external',$3,'encrypted')`, []any{uuid.New(), environmentID, "sha256:" + strings.Repeat("b", 64)}},
		{`INSERT INTO database_instances(id,environment_id,name,slug,engine,version,driver_source,driver_artifact_digest,encrypted_credentials) VALUES($1,$2,'Unbound','unbound','legacy','1','unbound','','encrypted')`, []any{uuid.New(), environmentID}},
		{`INSERT INTO database_instances(id,environment_id,name,slug,engine,version,driver_source,driver_artifact_digest,encrypted_credentials) VALUES($1,$2,'Unavailable','unavailable','missing','1','external',$3,'encrypted')`, []any{uuid.New(), environmentID, "sha256:" + strings.Repeat("c", 64)}},
		{`INSERT INTO service_reconciliations(compose_service_id,state,consecutive_failures,detail,last_checked_at) VALUES($1,'degraded',2,'replica shortfall',now()-interval '30 seconds')`, []any{serviceID}},
		{`INSERT INTO service_accounts(id,organization_id,name,role,created_at) VALUES($1,$2,'metrics-a-auditor','auditor',now()-interval '3 days')`, []any{auditorA, organizationA}},
		{`INSERT INTO service_accounts(id,organization_id,name,role,created_at) VALUES($1,$2,'metrics-b-auditor','auditor',now()-interval '3 days')`, []any{auditorB, organizationB}},
		{`INSERT INTO service_account_tokens(id,service_account_id,token_hash,expires_at,created_at) VALUES($1,$2,$3,now()+interval '7 days',now()-interval '3 days')`, []any{uuid.New(), auditorA, []byte("metrics-token-a-" + auditorA.String())}},
		{`INSERT INTO service_account_tokens(id,service_account_id,token_hash,expires_at,created_at) VALUES($1,$2,$3,now()+interval '7 days',now()-interval '3 days')`, []any{uuid.New(), auditorB, []byte("metrics-token-b-" + auditorB.String())}},
		{`INSERT INTO scim_tokens(id,organization_id,name,token_hash,default_role,expires_at) VALUES($1,$2,'metrics-directory',$3,'developer',now()+interval '7 days')`, []any{scimToken, organizationA, []byte("metrics-scim-" + scimToken.String())}},
		{`INSERT INTO scim_tokens(id,organization_id,name,token_hash,default_role,expires_at) VALUES($1,$2,'expired-directory',$3,'developer',now()-interval '31 days')`, []any{expiredSCIMToken, organizationA, []byte("expired-metrics-scim-" + expiredSCIMToken.String())}},
		{`INSERT INTO saml_providers(id,organization_id,name,idp_metadata,certificate_pem,encrypted_private_key,domains) VALUES($1,$2,'metrics-saml',$3,$4,'encrypted','{example.test}')`, []any{samlProvider, organizationA, samlMetadata, samlCertificate}},
		{`INSERT INTO ai_audit_runs(id,organization_id,service_account_id,agent_name,status,started_at,completed_at) VALUES($1,$2,$3,'metrics-agent','completed',now()-interval '65 minutes',now()-interval '1 hour')`, []any{uuid.New(), organizationA, auditorA}},
		{`INSERT INTO ai_audit_runs(id,organization_id,service_account_id,agent_name,status,started_at,completed_at) VALUES($1,$2,$3,'metrics-agent','failed',now()-interval '10 minutes',now()-interval '5 minutes')`, []any{uuid.New(), organizationA, auditorA}},
		{`INSERT INTO ai_audit_runs(id,organization_id,service_account_id,agent_name,status,started_at) VALUES($1,$2,$3,'metrics-agent','running',now()-interval '20 minutes')`, []any{uuid.New(), organizationA, auditorA}},
		{`INSERT INTO clusters(id,organization_id,name,slug,state,last_seen_at,certificate_serial,certificate_not_after,pending_certificate_serial,pending_certificate_not_after,pending_certificate_created_at) VALUES($1,$2,'Shared A','shared','active',now(),'current',now()+interval '1 hour','pending',now()+interval '7 days',now()-interval '10 minutes')`, []any{currentCluster, organizationA}},
		{`INSERT INTO clusters(id,organization_id,name,slug,state,last_seen_at) VALUES($1,$2,'Shared B','shared','active',now()-interval '10 minutes')`, []any{staleCluster, organizationB}},
		{`INSERT INTO clusters(id,organization_id,name,slug,state,last_seen_at,agent_update_state) VALUES($1,$2,'Never connected','never-connected','draining',NULL,'rollback_completed')`, []any{missingCluster, organizationB}},
		{`INSERT INTO clusters(id,organization_id,name,slug,state,deletion_requested_at) VALUES($1,$2,'Deleting','deleting','disabled',now()-interval '20 minutes')`, []any{finalizerClusterID, organizationA}},
		{`INSERT INTO jobs(id,kind,payload,status,last_error,finished_at) VALUES($1,'delete.cluster',$2,'failed','metrics-finalizer-error',now()-interval '10 minutes')`, []any{uuid.New(), `{"clusterId":"` + finalizerClusterID.String() + `"}`}},
		{`INSERT INTO cluster_commands(id,cluster_id,kind,encrypted_payload,status,target_image,created_at,run_after) VALUES($1,$2,'agent.upgrade','encrypted','verifying',$3,now()-interval '20 minutes',now()-interval '5 minutes')`, []any{upgradeID, currentCluster, "registry.example/dockyard@sha256:" + strings.Repeat("a", 64)}},
	}
	for _, statement := range statements {
		if _, err = tx.Exec(ctx, statement.query, statement.args...); err != nil {
			t.Fatal(err)
		}
	}
	recorder := httptest.NewRecorder()
	metricSet := NewMetrics()
	metricSet.SetDatabaseDrivers([]DatabaseDriverInfo{
		{Engine: "postgres", Source: "built-in", BackupCapable: true},
		{Engine: "cockroach", Source: "external", Digest: databaseDigest, BackupCapable: true},
	})
	metricSet.Handler(tx).ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	if recorder.Code != http.StatusOK {
		t.Fatalf("metrics status=%d body=%q", recorder.Code, recorder.Body.String())
	}
	for _, metric := range []string{"dockyard_restore_drill_last_duration_seconds", "dockyard_restore_drill_overdue", "dockyard_database_migrations", "dockyard_database_migration_active_age_seconds", "dockyard_database_migration_last_duration_seconds", "dockyard_database_migration_last_failure_age_seconds", "dockyard_volume_backups", "dockyard_volume_restores", "dockyard_volume_backup_last_success_age_seconds", "dockyard_volume_restore_last_success_age_seconds", "dockyard_volume_backup_overdue", "dockyard_volume_restore_rehearsal_overdue", "dockyard_backup_artifact_deletions", "dockyard_backup_artifact_deletion_oldest_age_seconds", "dockyard_database_driver_inventory_info", "dockyard_database_driver_info", "dockyard_database_driver_binding_issues", "dockyard_service_reconciliation", "dockyard_service_reconciliation_age_seconds", "dockyard_managed_networks", "dockyard_managed_network_provisioning_age_seconds", "dockyard_cluster_heartbeat_missing", "dockyard_cluster_agent_update_failure", "dockyard_agent_upgrade_verification_overdue", "dockyard_agent_upgrade_active_age_seconds", "dockyard_cluster_certificate_expiry_seconds", "dockyard_cluster_certificate_rotation_pending_age_seconds", "dockyard_service_account_token_expiry_seconds", "dockyard_scim_token_expiry_seconds", "dockyard_expired_credential_backlog", "dockyard_saml_certificate_rotation_pending_age_seconds", "dockyard_saml_certificate_expiry_seconds", "dockyard_saml_certificate_valid", "dockyard_ai_audit_runs", "dockyard_ai_audit_last_completed_age_seconds", "dockyard_ai_audit_last_failure_age_seconds", "dockyard_ai_audit_running_age_seconds", "dockyard_ai_audit_completion_overdue", "dockyard_template_repositories", "dockyard_template_repository_sync_pending_age_seconds", "dockyard_template_repository_sync_running_age_seconds", "dockyard_template_repository_sync_failed"} {
		if !strings.Contains(recorder.Body.String(), "# HELP "+metric) {
			t.Errorf("missing metric family %s", metric)
		}
	}
	metrics := recorder.Body.String()
	for _, metric := range []string{"dockyard_deploy_token_expiry_seconds", "dockyard_source_credential_rotation_age_seconds", "dockyard_resource_finalizers", "dockyard_resource_finalizer_oldest_age_seconds", "dockyard_custom_tls_certificate_expiry_seconds", "dockyard_edge_tls_reconciliation", "dockyard_edge_tls_reconciliation_age_seconds"} {
		if !strings.Contains(metrics, "# HELP "+metric) {
			t.Errorf("missing metric family %s", metric)
		}
	}
	for _, expected := range []string{
		`dockyard_deploy_token_expiry_seconds{organization="` + organizationA.String() + `",service="` + serviceID.String() + `",token="` + deployTokenID.String() + `"}`,
		`dockyard_source_credential_rotation_age_seconds{organization="` + organizationA.String() + `",credential="` + sourceCredentialID.String() + `",kind="registry"}`,
		`dockyard_resource_finalizers{organization="` + organizationA.String() + `",kind="cluster",state="failed"} 1`,
		`dockyard_resource_finalizer_oldest_age_seconds{organization="` + organizationA.String() + `",kind="cluster"}`,
		`dockyard_managed_networks{organization="` + organizationA.String() + `",scope="local",driver="overlay",status="error"} 1`,
		`dockyard_resource_finalizers{organization="` + organizationA.String() + `",kind="network",state="failed"} 1`,
		`dockyard_resource_finalizer_oldest_age_seconds{organization="` + organizationA.String() + `",kind="network"}`,
	} {
		if !strings.Contains(metrics, expected) {
			t.Errorf("missing %q in metrics output", expected)
		}
	}
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
		`dockyard_scim_token_expiry_seconds{organization="` + organizationA.String() + `",token="` + scimToken.String() + `",role="developer"}`,
		`dockyard_expired_credential_backlog{kind="scim_token"} 1`,
		`dockyard_saml_certificate_valid{organization="` + organizationA.String() + `",provider="` + samlProvider.String() + `",kind="service_provider"} 1`,
		`dockyard_saml_certificate_valid{organization="` + organizationA.String() + `",provider="` + samlProvider.String() + `",kind="identity_provider"} 1`,
		`dockyard_saml_certificate_expiry_seconds{organization="` + organizationA.String() + `",provider="` + samlProvider.String() + `",kind="identity_provider"}`,
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
		`dockyard_template_repositories{status="running"} 1`,
		`dockyard_template_repositories{status="failed"} 1`,
		`dockyard_template_repository_sync_pending_age_seconds{organization="` + organizationA.String() + `",repository="` + templatePending.String() + `"}`,
		`dockyard_template_repository_sync_running_age_seconds{organization="` + organizationB.String() + `",repository="` + templateRunning.String() + `"}`,
		`dockyard_template_repository_sync_failed{organization="` + organizationA.String() + `",repository="` + templateFailed.String() + `"} 1`,
		`dockyard_database_driver_info{engine="cockroach",source="external",digest="` + databaseDigest + `",backup_capable="true"} 1`,
		`dockyard_database_driver_binding_issues{engine="cockroach",reason="identity_mismatch"} 1`,
		`dockyard_database_driver_binding_issues{engine="legacy",reason="unbound"} 1`,
		`dockyard_database_driver_binding_issues{engine="missing",reason="unavailable"} 1`,
		`dockyard_volume_backups{status="succeeded"} 1`,
		`dockyard_volume_restores{status="succeeded"} 1`,
		`dockyard_volume_backup_last_success_age_seconds{service="` + serviceID.String() + `",volume="uploads"}`,
		`dockyard_volume_restore_last_success_age_seconds{service="` + serviceID.String() + `",volume="uploads"}`,
		`dockyard_volume_backup_overdue{service="` + serviceID.String() + `",volume="uploads"} 0`,
		`dockyard_volume_restore_rehearsal_overdue{service="` + serviceID.String() + `",volume="uploads"} 0`,
		`dockyard_volume_backup_overdue{service="` + serviceID.String() + `",volume="cache"} 1`,
		`dockyard_volume_restore_rehearsal_overdue{service="` + serviceID.String() + `",volume="cache"} 1`,
		`dockyard_backup_artifact_deletions{kind="volume"} 1`,
		`dockyard_backup_artifact_deletion_oldest_age_seconds{kind="volume"}`,
	} {
		if !strings.Contains(metrics, expected) {
			t.Errorf("missing %q in metrics output", expected)
		}
	}
}

func TestPrometheusAlertsCoverDatabaseDriverIdentity(t *testing.T) {
	contents, err := os.ReadFile(filepath.Join("..", "..", "deploy", "prometheus-alerts.yml"))
	if err != nil {
		t.Fatal(err)
	}
	text := string(contents)
	for _, expected := range []string{
		"alert: DockyardDatabaseDriverFleetMismatch",
		"dockyard_database_driver_inventory_info",
		"alert: DockyardDatabaseDriverBindingIssue",
		"expr: dockyard_database_driver_binding_issues > 0",
	} {
		if !strings.Contains(text, expected) {
			t.Errorf("missing alert configuration %q", expected)
		}
	}
}

func TestPrometheusAlertsCoverVolumeRecovery(t *testing.T) {
	contents, err := os.ReadFile(filepath.Join("..", "..", "deploy", "prometheus-alerts.yml"))
	if err != nil {
		t.Fatal(err)
	}
	text := string(contents)
	for _, expected := range []string{
		"alert: DockyardVolumeBackupOverdue",
		"expr: dockyard_volume_backup_overdue == 1",
		"alert: DockyardVolumeRestoreRehearsalOverdue",
		"expr: dockyard_volume_restore_rehearsal_overdue == 1",
		"alert: DockyardBackupArtifactDeletionStalled",
		"expr: dockyard_backup_artifact_deletion_oldest_age_seconds > 900",
	} {
		if !strings.Contains(text, expected) {
			t.Errorf("missing alert configuration %q", expected)
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

func TestPrometheusAlertsCoverTemplateRepositorySyncHealth(t *testing.T) {
	contents, err := os.ReadFile(filepath.Join("..", "..", "deploy", "prometheus-alerts.yml"))
	if err != nil {
		t.Fatal(err)
	}
	text := string(contents)
	for _, expected := range []string{
		"alert: DockyardTemplateRepositorySyncQueued",
		"expr: dockyard_template_repository_sync_pending_age_seconds > 300",
		"alert: DockyardTemplateRepositorySyncStuck",
		"expr: dockyard_template_repository_sync_running_age_seconds > 600",
		"alert: DockyardTemplateRepositorySyncFailed",
		"expr: dockyard_template_repository_sync_failed == 1",
	} {
		if !strings.Contains(text, expected) {
			t.Errorf("missing alert configuration %q", expected)
		}
	}
}

func TestPrometheusAlertsCoverBuildWorkspaceLimit(t *testing.T) {
	contents, err := os.ReadFile(filepath.Join("..", "..", "deploy", "prometheus-alerts.yml"))
	if err != nil {
		t.Fatal(err)
	}
	text := string(contents)
	for _, expected := range []string{
		"alert: DockyardBuildWorkspaceLimitRejected",
		"expr: increase(dockyard_build_workspace_limit_rejections_total[15m]) > 0",
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

func TestPrometheusAlertsCoverDeployTokensAndFinalizers(t *testing.T) {
	contents, err := os.ReadFile(filepath.Join("..", "..", "deploy", "prometheus-alerts.yml"))
	if err != nil {
		t.Fatal(err)
	}
	text := string(contents)
	for _, expected := range []string{
		"alert: DockyardDeployTokenExpiring",
		"expr: dockyard_deploy_token_expiry_seconds > 0 and dockyard_deploy_token_expiry_seconds < 604800",
		"alert: DockyardDeployTokenExpired",
		"expr: dockyard_deploy_token_expiry_seconds <= 0",
		"alert: DockyardSourceCredentialRotationOverdue",
		"expr: dockyard_source_credential_rotation_age_seconds > 15552000",
		"alert: DockyardResourceFinalizerRequiresIntervention",
		`expr: dockyard_resource_finalizers{state=~"failed|missing"} > 0`,
		"alert: DockyardResourceFinalizerStalled",
		`expr: dockyard_resource_finalizer_oldest_age_seconds > 900 unless on (organization, kind) dockyard_resource_finalizers{state=~"failed|missing"} > 0`,
		"alert: DockyardManagedNetworkProvisioningFailed",
		`expr: dockyard_managed_networks{status="error"} > 0`,
		"alert: DockyardManagedNetworkProvisioningStalled",
		"expr: dockyard_managed_network_provisioning_age_seconds > 900",
	} {
		if !strings.Contains(text, expected) {
			t.Errorf("missing alert configuration %q", expected)
		}
	}
}

func TestPrometheusAlertsCoverSCIMTokenExpiry(t *testing.T) {
	contents, err := os.ReadFile(filepath.Join("..", "..", "deploy", "prometheus-alerts.yml"))
	if err != nil {
		t.Fatal(err)
	}
	text := string(contents)
	for _, expected := range []string{
		"alert: DockyardSCIMTokenExpiring",
		"expr: dockyard_scim_token_expiry_seconds > 0 and dockyard_scim_token_expiry_seconds < 604800",
		"alert: DockyardSCIMTokenExpired",
		"expr: dockyard_scim_token_expiry_seconds <= 0",
	} {
		if !strings.Contains(text, expected) {
			t.Errorf("missing alert configuration %q", expected)
		}
	}
}

func TestPrometheusAlertsCoverCredentialCleanup(t *testing.T) {
	contents, err := os.ReadFile(filepath.Join("..", "..", "deploy", "prometheus-alerts.yml"))
	if err != nil {
		t.Fatal(err)
	}
	text := string(contents)
	for _, expected := range []string{
		"alert: DockyardCredentialCleanupBacklog",
		"expr: dockyard_expired_credential_backlog > 0",
		"for: 2h",
	} {
		if !strings.Contains(text, expected) {
			t.Errorf("missing alert configuration %q", expected)
		}
	}
}

func TestPrometheusAlertsCoverSAMLCertificateHealth(t *testing.T) {
	contents, err := os.ReadFile(filepath.Join("..", "..", "deploy", "prometheus-alerts.yml"))
	if err != nil {
		t.Fatal(err)
	}
	text := string(contents)
	for _, expected := range []string{
		"alert: DockyardSAMLCertificateExpiring",
		"expr: dockyard_saml_certificate_expiry_seconds > 0 and dockyard_saml_certificate_expiry_seconds < 2592000",
		"alert: DockyardSAMLCertificateExpired",
		"expr: dockyard_saml_certificate_expiry_seconds <= 0",
		"alert: DockyardSAMLCertificateInvalid",
		"expr: dockyard_saml_certificate_valid == 0 unless on (organization, provider, kind) dockyard_saml_certificate_expiry_seconds <= 0",
		"alert: DockyardSAMLCertificateRotationStalled",
		"expr: dockyard_saml_certificate_rotation_pending_age_seconds > 604800",
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

func TestPrometheusAlertsCoverCustomTLSHealth(t *testing.T) {
	contents, err := os.ReadFile(filepath.Join("..", "..", "deploy", "prometheus-alerts.yml"))
	if err != nil {
		t.Fatal(err)
	}
	text := string(contents)
	for _, expected := range []string{
		"alert: DockyardCustomTLSCertificateExpiring",
		"expr: dockyard_custom_tls_certificate_expiry_seconds > 0 and dockyard_custom_tls_certificate_expiry_seconds < 2592000",
		"alert: DockyardCustomTLSCertificateExpired",
		"expr: dockyard_custom_tls_certificate_expiry_seconds <= 0",
		"alert: DockyardEdgeTLSReconciliationFailed",
		`expr: dockyard_edge_tls_reconciliation{status="error"} == 1`,
		"alert: DockyardEdgeTLSReconciliationStalled",
		`expr: dockyard_edge_tls_reconciliation_age_seconds{status="pending"} > 300`,
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

func testSAMLMetricMaterial(t *testing.T, notAfter time.Time) (string, string) {
	t.Helper()
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{SerialNumber: big.NewInt(notAfter.UnixNano()), Subject: pkix.Name{CommonName: "metrics-saml"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: notAfter, KeyUsage: x509.KeyUsageDigitalSignature}
	der, err := x509.CreateCertificate(rand.Reader, template, template, publicKey, privateKey)
	if err != nil {
		t.Fatal(err)
	}
	encoded := base64.StdEncoding.EncodeToString(der)
	metadata := fmt.Sprintf(`<EntityDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata" entityID="https://idp.example.test"><IDPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol"><KeyDescriptor use="signing"><ds:KeyInfo xmlns:ds="http://www.w3.org/2000/09/xmldsig#"><ds:X509Data><ds:X509Certificate>%s</ds:X509Certificate></ds:X509Data></ds:KeyInfo></KeyDescriptor><SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="https://idp.example.test/sso"/></IDPSSODescriptor></EntityDescriptor>`, encoded)
	certificate := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
	return metadata, certificate
}

func isolatedMetricsStore(t *testing.T, ctx context.Context, databaseURL string) *store.Store {
	t.Helper()
	admin, err := pgxpool.New(ctx, databaseURL)
	if err != nil {
		t.Fatal(err)
	}
	schema := "metrics_test_" + strings.ReplaceAll(uuid.NewString(), "-", "")
	if _, err = admin.Exec(ctx, fmt.Sprintf(`CREATE SCHEMA %s`, schema)); err != nil {
		admin.Close()
		t.Fatal(err)
	}
	config, err := pgxpool.ParseConfig(databaseURL)
	if err != nil {
		admin.Close()
		t.Fatal(err)
	}
	config.ConnConfig.RuntimeParams["search_path"] = schema
	pool, err := pgxpool.NewWithConfig(ctx, config)
	if err != nil {
		admin.Close()
		t.Fatal(err)
	}
	if err = store.Migrate(ctx, pool); err != nil {
		pool.Close()
		admin.Close()
		t.Fatal(err)
	}
	t.Cleanup(func() {
		pool.Close()
		_, _ = admin.Exec(context.Background(), fmt.Sprintf(`DROP SCHEMA %s CASCADE`, schema))
		admin.Close()
	})
	return &store.Store{Pool: pool}
}
