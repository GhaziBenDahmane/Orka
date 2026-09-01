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

	"github.com/bendahma/dokploy-go/internal/clustercontract"
	"github.com/bendahma/dokploy-go/internal/store"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

func TestRuntimeMetricsUseBoundedLabelsAndCumulativeBuckets(t *testing.T) {
	m := NewMetrics()
	m.SetLocalClusterPosture(clustercontract.LocalPosture{ObservedAt: time.Now(), InspectionStatus: clustercontract.LocalInspectionReady, Nodes: 3, ReadyNodes: 2, ActiveNodes: 2, SchedulableNodes: 1, Managers: 1, NanoCPUs: 4_000_000_000, MemoryBytes: 8_000_000_000, DockerSwarm: true, DockerCompose: true, EdgeProxyConfigured: true, EdgeProxyReady: false, EdgeProxyStatus: "inspection_failed"})
	m.SetControllerBuild("v1.2.3", strings.Repeat("a", 40), 3)
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
		`dockyard_controller_build_info{version="v1.2.3",revision="` + strings.Repeat("a", 40) + `"} 1`,
		`dockyard_controller_expected_replicas 3`,
		`dockyard_local_cluster_inspection_success 1`,
		`dockyard_local_cluster_node_count 3`,
		`dockyard_local_cluster_schedulable_node_count 1`,
		`dockyard_local_cluster_manager_count 1`,
		`dockyard_local_cluster_cpu_capacity_nanocpus 4000000000`,
		`dockyard_local_cluster_memory_capacity_bytes 8000000000`,
		`dockyard_local_cluster_docker_swarm_capable 1`,
		`dockyard_local_cluster_docker_compose_capable 1`,
		`dockyard_local_cluster_edge_proxy_ready{status="inspection_failed"} 0`,
	} {
		if !strings.Contains(text, expected) {
			t.Fatalf("missing %q in metrics:\n%s", expected, text)
		}
	}
}

func TestControllerBuildMetricsRejectUnboundedIdentity(t *testing.T) {
	m := NewMetrics()
	m.SetControllerBuild("release\nsecret", strings.Repeat("x", 129), 100)
	var output bytes.Buffer
	m.renderRuntime(&output)
	text := output.String()
	if !strings.Contains(text, `dockyard_controller_build_info{version="unknown",revision="unknown"} 1`) {
		t.Fatalf("unsafe build identity was not normalized:\n%s", text)
	}
	if !strings.Contains(text, "dockyard_controller_expected_replicas 1") {
		t.Fatalf("invalid replica count was not normalized:\n%s", text)
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
	notificationEndpointA, notificationEndpointB := uuid.New(), uuid.New()
	exhaustedNotification, activeNotification, unknownNotification, foreignNotification := uuid.New(), uuid.New(), uuid.New(), uuid.New()
	samlMetadata, samlCertificate := testSAMLMetricMaterial(t, time.Now().Add(90*24*time.Hour))
	projectID, environmentID, serviceID, malformedServiceID, unboundServiceID, destinationID := uuid.New(), uuid.New(), uuid.New(), uuid.New(), uuid.New(), uuid.New()
	volumePolicyID, missingVolumePolicyID, disabledVolumePolicyID, unboundVolumePolicyID := uuid.New(), uuid.New(), uuid.New(), uuid.New()
	volumeBackupID, corruptVolumeBackupID, artifactDeletionID := uuid.New(), uuid.New(), uuid.New()
	healthyDatabaseID, overdueDatabaseID, disabledDatabaseID, unprotectedDatabaseID := uuid.New(), uuid.New(), uuid.New(), uuid.New()
	healthyDatabasePolicyID, overdueDatabasePolicyID, disabledDatabasePolicyID, healthyDatabaseBackupID, corruptDatabaseBackupID := uuid.New(), uuid.New(), uuid.New(), uuid.New(), uuid.New()
	databaseDigest := "sha256:" + strings.Repeat("a", 64)
	statements := []struct {
		query string
		args  []any
	}{
		{`INSERT INTO organizations(id,name,slug) VALUES($1,'Metrics A',$2)`, []any{organizationA, "metrics-a-" + organizationA.String()}},
		{`INSERT INTO organizations(id,name,slug) VALUES($1,'Metrics B',$2)`, []any{organizationB, "metrics-b-" + organizationB.String()}},
		{`INSERT INTO notification_endpoints(id,organization_id,name,kind,encrypted_url,encrypted_secret,events) VALUES($1,$2,'Metrics notification A','webhook','encrypted','encrypted',ARRAY['backup.failed'])`, []any{notificationEndpointA, organizationA}},
		{`INSERT INTO notification_endpoints(id,organization_id,name,kind,encrypted_url,encrypted_secret,events) VALUES($1,$2,'Metrics notification B','webhook','encrypted','encrypted',ARRAY['backup.failed'])`, []any{notificationEndpointB, organizationB}},
		{`INSERT INTO notification_deliveries(id,endpoint_id,event_type,resource_type,resource_id,payload,status,finished_at) VALUES($1,$2,'backup.failed','database','exhausted','{}','failed',now()-interval '10 minutes')`, []any{exhaustedNotification, notificationEndpointA}},
		{`INSERT INTO notification_deliveries(id,endpoint_id,event_type,resource_type,resource_id,payload,status,finished_at) VALUES($1,$2,'backup.failed','database','retrying','{}','failed',now()-interval '1 minute')`, []any{activeNotification, notificationEndpointA}},
		{`INSERT INTO notification_deliveries(id,endpoint_id,event_type,resource_type,resource_id,payload,status,finished_at) VALUES($1,$2,'untrusted.dynamic.event','database','unknown','{}','failed',now()-interval '3 minutes')`, []any{unknownNotification, notificationEndpointA}},
		{`INSERT INTO notification_deliveries(id,endpoint_id,event_type,resource_type,resource_id,payload,status,finished_at) VALUES($1,$2,'backup.failed','database','foreign','{}','failed',now()-interval '2 minutes')`, []any{foreignNotification, notificationEndpointB}},
		{`INSERT INTO jobs(id,kind,payload,status,run_after) VALUES($1,'notify.webhook',$2,'pending',now()+interval '1 minute')`, []any{uuid.New(), `{"deliveryId":"` + activeNotification.String() + `"}`}},
		{`INSERT INTO managed_networks(id,organization_id,name,driver,status,last_error) VALUES($1,$2,'failed-overlay','overlay','error','metrics-network-error')`, []any{failedNetworkID, organizationA}},
		{`INSERT INTO managed_networks(id,organization_id,name,driver,status,deletion_requested_at) VALUES($1,$2,'deleting-overlay','overlay','deleting',now()-interval '25 minutes')`, []any{deletingNetworkID, organizationA}},
		{`INSERT INTO jobs(id,kind,payload,status,last_error,finished_at) VALUES($1,'network.delete',$2,'failed','metrics-network-finalizer-error',now()-interval '10 minutes')`, []any{uuid.New(), `{"networkId":"` + deletingNetworkID.String() + `"}`}},
		{`INSERT INTO template_repositories(id,organization_id,name,slug,repository_url,git_ref,sync_requested_at) VALUES($1,$2,'Pending catalog','pending','https://github.com/acme/pending','main',now()-interval '10 minutes')`, []any{templatePending, organizationA}},
		{`INSERT INTO template_repositories(id,organization_id,name,slug,repository_url,git_ref,last_sync_status,sync_started_at) VALUES($1,$2,'Running catalog','running','https://github.com/acme/running','main','running',now()-interval '11 minutes')`, []any{templateRunning, organizationB}},
		{`INSERT INTO template_repositories(id,organization_id,name,slug,repository_url,git_ref,last_sync_status) VALUES($1,$2,'Failed catalog','failed','https://github.com/acme/failed','main','failed')`, []any{templateFailed, organizationA}},
		{`INSERT INTO projects(id,organization_id,name,slug) VALUES($1,$2,'Metrics project','metrics-project')`, []any{projectID, organizationA}},
		{`INSERT INTO environments(id,project_id,name,slug) VALUES($1,$2,'Metrics environment','metrics-environment')`, []any{environmentID, projectID}},
		{`INSERT INTO compose_services(id,environment_id,name,slug,stack_name,storage_node_id,compose_yaml) VALUES($1,$2,'Metrics service','metrics-service',$3,'nodeabc123',$4)`, []any{serviceID, environmentID, "metrics-" + serviceID.String(), "services:\n  app:\n    image: example/app:1\n    volumes: [uploads:/uploads, cache:/cache, disabled:/disabled, scratch:/scratch]\nvolumes:\n  uploads: {}\n  cache: {}\n  disabled: {}\n  scratch: {}\n"}},
		{`INSERT INTO compose_services(id,environment_id,name,slug,stack_name,compose_yaml) VALUES($1,$2,'Malformed service','malformed-service',$3,'services: []')`, []any{malformedServiceID, environmentID, "malformed-" + malformedServiceID.String()}},
		{`INSERT INTO compose_services(id,environment_id,name,slug,stack_name,compose_yaml) VALUES($1,$2,'Unbound service','unbound-service',$3,'services: {app: {image: example/app:1, volumes: [data:/data]}}\nvolumes: {data: {}}')`, []any{unboundServiceID, environmentID, "unbound-" + unboundServiceID.String()}},
		{`INSERT INTO deploy_tokens(id,compose_service_id,token_hash,name,expires_at) VALUES($1,$2,$3,'metrics-deploy-hook',now()+interval '1 day')`, []any{deployTokenID, serviceID, []byte("metrics-deploy-token-" + deployTokenID.String())}},
		{`INSERT INTO source_credentials(id,organization_id,kind,name,server,username,encrypted_secret,created_at,updated_at) VALUES($1,$2,'registry','Metrics registry','registry.example.test','builder','encrypted',now()-interval '1 year',now()-interval '181 days')`, []any{sourceCredentialID, organizationA}},
		{`INSERT INTO application_sources(compose_service_id,repository_url,target_service,registry_image,registry_credential_id) VALUES($1,'https://example.test/metrics.git','app','registry.example.test/metrics/app',$2)`, []any{serviceID, sourceCredentialID}},
		{`INSERT INTO backup_destinations(id,organization_id,name,endpoint,bucket,use_tls,encrypted_credentials,created_at,updated_at) VALUES($1,$2,'Metrics destination','http://s3.example.test','backups',false,'encrypted',now()-interval '1 year',now()-interval '181 days')`, []any{destinationID, organizationA}},
		{`INSERT INTO volume_backup_policies(id,compose_service_id,volume_name,destination_id,interval_seconds,retention_count,quiesce,enabled,next_run_at) VALUES($1,$2,'uploads',$3,3600,7,true,true,now()+interval '1 hour')`, []any{volumePolicyID, serviceID, destinationID}},
		{`INSERT INTO volume_backup_policies(id,compose_service_id,volume_name,destination_id,interval_seconds,retention_count,quiesce,enabled,next_run_at) VALUES($1,$2,'cache',$3,3600,7,false,true,now()+interval '1 hour')`, []any{missingVolumePolicyID, serviceID, destinationID}},
		{`INSERT INTO volume_backup_policies(id,compose_service_id,volume_name,destination_id,interval_seconds,retention_count,quiesce,enabled,next_run_at) VALUES($1,$2,'disabled',$3,3600,7,true,false,now()+interval '1 hour')`, []any{disabledVolumePolicyID, serviceID, destinationID}},
		{`INSERT INTO volume_backup_policies(id,compose_service_id,volume_name,destination_id,interval_seconds,retention_count,quiesce,enabled,next_run_at) VALUES($1,$2,'data',$3,3600,7,true,true,now()+interval '1 hour')`, []any{unboundVolumePolicyID, unboundServiceID, destinationID}},
		{`INSERT INTO volume_backups(id,volume_backup_policy_id,compose_service_id,volume_name,storage_node_id,destination_id,quiesce,status,object_key,size_bytes,sha256,plaintext_sha256,encrypted_data_key,started_at,finished_at) VALUES($1,$2,$3,'uploads','nodeabc123',$4,true,'succeeded','volume.enc',42,$5,$6,'encrypted',now()-interval '2 hours',now()-interval '1 hour')`, []any{volumeBackupID, volumePolicyID, serviceID, destinationID, strings.Repeat("a", 64), strings.Repeat("b", 64)}},
		{`INSERT INTO volume_backups(id,compose_service_id,volume_name,storage_node_id,destination_id,quiesce,status,finished_at) VALUES($1,$2,'scratch','nodeabc123',$3,true,'succeeded',now())`, []any{corruptVolumeBackupID, serviceID, destinationID}},
		{`INSERT INTO volume_restores(id,volume_backup_id,status,started_at,finished_at) VALUES($1,$2,'succeeded',now()-interval '30 minutes',now()-interval '29 minutes')`, []any{uuid.New(), volumeBackupID}},
		{`INSERT INTO volume_restores(id,volume_backup_id,target_storage_node_id,offline,status,error,started_at,finished_at) VALUES($1,$2,'nodeabc123',true,'failed','simulated offline failure',now()-interval '20 minutes',now()-interval '19 minutes')`, []any{uuid.New(), volumeBackupID}},
		{`INSERT INTO volume_restores(id,volume_backup_id,target_storage_node_id,offline,status,created_at,started_at) VALUES($1,$2,'nodeabc123',true,'running',now()-interval '40 minutes',now()-interval '39 minutes')`, []any{uuid.New(), volumeBackupID}},
		{`INSERT INTO backup_artifact_deletions(id,destination_id,object_key,source_kind,source_id,created_at) VALUES($1,$2,'expired/object.enc','volume',$3,now()-interval '5 minutes')`, []any{artifactDeletionID, destinationID, volumeBackupID}},
		{`INSERT INTO database_instances(id,environment_id,name,slug,engine,version,encrypted_credentials) VALUES($1,$2,'Healthy backup','healthy-backup','postgres','17','encrypted')`, []any{healthyDatabaseID, environmentID}},
		{`INSERT INTO database_instances(id,environment_id,name,slug,engine,version,encrypted_credentials) VALUES($1,$2,'Overdue backup','overdue-backup','postgres','17','encrypted')`, []any{overdueDatabaseID, environmentID}},
		{`INSERT INTO database_instances(id,environment_id,name,slug,engine,version,encrypted_credentials) VALUES($1,$2,'Disabled backup','disabled-backup','postgres','17','encrypted')`, []any{disabledDatabaseID, environmentID}},
		{`INSERT INTO database_instances(id,environment_id,name,slug,engine,version,encrypted_credentials) VALUES($1,$2,'No backup policy','no-backup-policy','postgres','17','encrypted')`, []any{unprotectedDatabaseID, environmentID}},
		{`INSERT INTO backup_policies(id,database_instance_id,interval_seconds,retention_count,enabled,next_run_at,destination_id,verify_restore) VALUES($1,$2,900,7,true,now()+interval '15 minutes',$3,false)`, []any{healthyDatabasePolicyID, healthyDatabaseID, destinationID}},
		{`INSERT INTO backup_policies(id,database_instance_id,interval_seconds,retention_count,enabled,next_run_at,destination_id,verify_restore) VALUES($1,$2,900,7,true,now()+interval '15 minutes',$3,true)`, []any{overdueDatabasePolicyID, overdueDatabaseID, destinationID}},
		{`INSERT INTO backup_policies(id,database_instance_id,interval_seconds,retention_count,enabled,next_run_at,destination_id,verify_restore) VALUES($1,$2,900,7,false,now()+interval '15 minutes',$3,true)`, []any{disabledDatabasePolicyID, disabledDatabaseID, destinationID}},
		{`INSERT INTO database_backups(id,database_instance_id,status,format,destination_id,object_key,size_bytes,sha256,encrypted,plaintext_sha256,encrypted_data_key,started_at,finished_at) VALUES($1,$2,'succeeded','native',$3,'database/healthy.enc',42,$4,true,$5,'wrapped',now()-interval '21 minutes',now()-interval '20 minutes')`, []any{healthyDatabaseBackupID, healthyDatabaseID, destinationID, strings.Repeat("a", 64), strings.Repeat("b", 64)}},
		{`INSERT INTO database_backups(id,database_instance_id,status,format,destination_id,finished_at) VALUES($1,$2,'succeeded','native',$3,now())`, []any{corruptDatabaseBackupID, unprotectedDatabaseID, destinationID}},
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
		{`INSERT INTO clusters(id,organization_id,name,slug,state,capacity,capabilities,last_seen_at,certificate_serial,certificate_not_after,pending_certificate_serial,pending_certificate_not_after,pending_certificate_created_at) VALUES($1,$2,'Shared A','shared','active','{"nodes":3,"readyNodes":2,"activeNodes":1,"schedulableNodes":1,"managers":0,"nanoCpus":2000000000,"memoryBytes":4000000000,"secret":"metrics-cluster-secret"}','{"protocolVersion":1,"dockerSwarm":false,"dockerCompose":true,"edgeProxy":{"ready":false,"status":"network_missing","serviceName":"metrics-edge-secret"}}',now(),'current',now()+interval '1 hour','pending',now()+interval '7 days',now()-interval '10 minutes')`, []any{currentCluster, organizationA}},
		{`UPDATE environments SET cluster_id=$2,minimum_nodes=2,minimum_nano_cpus=4000000000,minimum_memory_bytes=8000000000 WHERE id=$1`, []any{environmentID, currentCluster}},
		{`INSERT INTO clusters(id,organization_id,name,slug,state,capacity,last_seen_at) VALUES($1,$2,'Shared B','shared','active','{"nodes":99,"secret":"stale-cluster-secret"}',now()-interval '10 minutes')`, []any{staleCluster, organizationB}},
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
	for _, metric := range []string{"dockyard_restore_drill_last_duration_seconds", "dockyard_restore_drill_overdue", "dockyard_database_backup_overdue", "dockyard_database_migrations", "dockyard_database_migration_active_age_seconds", "dockyard_database_migration_last_duration_seconds", "dockyard_database_migration_last_failure_age_seconds", "dockyard_volume_backups", "dockyard_volume_restores", "dockyard_volume_restore_active_age_seconds", "dockyard_volume_restore_last_failure_age_seconds", "dockyard_volume_backup_last_success_age_seconds", "dockyard_volume_restore_last_success_age_seconds", "dockyard_volume_backup_overdue", "dockyard_volume_restore_rehearsal_overdue", "dockyard_backup_artifact_integrity_issues", "dockyard_backup_artifact_deletions", "dockyard_backup_artifact_deletion_oldest_age_seconds", "dockyard_database_driver_inventory_info", "dockyard_database_driver_info", "dockyard_database_driver_binding_issues", "dockyard_service_reconciliation", "dockyard_service_reconciliation_age_seconds", "dockyard_managed_networks", "dockyard_managed_network_provisioning_age_seconds", "dockyard_notification_delivery_exhausted", "dockyard_notification_delivery_oldest_exhausted_age_seconds", "dockyard_commit_status_delivery_exhausted", "dockyard_commit_status_delivery_oldest_exhausted_age_seconds", "dockyard_cluster_heartbeat_missing", "dockyard_cluster_node_count", "dockyard_cluster_ready_node_count", "dockyard_cluster_active_node_count", "dockyard_cluster_schedulable_node_count", "dockyard_cluster_manager_count", "dockyard_cluster_cpu_capacity_nanocpus", "dockyard_cluster_memory_capacity_bytes", "dockyard_cluster_docker_swarm_capable", "dockyard_cluster_docker_compose_capable", "dockyard_cluster_edge_proxy_ready", "dockyard_environment_cluster_capacity_satisfied", "dockyard_cluster_agent_update_failure", "dockyard_agent_upgrade_verification_overdue", "dockyard_agent_upgrade_active_age_seconds", "dockyard_cluster_certificate_expiry_seconds", "dockyard_cluster_certificate_rotation_pending_age_seconds", "dockyard_service_account_token_expiry_seconds", "dockyard_scim_token_expiry_seconds", "dockyard_expired_credential_backlog", "dockyard_saml_certificate_rotation_pending_age_seconds", "dockyard_saml_certificate_expiry_seconds", "dockyard_saml_certificate_valid", "dockyard_ai_audit_runs", "dockyard_ai_audit_last_completed_age_seconds", "dockyard_ai_audit_last_failure_age_seconds", "dockyard_ai_audit_running_age_seconds", "dockyard_ai_audit_completion_overdue", "dockyard_template_repositories", "dockyard_template_repository_sync_pending_age_seconds", "dockyard_template_repository_sync_running_age_seconds", "dockyard_template_repository_sync_failed"} {
		if !strings.Contains(recorder.Body.String(), "# HELP "+metric) {
			t.Errorf("missing metric family %s", metric)
		}
	}
	for _, metric := range []string{"dockyard_database_backup_policy_status", "dockyard_database_restore_verification_enabled"} {
		if !strings.Contains(recorder.Body.String(), "# HELP "+metric) {
			t.Errorf("missing database protection metric family %s", metric)
		}
	}
	for _, metric := range []string{"dockyard_volume_backup_policy_inventory_valid", "dockyard_volume_backup_policy_status", "dockyard_volume_backup_storage_node_bound", "dockyard_volume_backup_quiescence_enabled"} {
		if !strings.Contains(recorder.Body.String(), "# HELP "+metric) {
			t.Errorf("missing volume protection metric family %s", metric)
		}
	}
	if !strings.Contains(recorder.Body.String(), "# HELP dockyard_database_utility_provenance_issues") {
		t.Error("missing database utility provenance metric family")
	}
	metrics := recorder.Body.String()
	for _, metric := range []string{"dockyard_deploy_token_expiry_seconds", "dockyard_source_credential_rotation_age_seconds", "dockyard_backup_destination_credential_rotation_age_seconds", "dockyard_backup_destination_tls", "dockyard_resource_finalizers", "dockyard_resource_finalizer_oldest_age_seconds", "dockyard_custom_tls_certificate_expiry_seconds", "dockyard_edge_tls_reconciliation", "dockyard_edge_tls_reconciliation_age_seconds"} {
		if !strings.Contains(metrics, "# HELP "+metric) {
			t.Errorf("missing metric family %s", metric)
		}
	}
	for _, expected := range []string{
		`dockyard_deploy_token_expiry_seconds{organization="` + organizationA.String() + `",service="` + serviceID.String() + `",token="` + deployTokenID.String() + `"}`,
		`dockyard_source_credential_rotation_age_seconds{organization="` + organizationA.String() + `",credential="` + sourceCredentialID.String() + `",kind="registry"}`,
		`dockyard_backup_destination_credential_rotation_age_seconds{organization="` + organizationA.String() + `",destination="` + destinationID.String() + `"}`,
		`dockyard_backup_destination_tls{organization="` + organizationA.String() + `",destination="` + destinationID.String() + `"} 0`,
		`dockyard_notification_delivery_exhausted{organization="` + organizationA.String() + `",event="backup.failed"} 1`,
		`dockyard_notification_delivery_exhausted{organization="` + organizationA.String() + `",event="unknown"} 1`,
		`dockyard_notification_deliveries{event="unknown",status="failed"} 1`,
		`dockyard_notification_delivery_oldest_exhausted_age_seconds{organization="` + organizationA.String() + `",event="backup.failed"}`,
		`dockyard_database_backup_policy_status{database="` + healthyDatabaseID.String() + `",state="enabled"} 1`,
		`dockyard_database_backup_policy_status{database="` + disabledDatabaseID.String() + `",state="disabled"} 1`,
		`dockyard_database_backup_policy_status{database="` + unprotectedDatabaseID.String() + `",state="missing"} 1`,
		`dockyard_database_restore_verification_enabled{database="` + healthyDatabaseID.String() + `"} 0`,
		`dockyard_database_restore_verification_enabled{database="` + overdueDatabaseID.String() + `"} 1`,
		`dockyard_database_backup_overdue{database="` + healthyDatabaseID.String() + `"} 0`,
		`dockyard_database_backup_overdue{database="` + overdueDatabaseID.String() + `"} 1`,
		`dockyard_backup_artifact_integrity_issues{kind="database"} 1`,
		`dockyard_backup_artifact_integrity_issues{kind="volume"} 1`,
		`dockyard_volume_backup_policy_inventory_valid{service="` + serviceID.String() + `"} 1`,
		`dockyard_volume_backup_policy_inventory_valid{service="` + malformedServiceID.String() + `"} 0`,
		`dockyard_volume_backup_policy_status{service="` + serviceID.String() + `",volume="uploads",state="enabled"} 1`,
		`dockyard_volume_backup_policy_status{service="` + serviceID.String() + `",volume="disabled",state="disabled"} 1`,
		`dockyard_volume_backup_policy_status{service="` + serviceID.String() + `",volume="scratch",state="missing"} 1`,
		`dockyard_volume_backup_storage_node_bound{service="` + serviceID.String() + `",volume="uploads"} 1`,
		`dockyard_volume_backup_storage_node_bound{service="` + unboundServiceID.String() + `",volume="data"} 0`,
		`dockyard_volume_backup_quiescence_enabled{service="` + serviceID.String() + `",volume="uploads"} 1`,
		`dockyard_volume_backup_quiescence_enabled{service="` + serviceID.String() + `",volume="cache"} 0`,
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
		`dockyard_cluster_node_count{organization="` + organizationA.String() + `",cluster="shared"} 3`,
		`dockyard_cluster_ready_node_count{organization="` + organizationA.String() + `",cluster="shared"} 2`,
		`dockyard_cluster_active_node_count{organization="` + organizationA.String() + `",cluster="shared"} 1`,
		`dockyard_cluster_schedulable_node_count{organization="` + organizationA.String() + `",cluster="shared"} 1`,
		`dockyard_cluster_manager_count{organization="` + organizationA.String() + `",cluster="shared"} 0`,
		`dockyard_cluster_cpu_capacity_nanocpus{organization="` + organizationA.String() + `",cluster="shared"} 2e+09`,
		`dockyard_cluster_memory_capacity_bytes{organization="` + organizationA.String() + `",cluster="shared"} 4e+09`,
		`dockyard_cluster_docker_swarm_capable{organization="` + organizationA.String() + `",cluster="shared"} 0`,
		`dockyard_cluster_docker_compose_capable{organization="` + organizationA.String() + `",cluster="shared"} 1`,
		`dockyard_cluster_edge_proxy_ready{organization="` + organizationA.String() + `",cluster="shared",status="network_missing"} 0`,
		`dockyard_environment_cluster_capacity_satisfied{organization="` + organizationA.String() + `",environment="` + environmentID.String() + `",cluster="shared"} 0`,
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
		`dockyard_volume_backups{status="succeeded"} 2`,
		`dockyard_volume_restores{mode="online",status="succeeded"} 1`,
		`dockyard_volume_restores{mode="offline",status="failed"} 1`,
		`dockyard_volume_restores{mode="offline",status="running"} 1`,
		`dockyard_volume_restore_active_age_seconds{service="` + serviceID.String() + `",volume="uploads",mode="offline",status="running"}`,
		`dockyard_volume_restore_last_failure_age_seconds{service="` + serviceID.String() + `",volume="uploads",mode="offline"}`,
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
	if strings.Contains(metrics, "metrics-cluster-secret") || strings.Contains(metrics, "metrics-edge-secret") || strings.Contains(metrics, "stale-cluster-secret") || strings.Contains(metrics, `dockyard_cluster_node_count{organization="`+organizationB.String()) {
		t.Fatal("cluster metrics exposed raw or stale capacity metadata")
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
		"alert: DockyardDatabaseUtilityProvenanceMissing",
		"expr: max without (instance) (dockyard_database_utility_provenance_issues) > 0",
	} {
		if !strings.Contains(text, expected) {
			t.Errorf("missing alert configuration %q", expected)
		}
	}
}

func TestPrometheusAlertsCoverControllerFleetIdentity(t *testing.T) {
	contents, err := os.ReadFile(filepath.Join("..", "..", "deploy", "prometheus-alerts.yml"))
	if err != nil {
		t.Fatal(err)
	}
	text := string(contents)
	for _, expected := range []string{
		"alert: DockyardControllerReplicaShortfall",
		"count(dockyard_controller_build_info) < max(dockyard_controller_expected_replicas)",
		"alert: DockyardControllerBuildFleetMismatch",
		"count(count by (version, revision) (dockyard_controller_build_info)) > 1",
	} {
		if !strings.Contains(text, expected) {
			t.Errorf("missing controller fleet alert configuration %q", expected)
		}
	}
}

func TestPrometheusSwarmScrapeDiscoversControllerTasksDirectly(t *testing.T) {
	contents, err := os.ReadFile(filepath.Join("..", "..", "deploy", "prometheus-scrape.yml"))
	if err != nil {
		t.Fatal(err)
	}
	text := string(contents)
	for _, expected := range []string{
		"job_name: dockyard",
		"bearer_token_file: /run/secrets/dockyard_metrics_token",
		"- tasks.dockyard_dockyard",
		"type: A",
		"port: 8080",
	} {
		if !strings.Contains(text, expected) {
			t.Errorf("missing direct Swarm task discovery configuration %q", expected)
		}
	}
	if strings.Contains(text, "http://dockyard:8080") {
		t.Error("scrape configuration uses the Swarm VIP instead of per-task DNS discovery")
	}
}

func TestPrometheusAlertsCoverVolumeRecovery(t *testing.T) {
	contents, err := os.ReadFile(filepath.Join("..", "..", "deploy", "prometheus-alerts.yml"))
	if err != nil {
		t.Fatal(err)
	}
	text := string(contents)
	for _, expected := range []string{
		"alert: DockyardVolumeBackupPolicyUnavailable",
		`expr: max without (instance) (dockyard_volume_backup_policy_status{state=~"missing|disabled"}) == 1`,
		"alert: DockyardVolumeBackupPolicyInventoryInvalid",
		"expr: max without (instance) (dockyard_volume_backup_policy_inventory_valid) == 0",
		"alert: DockyardVolumeBackupStorageNodeMissing",
		"expr: max without (instance) (dockyard_volume_backup_storage_node_bound) == 0",
		"alert: DockyardVolumeBackupQuiescenceDisabled",
		"expr: max without (instance) (dockyard_volume_backup_quiescence_enabled) == 0",
		"alert: DockyardVolumeBackupOverdue",
		"expr: max without (instance) (dockyard_volume_backup_overdue) == 1",
		"alert: DockyardVolumeRestoreRehearsalOverdue",
		"expr: max without (instance) (dockyard_volume_restore_rehearsal_overdue) == 1",
		"alert: DockyardOfflineVolumeRestoreFailed",
		`expr: max without (instance) (dockyard_volume_restore_last_failure_age_seconds{mode="offline"}) < 900`,
		"description: Service {{ $labels.service }} volume {{ $labels.volume }} failed offline recovery",
		"alert: DockyardOfflineVolumeRestoreStalled",
		`expr: max without (instance) (dockyard_volume_restore_active_age_seconds{mode="offline"}) > 1800`,
		"alert: DockyardBackupArtifactDeletionStalled",
		"expr: max without (instance) (dockyard_backup_artifact_deletion_oldest_age_seconds) > 900",
	} {
		if !strings.Contains(text, expected) {
			t.Errorf("missing alert configuration %q", expected)
		}
	}
}

func TestPrometheusAlertsCoverDatabaseRecoveryPolicy(t *testing.T) {
	contents, err := os.ReadFile(filepath.Join("..", "..", "deploy", "prometheus-alerts.yml"))
	if err != nil {
		t.Fatal(err)
	}
	text := string(contents)
	for _, expected := range []string{
		"alert: DockyardDatabaseBackupPolicyUnavailable",
		`expr: max without (instance) (dockyard_database_backup_policy_status{state=~"missing|disabled"}) == 1`,
		"alert: DockyardDatabaseRestoreVerificationDisabled",
		"expr: max without (instance) (dockyard_database_restore_verification_enabled) == 0",
	} {
		if !strings.Contains(text, expected) {
			t.Errorf("missing database recovery-policy alert configuration %q", expected)
		}
	}
}

func TestPrometheusRecoveryAlertsDeduplicateHAReplicas(t *testing.T) {
	contents, err := os.ReadFile(filepath.Join("..", "..", "deploy", "prometheus-alerts.yml"))
	if err != nil {
		t.Fatal(err)
	}
	text := string(contents)
	for _, metric := range []string{
		"dockyard_database_utility_provenance_issues",
		"dockyard_database_backup_last_success_age_seconds",
		"dockyard_database_backup_overdue",
		"dockyard_database_backup_policy_status",
		"dockyard_database_restore_verification_enabled",
		"dockyard_backup_artifact_deletion_oldest_age_seconds",
		"dockyard_volume_backup_overdue",
		"dockyard_volume_backup_policy_status",
		"dockyard_volume_backup_policy_inventory_valid",
		"dockyard_volume_backup_storage_node_bound",
		"dockyard_volume_backup_quiescence_enabled",
		"dockyard_volume_restore_rehearsal_overdue",
		"dockyard_volume_restore_last_failure_age_seconds",
		"dockyard_volume_restore_active_age_seconds",
		"dockyard_restore_drill_overdue",
		"dockyard_database_migration_active_age_seconds",
		"dockyard_database_migration_last_failure_age_seconds",
	} {
		if !strings.Contains(text, "max without (instance) ("+metric) {
			t.Errorf("recovery alert for %s does not collapse replicated HA series", metric)
		}
	}
}

func TestPrometheusSharedStateAlertsDeduplicateHAReplicas(t *testing.T) {
	contents, err := os.ReadFile(filepath.Join("..", "..", "deploy", "prometheus-alerts.yml"))
	if err != nil {
		t.Fatal(err)
	}
	text := string(contents)
	for _, metric := range []string{
		"dockyard_job_stale_leases",
		"dockyard_template_repository_sync_pending_age_seconds",
		"dockyard_template_repository_sync_running_age_seconds",
		"dockyard_template_repository_sync_failed",
		"dockyard_ai_audit_last_failure_age_seconds",
		"dockyard_ai_audit_completion_overdue",
		"dockyard_ai_audit_running_age_seconds",
		"dockyard_maintenance_scopes",
		"dockyard_cluster_heartbeat_missing",
		"dockyard_cluster_manager_count",
		"dockyard_cluster_schedulable_node_count",
		"dockyard_cluster_ready_node_count",
		"dockyard_cluster_node_count",
		"dockyard_cluster_active_node_count",
		"dockyard_cluster_docker_swarm_capable",
		"dockyard_cluster_docker_compose_capable",
		"dockyard_cluster_edge_proxy_ready",
		"dockyard_environment_cluster_capacity_satisfied",
		"dockyard_cluster_agent_update_failure",
		"dockyard_agent_upgrade_verification_overdue",
		"dockyard_agent_upgrade_active_age_seconds",
		"dockyard_cluster_certificate_expiry_seconds",
		"dockyard_cluster_certificate_rotation_pending_age_seconds",
		"dockyard_custom_tls_certificate_expiry_seconds",
		"dockyard_edge_tls_reconciliation",
		"dockyard_edge_tls_reconciliation_age_seconds",
		"dockyard_service_account_token_expiry_seconds",
		"dockyard_deploy_token_expiry_seconds",
		"dockyard_source_credential_rotation_age_seconds",
		"dockyard_backup_destination_credential_rotation_age_seconds",
		"dockyard_backup_destination_tls",
		"dockyard_resource_finalizers",
		"dockyard_resource_finalizer_oldest_age_seconds",
		"dockyard_managed_networks",
		"dockyard_managed_network_provisioning_age_seconds",
		"dockyard_scim_token_expiry_seconds",
		"dockyard_expired_credential_backlog",
		"dockyard_saml_certificate_expiry_seconds",
		"dockyard_saml_certificate_valid",
		"dockyard_saml_certificate_rotation_pending_age_seconds",
	} {
		if !strings.Contains(text, "without (instance) ("+metric) {
			t.Errorf("shared-state alert for %s does not collapse replicated HA series", metric)
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
		"expr: min without (instance) (dockyard_ai_audit_last_failure_age_seconds) < 900",
		"alert: DockyardAIAuditOverdue",
		"expr: max without (instance) (dockyard_ai_audit_completion_overdue) == 1",
		"alert: DockyardAIAuditStuck",
		"expr: max without (instance) (dockyard_ai_audit_running_age_seconds) > 600",
	} {
		if !strings.Contains(text, expected) {
			t.Errorf("missing alert configuration %q", expected)
		}
	}
}

func TestPrometheusAlertsCoverExhaustedNotificationDeliveries(t *testing.T) {
	contents, err := os.ReadFile(filepath.Join("..", "..", "deploy", "prometheus-alerts.yml"))
	if err != nil {
		t.Fatal(err)
	}
	text := string(contents)
	for _, expected := range []string{
		"alert: DockyardNotificationDeliveryExhausted",
		"expr: max without (instance) (dockyard_notification_delivery_exhausted) > 0",
		"inspect notification delivery history and use audited retry",
	} {
		if !strings.Contains(text, expected) {
			t.Errorf("missing alert configuration %q", expected)
		}
	}
}

func TestPrometheusAlertsCoverExhaustedCommitStatusDeliveries(t *testing.T) {
	contents, err := os.ReadFile(filepath.Join("..", "..", "deploy", "prometheus-alerts.yml"))
	if err != nil {
		t.Fatal(err)
	}
	text := string(contents)
	for _, expected := range []string{
		"alert: DockyardCommitStatusDeliveryExhausted",
		"expr: max without (instance) (dockyard_commit_status_delivery_exhausted) > 0",
		"inspect commit status callback history and use audited retry",
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
		"expr: max without (instance) (dockyard_template_repository_sync_pending_age_seconds) > 300",
		"alert: DockyardTemplateRepositorySyncStuck",
		"expr: max without (instance) (dockyard_template_repository_sync_running_age_seconds) > 600",
		"alert: DockyardTemplateRepositorySyncFailed",
		"expr: max without (instance) (dockyard_template_repository_sync_failed) == 1",
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
		"expr: min without (instance) (dockyard_service_account_token_expiry_seconds) > 0 and min without (instance) (dockyard_service_account_token_expiry_seconds) < 604800",
		"alert: DockyardServiceAccountTokenExpired",
		"expr: min without (instance) (dockyard_service_account_token_expiry_seconds) <= 0",
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
		"expr: min without (instance) (dockyard_deploy_token_expiry_seconds) > 0 and min without (instance) (dockyard_deploy_token_expiry_seconds) < 604800",
		"alert: DockyardDeployTokenExpired",
		"expr: min without (instance) (dockyard_deploy_token_expiry_seconds) <= 0",
		"alert: DockyardSourceCredentialRotationOverdue",
		"expr: max without (instance) (dockyard_source_credential_rotation_age_seconds) > 15552000",
		"alert: DockyardBackupDestinationCredentialRotationOverdue",
		"expr: max without (instance) (dockyard_backup_destination_credential_rotation_age_seconds) > 15552000",
		"alert: DockyardBackupDestinationPlaintextTransport",
		"expr: min without (instance) (dockyard_backup_destination_tls) == 0",
		"alert: DockyardResourceFinalizerRequiresIntervention",
		`expr: max without (instance) (dockyard_resource_finalizers{state=~"failed|missing"}) > 0`,
		"alert: DockyardResourceFinalizerStalled",
		`expr: max without (instance) (dockyard_resource_finalizer_oldest_age_seconds) > 900 unless on (organization, kind) max without (instance) (dockyard_resource_finalizers{state=~"failed|missing"}) > 0`,
		"alert: DockyardManagedNetworkProvisioningFailed",
		`expr: max without (instance) (dockyard_managed_networks{status="error"}) > 0`,
		"alert: DockyardManagedNetworkProvisioningStalled",
		"expr: max without (instance) (dockyard_managed_network_provisioning_age_seconds) > 900",
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
		"expr: min without (instance) (dockyard_scim_token_expiry_seconds) > 0 and min without (instance) (dockyard_scim_token_expiry_seconds) < 604800",
		"alert: DockyardSCIMTokenExpired",
		"expr: min without (instance) (dockyard_scim_token_expiry_seconds) <= 0",
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
		"expr: max without (instance) (dockyard_expired_credential_backlog) > 0",
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
		"expr: min without (instance) (dockyard_saml_certificate_expiry_seconds) > 0 and min without (instance) (dockyard_saml_certificate_expiry_seconds) < 2592000",
		"alert: DockyardSAMLCertificateExpired",
		"expr: min without (instance) (dockyard_saml_certificate_expiry_seconds) <= 0",
		"alert: DockyardSAMLCertificateInvalid",
		"expr: min without (instance) (dockyard_saml_certificate_valid) == 0 unless on (organization, provider, kind) min without (instance) (dockyard_saml_certificate_expiry_seconds) <= 0",
		"alert: DockyardSAMLCertificateRotationStalled",
		"expr: max without (instance) (dockyard_saml_certificate_rotation_pending_age_seconds) > 604800",
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
		"alert: DockyardLocalClusterInspectionFailed",
		"expr: min without (instance) (dockyard_local_cluster_inspection_success) == 0",
		"alert: DockyardLocalClusterPostureStale",
		"dockyard_local_cluster_observation_age_seconds",
		"alert: DockyardLocalClusterManagerUnavailable",
		"dockyard_local_cluster_manager_count",
		"alert: DockyardLocalClusterUnschedulable",
		"dockyard_local_cluster_schedulable_node_count",
		"alert: DockyardLocalClusterNodeReadinessDegraded",
		"dockyard_local_cluster_ready_node_count",
		"alert: DockyardLocalClusterNodesDrained",
		"dockyard_local_cluster_active_node_count",
		"alert: DockyardLocalClusterCapabilityMissing",
		"dockyard_local_cluster_docker_swarm_capable",
		"dockyard_local_cluster_docker_compose_capable",
		"alert: DockyardLocalEdgeProxyUnavailable",
		"dockyard_local_cluster_edge_proxy_ready",
		"alert: DockyardRemoteClusterHeartbeatMissing",
		"expr: max without (instance) (dockyard_cluster_heartbeat_missing) == 1",
		"alert: DockyardRemoteClusterManagerUnavailable",
		"expr: max without (instance) (dockyard_cluster_manager_count) == 0",
		"alert: DockyardRemoteClusterUnschedulable",
		"expr: max without (instance) (dockyard_cluster_schedulable_node_count) == 0",
		"alert: DockyardRemoteClusterNodeReadinessDegraded",
		"expr: max without (instance) (dockyard_cluster_ready_node_count) < max without (instance) (dockyard_cluster_node_count)",
		"alert: DockyardRemoteClusterNodesDrained",
		"expr: max without (instance) (dockyard_cluster_active_node_count) < max without (instance) (dockyard_cluster_ready_node_count)",
		"alert: DockyardRemoteClusterCapabilityMissing",
		"dockyard_cluster_docker_swarm_capable",
		"dockyard_cluster_docker_compose_capable",
		"alert: DockyardRemoteEdgeProxyUnavailable",
		"expr: max without (instance) (dockyard_cluster_edge_proxy_ready) == 0",
		"alert: DockyardEnvironmentClusterCapacityInsufficient",
		"expr: max without (instance) (dockyard_environment_cluster_capacity_satisfied) == 0",
		"alert: DockyardAgentUpgradeRollback",
		"expr: max without (instance) (dockyard_cluster_agent_update_failure) == 1",
		"alert: DockyardAgentUpgradeVerificationOverdue",
		"expr: max without (instance) (dockyard_agent_upgrade_verification_overdue) > 0",
		"alert: DockyardAgentUpgradeStalled",
		`expr: max without (instance) (dockyard_agent_upgrade_active_age_seconds{status=~"pending|leased"}) > 900`,
		"alert: DockyardAgentCertificateExpiring",
		"expr: min without (instance) (dockyard_cluster_certificate_expiry_seconds) > 0 and min without (instance) (dockyard_cluster_certificate_expiry_seconds) < 79200",
		"alert: DockyardAgentCertificateExpired",
		"expr: min without (instance) (dockyard_cluster_certificate_expiry_seconds) <= 0",
		"alert: DockyardAgentCertificateRotationStalled",
		"expr: max without (instance) (dockyard_cluster_certificate_rotation_pending_age_seconds) > 300",
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
		"expr: min without (instance) (dockyard_custom_tls_certificate_expiry_seconds) > 0 and min without (instance) (dockyard_custom_tls_certificate_expiry_seconds) < 2592000",
		"alert: DockyardCustomTLSCertificateExpired",
		"expr: min without (instance) (dockyard_custom_tls_certificate_expiry_seconds) <= 0",
		"alert: DockyardEdgeTLSReconciliationFailed",
		`expr: max without (instance) (dockyard_edge_tls_reconciliation{status="error"}) == 1`,
		"alert: DockyardEdgeTLSReconciliationStalled",
		`expr: max without (instance) (dockyard_edge_tls_reconciliation_age_seconds{status="pending"}) > 300`,
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
