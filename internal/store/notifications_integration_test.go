package store

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"reflect"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
)

func TestFailureNotificationsAreFilteredAndDeduplicated(t *testing.T) {
	databaseURL := os.Getenv("DOCKYARD_TEST_DATABASE_URL")
	if databaseURL == "" {
		t.Skip("DOCKYARD_TEST_DATABASE_URL is not set")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	db, err := Open(ctx, databaseURL)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(db.Pool.Close)
	orgID, projectID, environmentID, serviceID, deploymentID := uuid.New(), uuid.New(), uuid.New(), uuid.New(), uuid.New()
	endpointID, ignoredEndpointID := uuid.New(), uuid.New()
	statements := []struct {
		query string
		args  []any
	}{
		{`INSERT INTO organizations(id,name,slug) VALUES($1,'Notify',$2)`, []any{orgID, "notify-" + orgID.String()}},
		{`INSERT INTO projects(id,organization_id,name,slug) VALUES($1,$2,'Project','project')`, []any{projectID, orgID}},
		{`INSERT INTO environments(id,project_id,name,slug) VALUES($1,$2,'Production','production')`, []any{environmentID, projectID}},
		{`INSERT INTO compose_services(id,environment_id,name,slug,stack_name,compose_yaml) VALUES($1,$2,'App','app',$3,'services: {}')`, []any{serviceID, environmentID, "notify-" + serviceID.String()}},
		{`INSERT INTO deployments(id,compose_service_id,revision,compose_snapshot,status,trigger) VALUES($1,$2,1,'services: {}','failed','manual')`, []any{deploymentID, serviceID}},
		{`INSERT INTO notification_endpoints(id,organization_id,name,kind,encrypted_url,encrypted_secret,events) VALUES($1,$2,'receiver','webhook','url','secret',ARRAY['deployment.failed']),($3,$2,'ignored','webhook','url','secret',ARRAY['backup.failed'])`, []any{endpointID, orgID, ignoredEndpointID}},
	}
	for _, statement := range statements {
		if _, err = db.Pool.Exec(ctx, statement.query, statement.args...); err != nil {
			t.Fatal(err)
		}
	}
	t.Cleanup(func() { _, _ = db.Pool.Exec(context.Background(), `DELETE FROM organizations WHERE id=$1`, orgID) })
	payload, _ := json.Marshal(map[string]string{"deploymentId": deploymentID.String()})
	for range 2 {
		if err = db.QueueFailureNotifications(ctx, "deploy.compose", payload, errors.New("boom")); err != nil {
			t.Fatal(err)
		}
	}
	var deliveries, jobs int
	if err = db.Pool.QueryRow(ctx, `SELECT count(*) FROM notification_deliveries WHERE endpoint_id=$1`, endpointID).Scan(&deliveries); err != nil {
		t.Fatal(err)
	}
	if err = db.Pool.QueryRow(ctx, `SELECT count(*) FROM jobs WHERE kind='notify.webhook' AND payload->>'deliveryId' IN (SELECT id::text FROM notification_deliveries WHERE endpoint_id=$1)`, endpointID).Scan(&jobs); err != nil {
		t.Fatal(err)
	}
	if deliveries != 1 || jobs != 1 {
		t.Fatalf("deliveries=%d jobs=%d, want one deduplicated delivery", deliveries, jobs)
	}
}

func TestRestoreDrillFailureUsesDedicatedEvent(t *testing.T) {
	databaseURL := os.Getenv("DOCKYARD_TEST_DATABASE_URL")
	if databaseURL == "" {
		t.Skip("DOCKYARD_TEST_DATABASE_URL is not set")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	db, err := Open(ctx, databaseURL)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(db.Pool.Close)
	orgID, projectID, environmentID, databaseID, backupID, restoreID, endpointID := uuid.New(), uuid.New(), uuid.New(), uuid.New(), uuid.New(), uuid.New(), uuid.New()
	statements := []struct {
		query string
		args  []any
	}{
		{`INSERT INTO organizations(id,name,slug) VALUES($1,'Drill alert',$2)`, []any{orgID, "drill-alert-" + orgID.String()}},
		{`INSERT INTO projects(id,organization_id,name,slug) VALUES($1,$2,'Project','project')`, []any{projectID, orgID}},
		{`INSERT INTO environments(id,project_id,name,slug) VALUES($1,$2,'Production','production')`, []any{environmentID, projectID}},
		{`INSERT INTO database_instances(id,environment_id,name,slug,engine,version,encrypted_credentials) VALUES($1,$2,'DB','db','postgres','17','secret')`, []any{databaseID, environmentID}},
		{`INSERT INTO database_backups(id,database_instance_id,status,format) VALUES($1,$2,'succeeded','native')`, []any{backupID, databaseID}},
		{`INSERT INTO database_restores(id,database_backup_id,status,kind) VALUES($1,$2,'failed','drill')`, []any{restoreID, backupID}},
		{`INSERT INTO notification_endpoints(id,organization_id,name,kind,encrypted_url,encrypted_secret,events) VALUES($1,$2,'drills','webhook','url','secret',ARRAY['restore.drill.failed'])`, []any{endpointID, orgID}},
	}
	for _, statement := range statements {
		if _, err = db.Pool.Exec(ctx, statement.query, statement.args...); err != nil {
			t.Fatal(err)
		}
	}
	t.Cleanup(func() { _, _ = db.Pool.Exec(context.Background(), `DELETE FROM organizations WHERE id=$1`, orgID) })
	payload, _ := json.Marshal(map[string]string{"restoreId": restoreID.String()})
	if err := db.QueueFailureNotifications(ctx, "restore.database", payload, errors.New("drill failed")); err != nil {
		t.Fatal(err)
	}
	var event string
	if err := db.Pool.QueryRow(ctx, `SELECT event_type FROM notification_deliveries WHERE endpoint_id=$1`, endpointID).Scan(&event); err != nil || event != "restore.drill.failed" {
		t.Fatalf("event=%q err=%v", event, err)
	}
}

func TestOfflineVolumeRestoreFailureIncludesRecoveryContext(t *testing.T) {
	databaseURL := os.Getenv("DOCKYARD_TEST_DATABASE_URL")
	if databaseURL == "" {
		t.Skip("DOCKYARD_TEST_DATABASE_URL is not set")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	db, err := Open(ctx, databaseURL)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(db.Pool.Close)
	organizationID, projectID, environmentID, serviceID := uuid.New(), uuid.New(), uuid.New(), uuid.New()
	destinationID, backupID, restoreID, endpointID := uuid.New(), uuid.New(), uuid.New(), uuid.New()
	for _, statement := range []struct {
		query string
		args  []any
	}{
		{`INSERT INTO organizations(id,name,slug) VALUES($1,'Offline recovery alert',$2)`, []any{organizationID, "offline-recovery-alert-" + organizationID.String()}},
		{`INSERT INTO projects(id,organization_id,name,slug) VALUES($1,$2,'Project','project')`, []any{projectID, organizationID}},
		{`INSERT INTO environments(id,project_id,name,slug) VALUES($1,$2,'Production','production')`, []any{environmentID, projectID}},
		{`INSERT INTO compose_services(id,environment_id,name,slug,stack_name,storage_node_id,compose_yaml,desired_state) VALUES($1,$2,'App','app',$3,'nodenew','services: {}','stopped')`, []any{serviceID, environmentID, "offline-alert-" + serviceID.String()}},
		{`INSERT INTO backup_destinations(id,organization_id,name,endpoint,bucket,encrypted_credentials) VALUES($1,$2,'S3','https://s3.example.test','backups','encrypted')`, []any{destinationID, organizationID}},
		{`INSERT INTO volume_backups(id,compose_service_id,volume_name,storage_node_id,destination_id,quiesce,status,object_key,size_bytes,sha256,plaintext_sha256,encrypted_data_key,finished_at) VALUES($1,$2,'uploads','nodeold',$3,true,'succeeded','backup.enc',42,$4,$5,'encrypted',now())`, []any{backupID, serviceID, destinationID, strings.Repeat("a", 64), strings.Repeat("b", 64)}},
		{`INSERT INTO volume_restores(id,volume_backup_id,target_storage_node_id,offline,status,error,started_at,finished_at) VALUES($1,$2,'nodenew',true,'failed','stored private failure',now()-interval '1 minute',now())`, []any{restoreID, backupID}},
		{`INSERT INTO notification_endpoints(id,organization_id,name,kind,encrypted_url,encrypted_secret,events) VALUES($1,$2,'recovery-on-call','webhook','url','secret',ARRAY['restore.failed'])`, []any{endpointID, organizationID}},
	} {
		if _, err = db.Pool.Exec(ctx, statement.query, statement.args...); err != nil {
			t.Fatal(err)
		}
	}
	t.Cleanup(func() {
		_, _ = db.Pool.Exec(context.Background(), `DELETE FROM organizations WHERE id=$1`, organizationID)
	})
	payload, _ := json.Marshal(map[string]string{"restoreId": restoreID.String()})
	if err = db.QueueFailureNotifications(ctx, "restore.volume", payload, errors.New("worker recovery failed")); err != nil {
		t.Fatal(err)
	}
	var eventType, resourceType, resourceID string
	var deliveryPayload []byte
	if err = db.Pool.QueryRow(ctx, `SELECT event_type,resource_type,resource_id,payload FROM notification_deliveries WHERE endpoint_id=$1`, endpointID).Scan(&eventType, &resourceType, &resourceID, &deliveryPayload); err != nil {
		t.Fatal(err)
	}
	var decoded map[string]any
	if err = json.Unmarshal(deliveryPayload, &decoded); err != nil {
		t.Fatal(err)
	}
	if eventType != "restore.failed" || resourceType != "volume_restore" || resourceID != restoreID.String() || decoded["mode"] != "offline" || decoded["serviceId"] != serviceID.String() || decoded["volumeName"] != "uploads" || decoded["targetStorageNodeId"] != "nodenew" || !strings.Contains(decoded["text"].(string), "offline volume uploads") {
		t.Fatalf("offline restore notification event=%q resource=%q/%q payload=%s", eventType, resourceType, resourceID, deliveryPayload)
	}
}

func TestManagedNetworkFailuresUseDedicatedEvents(t *testing.T) {
	databaseURL := os.Getenv("DOCKYARD_TEST_DATABASE_URL")
	if databaseURL == "" {
		t.Skip("DOCKYARD_TEST_DATABASE_URL is not set")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	db, err := Open(ctx, databaseURL)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(db.Pool.Close)
	organizationID, networkID, endpointID := uuid.New(), uuid.New(), uuid.New()
	for _, statement := range []struct {
		query string
		args  []any
	}{
		{`INSERT INTO organizations(id,name,slug) VALUES($1,'Network notifications',$2)`, []any{organizationID, "network-notifications-" + organizationID.String()}},
		{`INSERT INTO managed_networks(id,organization_id,name,driver,status) VALUES($1,$2,'shared','overlay','error')`, []any{networkID, organizationID}},
		{`INSERT INTO notification_endpoints(id,organization_id,name,kind,encrypted_url,encrypted_secret,events) VALUES($1,$2,'network-on-call','webhook','url','secret',ARRAY['network.provision.failed','network.delete.failed'])`, []any{endpointID, organizationID}},
	} {
		if _, err = db.Pool.Exec(ctx, statement.query, statement.args...); err != nil {
			t.Fatal(err)
		}
	}
	t.Cleanup(func() {
		_, _ = db.Pool.Exec(context.Background(), `DELETE FROM organizations WHERE id=$1`, organizationID)
	})
	payload, _ := json.Marshal(map[string]string{"networkId": networkID.String()})
	for _, kind := range []string{"network.create", "network.delete"} {
		if err = db.QueueFailureNotifications(ctx, kind, payload, errors.New("daemon unavailable")); err != nil {
			t.Fatal(err)
		}
	}
	rows, err := db.Pool.Query(ctx, `SELECT event_type,resource_type,payload->>'operation' FROM notification_deliveries WHERE endpoint_id=$1 ORDER BY event_type`, endpointID)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	want := map[string]string{"network.provision.failed": "network.create", "network.delete.failed": "network.delete"}
	seen := map[string]string{}
	for rows.Next() {
		var eventType, resourceType, operation string
		if err = rows.Scan(&eventType, &resourceType, &operation); err != nil {
			t.Fatal(err)
		}
		if resourceType != "managed_network" {
			t.Fatalf("resource type=%q", resourceType)
		}
		seen[eventType] = operation
	}
	if err = rows.Err(); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(seen, want) {
		t.Fatalf("network failure events=%#v want=%#v", seen, want)
	}
}

func TestDeletionFinalizerFailuresUseDedicatedTenantEvent(t *testing.T) {
	databaseURL := os.Getenv("DOCKYARD_TEST_DATABASE_URL")
	if databaseURL == "" {
		t.Skip("DOCKYARD_TEST_DATABASE_URL is not set")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	db, err := Open(ctx, databaseURL)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(db.Pool.Close)
	organizationID, projectID, environmentID := uuid.New(), uuid.New(), uuid.New()
	serviceID, databaseID, clusterID, endpointID := uuid.New(), uuid.New(), uuid.New(), uuid.New()
	for _, statement := range []struct {
		query string
		args  []any
	}{
		{`INSERT INTO organizations(id,name,slug) VALUES($1,'Finalizer notifications',$2)`, []any{organizationID, "finalizer-notifications-" + organizationID.String()}},
		{`INSERT INTO projects(id,organization_id,name,slug,deletion_requested_at) VALUES($1,$2,'Project','project',now())`, []any{projectID, organizationID}},
		{`INSERT INTO environments(id,project_id,name,slug,deletion_requested_at) VALUES($1,$2,'Production','production',now())`, []any{environmentID, projectID}},
		{`INSERT INTO compose_services(id,environment_id,name,slug,stack_name,compose_yaml,deletion_requested_at) VALUES($1,$2,'App','app',$3,'services: {}',now())`, []any{serviceID, environmentID, "finalizer-" + serviceID.String()}},
		{`INSERT INTO database_instances(id,environment_id,name,slug,engine,version,management_kind,connection_service_name,encrypted_credentials,compose_service_id,deletion_requested_at) VALUES($1,$2,'Linked DB','linked-db','postgres','17','compose','postgres','encrypted',$3,now())`, []any{databaseID, environmentID, serviceID}},
		{`INSERT INTO clusters(id,organization_id,name,slug,state,deletion_requested_at) VALUES($1,$2,'Retired cluster','retired','disabled',now())`, []any{clusterID, organizationID}},
		{`INSERT INTO notification_endpoints(id,organization_id,name,kind,encrypted_url,encrypted_secret,events) VALUES($1,$2,'Finalizer on-call','webhook','url','secret',ARRAY['resource.delete.failed'])`, []any{endpointID, organizationID}},
	} {
		if _, err = db.Pool.Exec(ctx, statement.query, statement.args...); err != nil {
			t.Fatal(err)
		}
	}
	t.Cleanup(func() {
		_, _ = db.Pool.Exec(context.Background(), `DELETE FROM organizations WHERE id=$1`, organizationID)
	})
	tests := []struct {
		kind         string
		payloadKey   string
		resourceID   uuid.UUID
		resourceType string
	}{
		{kind: "delete.compose", payloadKey: "serviceId", resourceID: serviceID, resourceType: "compose_service"},
		{kind: "delete.database-link", payloadKey: "databaseId", resourceID: databaseID, resourceType: "database"},
		{kind: "delete.environment", payloadKey: "environmentId", resourceID: environmentID, resourceType: "environment"},
		{kind: "delete.project", payloadKey: "projectId", resourceID: projectID, resourceType: "project"},
		{kind: "delete.cluster", payloadKey: "clusterId", resourceID: clusterID, resourceType: "cluster"},
	}
	for _, test := range tests {
		payload, _ := json.Marshal(map[string]string{test.payloadKey: test.resourceID.String()})
		for range 2 {
			if err = db.QueueFailureNotifications(ctx, test.kind, payload, errors.New("finalizer failed")); err != nil {
				t.Fatalf("%s notification: %v", test.kind, err)
			}
		}
	}
	rows, err := db.Pool.Query(ctx, `SELECT resource_id,resource_type,payload->>'operation' FROM notification_deliveries WHERE endpoint_id=$1 AND event_type='resource.delete.failed'`, endpointID)
	if err != nil {
		t.Fatal(err)
	}
	seen := map[uuid.UUID]string{}
	for rows.Next() {
		var resourceID uuid.UUID
		var resourceType, operation string
		if err = rows.Scan(&resourceID, &resourceType, &operation); err != nil {
			rows.Close()
			t.Fatal(err)
		}
		seen[resourceID] = resourceType + ":" + operation
	}
	if err = rows.Err(); err != nil {
		rows.Close()
		t.Fatal(err)
	}
	rows.Close()
	for _, test := range tests {
		if got, want := seen[test.resourceID], test.resourceType+":"+test.kind; got != want {
			t.Fatalf("%s failure mapping=%q, want %q", test.kind, got, want)
		}
	}
	var deliveries, jobs int
	if err = db.Pool.QueryRow(ctx, `SELECT count(*),(SELECT count(*) FROM jobs WHERE kind='notify.webhook' AND payload->>'deliveryId' IN (SELECT id::text FROM notification_deliveries WHERE endpoint_id=$1)) FROM notification_deliveries WHERE endpoint_id=$1`, endpointID).Scan(&deliveries, &jobs); err != nil || deliveries != len(tests) || jobs != len(tests) {
		t.Fatalf("finalizer deliveries=%d jobs=%d err=%v", deliveries, jobs, err)
	}
}

func TestCommitStatusFailuresUseDeploymentTenantEvent(t *testing.T) {
	pool, ctx := migrationTestPool(t)
	if err := Migrate(ctx, pool); err != nil {
		t.Fatal(err)
	}
	db := &Store{Pool: pool}
	organizationID, otherOrganizationID := uuid.New(), uuid.New()
	projectID, environmentID, serviceID, deploymentID := uuid.New(), uuid.New(), uuid.New(), uuid.New()
	deliveryID, endpointID, otherEndpointID := uuid.New(), uuid.New(), uuid.New()
	for _, statement := range []struct {
		query string
		args  []any
	}{
		{`INSERT INTO organizations(id,name,slug) VALUES($1,'Commit status',$2),($3,'Other',$4)`, []any{organizationID, "commit-status-" + organizationID.String(), otherOrganizationID, "other-commit-status-" + otherOrganizationID.String()}},
		{`INSERT INTO projects(id,organization_id,name,slug) VALUES($1,$2,'Project','project')`, []any{projectID, organizationID}},
		{`INSERT INTO environments(id,project_id,name,slug) VALUES($1,$2,'Production','production')`, []any{environmentID, projectID}},
		{`INSERT INTO compose_services(id,environment_id,name,slug,stack_name,compose_yaml) VALUES($1,$2,'App','app',$3,'services: {}')`, []any{serviceID, environmentID, "commit-status-" + serviceID.String()}},
		{`INSERT INTO deployments(id,compose_service_id,revision,compose_snapshot,status,trigger) VALUES($1,$2,1,'services: {}','succeeded','manual')`, []any{deploymentID, serviceID}},
		{`INSERT INTO commit_status_deliveries(id,deployment_id,state,status,last_error) VALUES($1,$2,'success','failed','provider unavailable')`, []any{deliveryID, deploymentID}},
		{`INSERT INTO notification_endpoints(id,organization_id,name,kind,encrypted_url,encrypted_secret,events) VALUES($1,$2,'Status on-call','webhook','url','secret',ARRAY['commit.status.failed']),($3,$4,'Other status on-call','webhook','url','secret',ARRAY['commit.status.failed'])`, []any{endpointID, organizationID, otherEndpointID, otherOrganizationID}},
	} {
		if _, err := pool.Exec(ctx, statement.query, statement.args...); err != nil {
			t.Fatal(err)
		}
	}
	payload, _ := json.Marshal(map[string]string{"deliveryId": deliveryID.String()})
	for range 2 {
		if err := db.QueueFailureNotifications(ctx, "commit.status", payload, errors.New("provider unavailable")); err != nil {
			t.Fatal(err)
		}
	}
	var eventType, resourceType, resourceID, operation string
	if err := pool.QueryRow(ctx, `SELECT event_type,resource_type,resource_id,payload->>'operation' FROM notification_deliveries WHERE endpoint_id=$1`, endpointID).Scan(&eventType, &resourceType, &resourceID, &operation); err != nil {
		t.Fatal(err)
	}
	if eventType != "commit.status.failed" || resourceType != "commit_status_delivery" || resourceID != deliveryID.String() || operation != "commit.status" {
		t.Fatalf("event=%q resource_type=%q resource_id=%q operation=%q", eventType, resourceType, resourceID, operation)
	}
	var targetDeliveries, otherDeliveries int
	if err := pool.QueryRow(ctx, `SELECT count(*) FILTER (WHERE endpoint_id=$1),count(*) FILTER (WHERE endpoint_id=$2) FROM notification_deliveries`, endpointID, otherEndpointID).Scan(&targetDeliveries, &otherDeliveries); err != nil {
		t.Fatal(err)
	}
	if targetDeliveries != 1 || otherDeliveries != 0 {
		t.Fatalf("target deliveries=%d other deliveries=%d", targetDeliveries, otherDeliveries)
	}
}

func TestEdgeCertificateFailureNotificationsFanOutToAffectedTenants(t *testing.T) {
	pool, ctx := migrationTestPool(t)
	if err := Migrate(ctx, pool); err != nil {
		t.Fatal(err)
	}
	db := &Store{Pool: pool}
	organizationIDs := []uuid.UUID{uuid.New(), uuid.New(), uuid.New()}
	endpointIDs := []uuid.UUID{uuid.New(), uuid.New(), uuid.New()}
	var routeIDs []uuid.UUID
	for index, organizationID := range organizationIDs {
		projectID, environmentID, serviceID := uuid.New(), uuid.New(), uuid.New()
		for _, statement := range []struct {
			query string
			args  []any
		}{
			{`INSERT INTO organizations(id,name,slug) VALUES($1,$2,$3)`, []any{organizationID, "Edge tenant " + strconv.Itoa(index), "edge-tenant-" + organizationID.String()}},
			{`INSERT INTO projects(id,organization_id,name,slug) VALUES($1,$2,'Project','project')`, []any{projectID, organizationID}},
			{`INSERT INTO environments(id,project_id,name,slug) VALUES($1,$2,'Production','production')`, []any{environmentID, projectID}},
			{`INSERT INTO compose_services(id,environment_id,name,slug,stack_name,compose_yaml) VALUES($1,$2,'Web','web',$3,'services: {}')`, []any{serviceID, environmentID, "edge-notify-" + serviceID.String()}},
			{`INSERT INTO notification_endpoints(id,organization_id,name,kind,encrypted_url,encrypted_secret,events) VALUES($1,$2,'Edge on-call','webhook','url','secret',ARRAY['edge.certificate.reconcile.failed'])`, []any{endpointIDs[index], organizationID}},
		} {
			if _, err := pool.Exec(ctx, statement.query, statement.args...); err != nil {
				t.Fatal(err)
			}
		}
		if index == len(organizationIDs)-1 {
			continue
		}
		certificateID := uuid.New()
		if _, err := pool.Exec(ctx, `INSERT INTO custom_tls_certificates(id,organization_id,name,encrypted_certificate,encrypted_private_key,fingerprint,dns_names,not_before,not_after) VALUES($1,$2,$3,'encrypted-certificate','encrypted-private-key',$4,$5,now()-interval '1 day',now()+interval '30 days')`, certificateID, organizationID, "Certificate "+strconv.Itoa(index), "sha256:"+strings.Repeat(strconv.Itoa(index+1), 64), []string{"app-" + strconv.Itoa(index) + ".example.test"}); err != nil {
			t.Fatal(err)
		}
		route, err := db.AddRoute(ctx, organizationID, Route{ComposeServiceID: serviceID, ServiceName: "web", Host: "app-" + strconv.Itoa(index) + ".example.test", PathPrefix: "/", InternalPath: "/", TargetPort: 80, TLS: true, CustomCertificateID: &certificateID})
		if err != nil {
			t.Fatal(err)
		}
		routeIDs = append(routeIDs, route.ID)
	}
	for index, routeID := range routeIDs {
		if err := db.DeleteRoute(ctx, organizationIDs[index], routeID); err != nil {
			t.Fatal(err)
		}
	}
	var jobPayload []byte
	if err := pool.QueryRow(ctx, `SELECT payload FROM jobs WHERE kind='edge-certificates.reconcile' AND status='pending'`).Scan(&jobPayload); err != nil {
		t.Fatal(err)
	}
	for range 2 {
		if err := db.QueueFailureNotifications(ctx, "edge-certificates.reconcile", jobPayload, errors.New("edge provider unavailable")); err != nil {
			t.Fatal(err)
		}
	}
	var generation int64
	if err := pool.QueryRow(ctx, `SELECT generation FROM edge_certificate_targets WHERE target_key='local'`).Scan(&generation); err != nil {
		t.Fatal(err)
	}
	for index, endpointID := range endpointIDs {
		var deliveries int
		if err := pool.QueryRow(ctx, `SELECT count(*) FROM notification_deliveries WHERE endpoint_id=$1 AND event_type='edge.certificate.reconcile.failed' AND resource_type='edge_certificate_target' AND resource_id=$2`, endpointID, "local:"+strconv.FormatInt(generation, 10)).Scan(&deliveries); err != nil {
			t.Fatal(err)
		}
		want := 1
		if index == len(endpointIDs)-1 {
			want = 0
		}
		if deliveries != want {
			t.Fatalf("tenant %d deliveries=%d want=%d", index, deliveries, want)
		}
	}
	if _, err := pool.Exec(ctx, `DELETE FROM jobs WHERE kind='edge-certificates.reconcile'`); err != nil {
		t.Fatal(err)
	}
	queued, err := db.QueueAllEdgeCertificateReconciliations(ctx)
	if err != nil || queued != 1 {
		t.Fatalf("periodic edge reconciliation queued=%d err=%v", queued, err)
	}
	var affectedOrganizations int
	if err = pool.QueryRow(ctx, `SELECT cardinality(affected_organization_ids) FROM edge_certificate_targets WHERE target_key='local'`).Scan(&affectedOrganizations); err != nil || affectedOrganizations != 2 {
		t.Fatalf("retained affected organizations=%d err=%v", affectedOrganizations, err)
	}
}

func TestFailedAIAuditsQueueTenantNotifications(t *testing.T) {
	databaseURL := os.Getenv("DOCKYARD_TEST_DATABASE_URL")
	if databaseURL == "" {
		t.Skip("DOCKYARD_TEST_DATABASE_URL is not set")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	db, err := Open(ctx, databaseURL)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(db.Pool.Close)
	organizationID, accountID, endpointID, ownerID := uuid.New(), uuid.New(), uuid.New(), uuid.New()
	for _, statement := range []struct {
		query string
		args  []any
	}{
		{`INSERT INTO organizations(id,name,slug) VALUES($1,'AI notifications',$2)`, []any{organizationID, "ai-notifications-" + organizationID.String()}},
		{`INSERT INTO users(id,email,password_hash) VALUES($1,$2,'!test')`, []any{ownerID, ownerID.String() + "@example.test"}},
		{`INSERT INTO service_accounts(id,organization_id,name,role) VALUES($1,$2,'auditor','auditor')`, []any{accountID, organizationID}},
		{`INSERT INTO notification_endpoints(id,organization_id,name,kind,encrypted_url,encrypted_secret,events) VALUES($1,$2,'ai-on-call','webhook','url','secret',ARRAY['ai.audit.failed','ai.finding.critical'])`, []any{endpointID, organizationID}},
	} {
		if _, err = db.Pool.Exec(ctx, statement.query, statement.args...); err != nil {
			t.Fatal(err)
		}
	}
	t.Cleanup(func() {
		_, _ = db.Pool.Exec(context.Background(), `DELETE FROM organizations WHERE id=$1`, organizationID)
		_, _ = db.Pool.Exec(context.Background(), `DELETE FROM users WHERE id=$1`, ownerID)
	})

	failedRun, err := db.CreateAIAuditRun(ctx, organizationID, accountID, "security", "v1", "test", json.RawMessage(`{}`))
	if err != nil {
		t.Fatal(err)
	}
	if err = db.FinishAIAuditRun(ctx, organizationID, accountID, failedRun.ID, "failed", "model unavailable"); err != nil {
		t.Fatal(err)
	}
	completedRun, err := db.CreateAIAuditRun(ctx, organizationID, accountID, "security", "v1", "test", json.RawMessage(`{}`))
	if err != nil {
		t.Fatal(err)
	}
	if err = db.FinishAIAuditRun(ctx, organizationID, accountID, completedRun.ID, "completed", "healthy"); err != nil {
		t.Fatal(err)
	}
	orphanedRun, err := db.CreateAIAuditRun(ctx, organizationID, accountID, "reliability", "v1", "test", json.RawMessage(`{}`))
	if err != nil {
		t.Fatal(err)
	}
	if _, err = db.Pool.Exec(ctx, `UPDATE ai_audit_runs SET lease_expires_at=now()-interval '1 second' WHERE id=$1`, orphanedRun.ID); err != nil {
		t.Fatal(err)
	}
	replacementRun, err := db.CreateAIAuditRun(ctx, organizationID, accountID, "reliability", "v2", "test", json.RawMessage(`{}`))
	if err != nil {
		t.Fatal(err)
	}
	if err = db.FinishAIAuditRun(ctx, organizationID, accountID, replacementRun.ID, "completed", "healthy"); err != nil {
		t.Fatal(err)
	}
	criticalRun, err := db.CreateAIAuditRun(ctx, organizationID, accountID, "security-findings", "v1", "test", json.RawMessage(`{}`))
	if err != nil {
		t.Fatal(err)
	}
	criticalFinding, err := db.AddAIAuditFinding(ctx, organizationID, accountID, AIAuditFinding{RunID: criticalRun.ID, Severity: "critical", Category: "security", Title: "Exposed control plane", Description: "The control plane is exposed", Evidence: json.RawMessage(`{}`), Fingerprint: "security:exposed"})
	if err != nil {
		t.Fatal(err)
	}
	if repeated, repeatErr := db.AddAIAuditFinding(ctx, organizationID, accountID, AIAuditFinding{RunID: criticalRun.ID, Severity: "critical", Category: "security", Title: "Exposed control plane", Description: "Still exposed", Evidence: json.RawMessage(`{}`), Fingerprint: "security:exposed"}); repeatErr != nil || repeated.ID != criticalFinding.ID {
		t.Fatalf("repeated critical finding=%#v err=%v", repeated, repeatErr)
	}
	escalatedFinding, err := db.AddAIAuditFinding(ctx, organizationID, accountID, AIAuditFinding{RunID: criticalRun.ID, Severity: "high", Category: "security", Title: "Weak policy", Description: "Policy needs review", Evidence: json.RawMessage(`{}`), Fingerprint: "security:policy"})
	if err != nil {
		t.Fatal(err)
	}
	escalatedFinding, err = db.AddAIAuditFinding(ctx, organizationID, accountID, AIAuditFinding{RunID: criticalRun.ID, Severity: "critical", Category: "security", Title: "Weak policy", Description: "Policy is now critical", Evidence: json.RawMessage(`{}`), Fingerprint: "security:policy"})
	if err != nil {
		t.Fatal(err)
	}
	if err = db.FinishAIAuditRun(ctx, organizationID, accountID, criticalRun.ID, "completed", "critical finding"); err != nil {
		t.Fatal(err)
	}
	recurrenceRun, err := db.CreateAIAuditRun(ctx, organizationID, accountID, "security-findings", "v2", "test", json.RawMessage(`{}`))
	if err != nil {
		t.Fatal(err)
	}
	recurrence, err := db.AddAIAuditFinding(ctx, organizationID, accountID, AIAuditFinding{RunID: recurrenceRun.ID, Severity: "critical", Category: "security", Title: "Exposed control plane", Description: "Still exposed in the next run", Evidence: json.RawMessage(`{}`), Fingerprint: "security:exposed"})
	if err != nil {
		t.Fatal(err)
	}
	if err = db.FinishAIAuditRun(ctx, organizationID, accountID, recurrenceRun.ID, "completed", "unchanged critical finding"); err != nil {
		t.Fatal(err)
	}
	if _, err = db.UpdateAIAuditFindingDisposition(ctx, Principal{UserID: ownerID, OrganizationID: organizationID, Role: "owner"}, recurrence.ID, "resolved", "fixed", "127.0.0.1"); err != nil {
		t.Fatal(err)
	}
	reopenedRun, err := db.CreateAIAuditRun(ctx, organizationID, accountID, "security-findings", "v3", "test", json.RawMessage(`{}`))
	if err != nil {
		t.Fatal(err)
	}
	reopenedFinding, err := db.AddAIAuditFinding(ctx, organizationID, accountID, AIAuditFinding{RunID: reopenedRun.ID, Severity: "critical", Category: "security", Title: "Exposed control plane", Description: "The resolved condition returned", Evidence: json.RawMessage(`{}`), Fingerprint: "security:exposed"})
	if err != nil {
		t.Fatal(err)
	}
	if err = db.FinishAIAuditRun(ctx, organizationID, accountID, reopenedRun.ID, "completed", "reopened critical finding"); err != nil {
		t.Fatal(err)
	}

	rows, err := db.Pool.Query(ctx, `SELECT event_type,resource_type,resource_id,payload FROM notification_deliveries WHERE endpoint_id=$1 ORDER BY created_at,id`, endpointID)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	deliveries := map[string]json.RawMessage{}
	for rows.Next() {
		var eventType, resourceType, resourceID string
		var payload json.RawMessage
		if err = rows.Scan(&eventType, &resourceType, &resourceID, &payload); err != nil {
			t.Fatal(err)
		}
		if (eventType != "ai.audit.failed" && eventType != "ai.finding.critical") || (eventType == "ai.audit.failed" && resourceType != "ai_audit_run") || (eventType == "ai.finding.critical" && resourceType != "ai_audit_finding") {
			t.Fatalf("unexpected delivery event=%q resource=%q", eventType, resourceType)
		}
		deliveries[eventType+":"+resourceID] = payload
	}
	if err = rows.Err(); err != nil {
		t.Fatal(err)
	}
	if len(deliveries) != 5 || deliveries["ai.audit.failed:"+failedRun.ID.String()] == nil || deliveries["ai.audit.failed:"+orphanedRun.ID.String()] == nil || deliveries["ai.audit.failed:"+completedRun.ID.String()] != nil || deliveries["ai.finding.critical:"+criticalFinding.ID.String()] == nil || deliveries["ai.finding.critical:"+escalatedFinding.ID.String()] == nil || deliveries["ai.finding.critical:"+reopenedFinding.ID.String()] == nil {
		t.Fatalf("AI audit deliveries=%v", deliveries)
	}
	var failedPayload map[string]any
	if err = json.Unmarshal(deliveries["ai.audit.failed:"+failedRun.ID.String()], &failedPayload); err != nil || failedPayload["agentName"] != "security" || failedPayload["error"] != "model unavailable" {
		t.Fatalf("failed audit payload=%v err=%v", failedPayload, err)
	}
	var criticalPayload map[string]any
	if err = json.Unmarshal(deliveries["ai.finding.critical:"+criticalFinding.ID.String()], &criticalPayload); err != nil || criticalPayload["agentName"] != "security-findings" || criticalPayload["title"] != "Exposed control plane" {
		t.Fatalf("critical finding payload=%v err=%v", criticalPayload, err)
	}
	var jobs int
	if err = db.Pool.QueryRow(ctx, `SELECT count(*) FROM jobs WHERE kind='notify.webhook' AND payload->>'deliveryId' IN (SELECT id::text FROM notification_deliveries WHERE endpoint_id=$1)`, endpointID).Scan(&jobs); err != nil || jobs != 5 {
		t.Fatalf("notification jobs=%d err=%v", jobs, err)
	}
}
