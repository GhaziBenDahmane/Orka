package store

import (
	"context"
	"encoding/json"
	"errors"
	"os"
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
	organizationID, accountID, endpointID := uuid.New(), uuid.New(), uuid.New()
	for _, statement := range []struct {
		query string
		args  []any
	}{
		{`INSERT INTO organizations(id,name,slug) VALUES($1,'AI notifications',$2)`, []any{organizationID, "ai-notifications-" + organizationID.String()}},
		{`INSERT INTO service_accounts(id,organization_id,name,role) VALUES($1,$2,'auditor','auditor')`, []any{accountID, organizationID}},
		{`INSERT INTO notification_endpoints(id,organization_id,name,kind,encrypted_url,encrypted_secret,events) VALUES($1,$2,'ai-on-call','webhook','url','secret',ARRAY['ai.audit.failed'])`, []any{endpointID, organizationID}},
	} {
		if _, err = db.Pool.Exec(ctx, statement.query, statement.args...); err != nil {
			t.Fatal(err)
		}
	}
	t.Cleanup(func() {
		_, _ = db.Pool.Exec(context.Background(), `DELETE FROM organizations WHERE id=$1`, organizationID)
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
	replacementRun, err := db.CreateAIAuditRun(ctx, organizationID, accountID, "reliability", "v2", "test", json.RawMessage(`{}`))
	if err != nil {
		t.Fatal(err)
	}
	if err = db.FinishAIAuditRun(ctx, organizationID, accountID, replacementRun.ID, "completed", "healthy"); err != nil {
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
		if eventType != "ai.audit.failed" || resourceType != "ai_audit_run" {
			t.Fatalf("unexpected delivery event=%q resource=%q", eventType, resourceType)
		}
		deliveries[resourceID] = payload
	}
	if err = rows.Err(); err != nil {
		t.Fatal(err)
	}
	if len(deliveries) != 2 || deliveries[failedRun.ID.String()] == nil || deliveries[orphanedRun.ID.String()] == nil || deliveries[completedRun.ID.String()] != nil {
		t.Fatalf("AI audit deliveries=%v", deliveries)
	}
	var failedPayload map[string]any
	if err = json.Unmarshal(deliveries[failedRun.ID.String()], &failedPayload); err != nil || failedPayload["agentName"] != "security" || failedPayload["error"] != "model unavailable" {
		t.Fatalf("failed audit payload=%v err=%v", failedPayload, err)
	}
	var jobs int
	if err = db.Pool.QueryRow(ctx, `SELECT count(*) FROM jobs WHERE kind='notify.webhook' AND payload->>'deliveryId' IN (SELECT id::text FROM notification_deliveries WHERE endpoint_id=$1)`, endpointID).Scan(&jobs); err != nil || jobs != 2 {
		t.Fatalf("notification jobs=%d err=%v", jobs, err)
	}
}
