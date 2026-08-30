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
