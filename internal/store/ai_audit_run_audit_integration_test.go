package store

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

func TestAIAuditRunLifecycleCommitsWithServiceAccountAudit(t *testing.T) {
	pool, ctx := migrationTestPool(t)
	if err := Migrate(ctx, pool); err != nil {
		t.Fatal(err)
	}
	db := &Store{Pool: pool}
	organizationID, userID := uuid.New(), uuid.New()
	if _, err := pool.Exec(ctx, `INSERT INTO organizations(id,name,slug) VALUES($1,'AI audit lifecycle',$2)`, organizationID, "ai-audit-lifecycle-"+organizationID.String()); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO users(id,email,password_hash) VALUES($1,$2,'!test')`, userID, userID.String()+"@example.test"); err != nil {
		t.Fatal(err)
	}
	account, err := db.CreateServiceAccount(ctx, organizationID, userID, "platform-auditor", "auditor", []byte("ai-audit-lifecycle-token"), time.Now().Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if _, err = db.CreateNotificationEndpoint(ctx, NotificationEndpoint{
		ID: uuid.New(), OrganizationID: organizationID, Name: "AI failures", Kind: "webhook",
		EncryptedURL: "encrypted-url", EncryptedSecret: "encrypted-secret",
		Events: []string{"ai.audit.failed"}, Enabled: true,
	}); err != nil {
		t.Fatal(err)
	}
	principal := Principal{OrganizationID: organizationID, ServiceAccountID: &account.ID, Role: "auditor"}
	invalidPrincipal := principal
	invalidPrincipal.UserID = uuid.New()
	scope := json.RawMessage(`{"kind":"platform"}`)

	if _, err = db.CreateAIAuditRunWithAudit(ctx, invalidPrincipal, "security", "v0", "test", scope, "127.0.0.1:1234"); err == nil {
		t.Fatal("AI audit run creation succeeded without valid audit evidence")
	}
	var runCount int
	if err = pool.QueryRow(ctx, `SELECT count(*) FROM ai_audit_runs WHERE organization_id=$1`, organizationID).Scan(&runCount); err != nil || runCount != 0 {
		t.Fatalf("failed evidence retained AI audit run: count=%d err=%v", runCount, err)
	}

	run, err := db.CreateAIAuditRunWithAudit(ctx, principal, "security", "v1", "test", scope, "127.0.0.1:1234")
	if err != nil {
		t.Fatal(err)
	}
	if _, err = db.CreateAIAuditRunWithAudit(ctx, invalidPrincipal, "security", "v2", "test", scope, "127.0.0.1:1234"); err == nil {
		t.Fatal("AI audit run supersession succeeded without valid audit evidence")
	}
	assertAIAuditRunState(t, pool, ctx, run.ID, "running", "", false)
	assertAIAuditNotificationCounts(t, pool, ctx, organizationID, 0, 0)

	if err = db.FinishAIAuditRunWithAudit(ctx, invalidPrincipal, run.ID, "failed", "scanner unavailable", "127.0.0.1:1234"); err == nil {
		t.Fatal("AI audit run failure succeeded without valid audit evidence")
	}
	assertAIAuditRunState(t, pool, ctx, run.ID, "running", "", false)
	assertAIAuditNotificationCounts(t, pool, ctx, organizationID, 0, 0)

	if err = db.FinishAIAuditRunWithAudit(ctx, principal, run.ID, "failed", "scanner unavailable", "127.0.0.1:1234"); err != nil {
		t.Fatal(err)
	}
	assertAIAuditRunState(t, pool, ctx, run.ID, "failed", "scanner unavailable", true)
	assertAIAuditNotificationCounts(t, pool, ctx, organizationID, 1, 1)

	completed, err := db.CreateAIAuditRunWithAudit(ctx, principal, "compliance", "v1", "test", scope, "127.0.0.1:1234")
	if err != nil {
		t.Fatal(err)
	}
	if err = db.FinishAIAuditRunWithAudit(ctx, principal, completed.ID, "completed", "no findings", "127.0.0.1:1234"); err != nil {
		t.Fatal(err)
	}
	assertAIAuditRunState(t, pool, ctx, completed.ID, "completed", "no findings", true)

	var starts, failures, completions int
	if err = pool.QueryRow(ctx, `SELECT
		count(*) FILTER (WHERE action='ai_audit.start'),
		count(*) FILTER (WHERE action='ai_audit.failed'),
		count(*) FILTER (WHERE action='ai_audit.completed')
		FROM audit_events
		WHERE organization_id=$1 AND actor_service_account_id=$2 AND actor_user_id IS NULL`, organizationID, account.ID).Scan(&starts, &failures, &completions); err != nil {
		t.Fatal(err)
	}
	if starts != 2 || failures != 1 || completions != 1 {
		t.Fatalf("AI audit evidence counts: starts=%d failures=%d completions=%d", starts, failures, completions)
	}
}

func assertAIAuditRunState(t *testing.T, pool *pgxpool.Pool, ctx context.Context, runID uuid.UUID, wantStatus, wantSummary string, wantCompleted bool) {
	t.Helper()
	var status, summary string
	var completedAt *time.Time
	if err := pool.QueryRow(ctx, `SELECT status,summary,completed_at FROM ai_audit_runs WHERE id=$1`, runID).Scan(&status, &summary, &completedAt); err != nil {
		t.Fatal(err)
	}
	if status != wantStatus || summary != wantSummary || (completedAt != nil) != wantCompleted {
		t.Fatalf("AI audit run state: status=%q summary=%q completed=%v", status, summary, completedAt)
	}
}

func assertAIAuditNotificationCounts(t *testing.T, pool *pgxpool.Pool, ctx context.Context, organizationID uuid.UUID, wantDeliveries, wantJobs int) {
	t.Helper()
	var deliveries, jobs int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM notification_deliveries d JOIN notification_endpoints e ON e.id=d.endpoint_id WHERE e.organization_id=$1 AND d.event_type='ai.audit.failed'`, organizationID).Scan(&deliveries); err != nil {
		t.Fatal(err)
	}
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM jobs WHERE kind='notify.webhook' AND payload->>'deliveryId' IN (SELECT d.id::text FROM notification_deliveries d JOIN notification_endpoints e ON e.id=d.endpoint_id WHERE e.organization_id=$1)`, organizationID).Scan(&jobs); err != nil {
		t.Fatal(err)
	}
	if deliveries != wantDeliveries || jobs != wantJobs {
		t.Fatalf("AI audit notifications: deliveries=%d jobs=%d", deliveries, jobs)
	}
}
