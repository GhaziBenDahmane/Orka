package store

import (
	"context"
	"testing"

	"github.com/google/uuid"
)

func TestNotificationEndpointLifecycleCommitsWithAudit(t *testing.T) {
	pool, ctx := migrationTestPool(t)
	if err := Migrate(ctx, pool); err != nil {
		t.Fatal(err)
	}
	db := &Store{Pool: pool}
	organizationID, userID, endpointID := uuid.New(), uuid.New(), uuid.New()
	if _, err := pool.Exec(ctx, `INSERT INTO organizations(id,name,slug) VALUES($1,'Notification audit',$2)`, organizationID, "notification-audit-"+organizationID.String()); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO users(id,email,password_hash) VALUES($1,$2,'!test')`, userID, userID.String()+"@example.test"); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `DELETE FROM jobs WHERE kind='notify.webhook' AND payload->>'deliveryId' IN (SELECT d.id::text FROM notification_deliveries d JOIN notification_endpoints e ON e.id=d.endpoint_id WHERE e.organization_id=$1)`, organizationID)
		_, _ = pool.Exec(context.Background(), `DELETE FROM organizations WHERE id=$1`, organizationID)
		_, _ = pool.Exec(context.Background(), `DELETE FROM users WHERE id=$1`, userID)
	})
	invalidPrincipal := Principal{OrganizationID: organizationID, UserID: uuid.New()}
	principal := Principal{OrganizationID: organizationID, UserID: userID}
	input := NotificationEndpoint{ID: endpointID, Name: "On-call", Kind: "webhook", EncryptedURL: "encrypted-url", EncryptedSecret: "encrypted-secret", Events: []string{"deployment.failed"}, Enabled: true}

	if _, err := db.CreateNotificationEndpointWithAudit(ctx, invalidPrincipal, input, "127.0.0.1:1234"); err == nil {
		t.Fatal("notification endpoint creation succeeded without valid audit evidence")
	}
	var endpointCount int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM notification_endpoints WHERE id=$1`, endpointID).Scan(&endpointCount); err != nil || endpointCount != 0 {
		t.Fatalf("failed evidence retained notification endpoint: count=%d err=%v", endpointCount, err)
	}
	endpoint, err := db.CreateNotificationEndpointWithAudit(ctx, principal, input, "127.0.0.1:1234")
	if err != nil {
		t.Fatal(err)
	}
	deliveryID, jobID := uuid.New(), uuid.New()
	if _, err = pool.Exec(ctx, `INSERT INTO notification_deliveries(id,endpoint_id,event_type,resource_type,resource_id,payload) VALUES($1,$2,'deployment.failed','deployment','test','{}')`, deliveryID, endpoint.ID); err != nil {
		t.Fatal(err)
	}
	if _, err = pool.Exec(ctx, `INSERT INTO jobs(id,kind,payload) VALUES($1,'notify.webhook',$2)`, jobID, []byte(`{"deliveryId":"`+deliveryID.String()+`"}`)); err != nil {
		t.Fatal(err)
	}

	if err = db.DeleteNotificationEndpointWithAudit(ctx, invalidPrincipal, endpoint.ID, "127.0.0.1:1234"); err == nil {
		t.Fatal("notification endpoint deletion succeeded without valid audit evidence")
	}
	var enabled bool
	var deliveryStatus, jobStatus string
	if err = pool.QueryRow(ctx, `SELECT enabled FROM notification_endpoints WHERE id=$1`, endpoint.ID).Scan(&enabled); err != nil || !enabled {
		t.Fatalf("failed evidence disabled notification endpoint: enabled=%v err=%v", enabled, err)
	}
	if err = pool.QueryRow(ctx, `SELECT status FROM notification_deliveries WHERE id=$1`, deliveryID).Scan(&deliveryStatus); err != nil || deliveryStatus != "pending" {
		t.Fatalf("failed evidence changed notification delivery: status=%q err=%v", deliveryStatus, err)
	}
	if err = pool.QueryRow(ctx, `SELECT status FROM jobs WHERE id=$1`, jobID).Scan(&jobStatus); err != nil || jobStatus != "pending" {
		t.Fatalf("failed evidence changed notification job: status=%q err=%v", jobStatus, err)
	}

	if err = db.DeleteNotificationEndpointWithAudit(ctx, principal, endpoint.ID, "127.0.0.1:1234"); err != nil {
		t.Fatal(err)
	}
	if err = pool.QueryRow(ctx, `SELECT enabled FROM notification_endpoints WHERE id=$1`, endpoint.ID).Scan(&enabled); err != nil || enabled {
		t.Fatalf("audited notification endpoint disable: enabled=%v err=%v", enabled, err)
	}
	if err = pool.QueryRow(ctx, `SELECT status FROM notification_deliveries WHERE id=$1`, deliveryID).Scan(&deliveryStatus); err != nil || deliveryStatus != "failed" {
		t.Fatalf("notification delivery status=%q err=%v", deliveryStatus, err)
	}
	if err = pool.QueryRow(ctx, `SELECT status FROM jobs WHERE id=$1`, jobID).Scan(&jobStatus); err != nil || jobStatus != "cancelled" {
		t.Fatalf("notification job status=%q err=%v", jobStatus, err)
	}
	var auditCount int
	if err = pool.QueryRow(ctx, `SELECT count(*) FROM audit_events WHERE organization_id=$1 AND actor_user_id=$2 AND resource_id=$3 AND action IN ('notification_endpoint.create','notification_endpoint.delete')`, organizationID, userID, endpoint.ID.String()).Scan(&auditCount); err != nil || auditCount != 2 {
		t.Fatalf("notification endpoint audit count=%d err=%v", auditCount, err)
	}
}
