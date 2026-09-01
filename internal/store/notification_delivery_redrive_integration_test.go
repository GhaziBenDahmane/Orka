package store

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"sync"
	"testing"

	"github.com/google/uuid"
)

func TestNotificationDeliveryHistoryAndAuditedRedrive(t *testing.T) {
	pool, ctx := migrationTestPool(t)
	if err := Migrate(ctx, pool); err != nil {
		t.Fatal(err)
	}
	db := &Store{Pool: pool}
	organizationID, otherOrganizationID, userID := uuid.New(), uuid.New(), uuid.New()
	for _, organization := range []struct {
		id   uuid.UUID
		name string
	}{
		{organizationID, "Notification redrive"},
		{otherOrganizationID, "Other notification redrive"},
	} {
		if _, err := pool.Exec(ctx, `INSERT INTO organizations(id,name,slug) VALUES($1,$2,$3)`, organization.id, organization.name, strings.ToLower(strings.ReplaceAll(organization.name, " ", "-"))+"-"+organization.id.String()); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := pool.Exec(ctx, `INSERT INTO users(id,email,password_hash) VALUES($1,$2,'!test')`, userID, userID.String()+"@example.test"); err != nil {
		t.Fatal(err)
	}
	principal := Principal{OrganizationID: organizationID, UserID: userID}
	endpointID, disabledEndpointID, otherEndpointID := uuid.New(), uuid.New(), uuid.New()
	for _, endpoint := range []struct {
		id      uuid.UUID
		orgID   uuid.UUID
		name    string
		enabled bool
	}{
		{endpointID, organizationID, "Primary", true},
		{disabledEndpointID, organizationID, "Disabled", false},
		{otherEndpointID, otherOrganizationID, "Foreign", true},
	} {
		if _, err := pool.Exec(ctx, `INSERT INTO notification_endpoints(id,organization_id,name,kind,encrypted_url,encrypted_secret,events,enabled) VALUES($1,$2,$3,'webhook','current-url','current-secret',ARRAY['deployment.failed'],$4)`, endpoint.id, endpoint.orgID, endpoint.name, endpoint.enabled); err != nil {
			t.Fatal(err)
		}
	}
	failedID, rollbackID, activeID, succeededID, disabledID, foreignID := uuid.New(), uuid.New(), uuid.New(), uuid.New(), uuid.New(), uuid.New()
	for _, delivery := range []struct {
		id         uuid.UUID
		endpointID uuid.UUID
		status     string
	}{
		{failedID, endpointID, "failed"},
		{rollbackID, endpointID, "failed"},
		{activeID, endpointID, "failed"},
		{succeededID, endpointID, "succeeded"},
		{disabledID, disabledEndpointID, "failed"},
		{foreignID, otherEndpointID, "failed"},
	} {
		if _, err := pool.Exec(ctx, `INSERT INTO notification_deliveries(id,endpoint_id,event_type,resource_type,resource_id,payload,status,last_error,finished_at) VALUES($1,$2,'deployment.failed','deployment',$3,'{"secret":"must-not-leak"}',$4,'provider failed',now())`, delivery.id, delivery.endpointID, delivery.id.String(), delivery.status); err != nil {
			t.Fatal(err)
		}
	}
	failedJobID := uuid.New()
	if _, err := pool.Exec(ctx, `INSERT INTO jobs(id,kind,payload,status,attempts,max_attempts,last_error,finished_at) VALUES($1,'notify.webhook',$2,'failed',8,8,'provider failed',now())`, failedJobID, []byte(`{"deliveryId":"`+failedID.String()+`"}`)); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO jobs(id,kind,payload,status,attempts,max_attempts,last_error,run_after) VALUES($1,'notify.webhook',$2,'pending',1,8,'provider failed',now()+interval '1 minute')`, uuid.New(), []byte(`{"deliveryId":"`+activeID.String()+`"}`)); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO jobs(id,kind,payload,status) VALUES($1,'notify.webhook',$2,'pending')`, uuid.New(), []byte(`{"deliveryId":"`+activeID.String()+`"}`)); err == nil {
		t.Fatal("database accepted two active jobs for one notification delivery")
	}

	failed, err := db.ListNotificationDeliveries(ctx, organizationID, NotificationDeliveryFilter{Status: "failed", EventType: "deployment.failed", Limit: 200})
	if err != nil {
		t.Fatal(err)
	}
	if len(failed) != 4 {
		t.Fatalf("tenant failed history count=%d, want 4", len(failed))
	}
	retryable := map[uuid.UUID]bool{}
	inProgress := map[uuid.UUID]bool{}
	for _, item := range failed {
		retryable[item.ID] = item.Retryable
		inProgress[item.ID] = item.InProgress
		encoded, marshalErr := json.Marshal(item)
		if marshalErr != nil || strings.Contains(string(encoded), "must-not-leak") || strings.Contains(string(encoded), "payload") {
			t.Fatalf("delivery history leaked payload: %s err=%v", encoded, marshalErr)
		}
	}
	if !retryable[failedID] || !retryable[rollbackID] || retryable[activeID] || retryable[disabledID] || !inProgress[activeID] {
		t.Fatalf("retry posture retryable=%v inProgress=%v", retryable, inProgress)
	}
	if items, err := db.ListNotificationDeliveries(ctx, otherOrganizationID, NotificationDeliveryFilter{Limit: 200}); err != nil || len(items) != 1 || items[0].ID != foreignID {
		t.Fatalf("foreign tenant history=%v err=%v", items, err)
	}

	if _, err = db.RetryNotificationDeliveryWithAudit(ctx, principal, activeID, "127.0.0.1:1234"); !errors.Is(err, ErrBusy) {
		t.Fatalf("active retry error=%v, want ErrBusy", err)
	}
	if _, err = db.RetryNotificationDeliveryWithAudit(ctx, principal, succeededID, "127.0.0.1:1234"); !errors.Is(err, ErrNotificationDeliveryNotRetryable) {
		t.Fatalf("successful retry error=%v, want ErrNotificationDeliveryNotRetryable", err)
	}
	if _, err = db.RetryNotificationDeliveryWithAudit(ctx, principal, disabledID, "127.0.0.1:1234"); !errors.Is(err, ErrNotificationEndpointDisabled) {
		t.Fatalf("disabled endpoint retry error=%v, want ErrNotificationEndpointDisabled", err)
	}
	if _, err = db.RetryNotificationDeliveryWithAudit(ctx, principal, foreignID, "127.0.0.1:1234"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("cross-tenant retry error=%v, want ErrNotFound", err)
	}

	invalidPrincipal := Principal{OrganizationID: organizationID, UserID: uuid.New()}
	if _, err = db.RetryNotificationDeliveryWithAudit(ctx, invalidPrincipal, rollbackID, "127.0.0.1:1234"); err == nil {
		t.Fatal("redrive succeeded without valid audit evidence")
	}
	var rollbackStatus, rollbackError string
	var rollbackJobs int
	if err = pool.QueryRow(ctx, `SELECT status,last_error,(SELECT count(*) FROM jobs WHERE kind='notify.webhook' AND payload->>'deliveryId'=$1) FROM notification_deliveries WHERE id=$2`, rollbackID.String(), rollbackID).Scan(&rollbackStatus, &rollbackError, &rollbackJobs); err != nil || rollbackStatus != "failed" || rollbackError != "provider failed" || rollbackJobs != 0 {
		t.Fatalf("audit rollback status=%q error=%q jobs=%d err=%v", rollbackStatus, rollbackError, rollbackJobs, err)
	}

	start := make(chan struct{})
	results := make(chan error, 2)
	var wait sync.WaitGroup
	for range 2 {
		wait.Add(1)
		go func() {
			defer wait.Done()
			<-start
			_, retryErr := db.RetryNotificationDeliveryWithAudit(context.Background(), principal, failedID, "127.0.0.1:1234")
			results <- retryErr
		}()
	}
	close(start)
	wait.Wait()
	close(results)
	var successes, busy int
	for result := range results {
		switch {
		case result == nil:
			successes++
		case errors.Is(result, ErrBusy):
			busy++
		default:
			t.Fatalf("concurrent retry error=%v", result)
		}
	}
	if successes != 1 || busy != 1 {
		t.Fatalf("concurrent retry successes=%d busy=%d", successes, busy)
	}
	var status, lastError string
	var responseCode *int
	var startedAt, finishedAt any
	var jobCount, pendingJobs, auditCount int
	if err = pool.QueryRow(ctx, `SELECT status,response_code,last_error,started_at,finished_at FROM notification_deliveries WHERE id=$1`, failedID).Scan(&status, &responseCode, &lastError, &startedAt, &finishedAt); err != nil {
		t.Fatal(err)
	}
	if err = pool.QueryRow(ctx, `SELECT count(*),count(*) FILTER (WHERE status='pending') FROM jobs WHERE kind='notify.webhook' AND payload->>'deliveryId'=$1`, failedID.String()).Scan(&jobCount, &pendingJobs); err != nil {
		t.Fatal(err)
	}
	if err = pool.QueryRow(ctx, `SELECT count(*) FROM audit_events WHERE organization_id=$1 AND actor_user_id=$2 AND action='notification_delivery.retry' AND resource_id=$3`, organizationID, userID, failedID.String()).Scan(&auditCount); err != nil {
		t.Fatal(err)
	}
	if status != "pending" || responseCode != nil || lastError != "" || startedAt != nil || finishedAt != nil || jobCount != 2 || pendingJobs != 1 || auditCount != 1 {
		t.Fatalf("redrive state status=%q response=%v error=%q started=%v finished=%v jobs=%d pending=%d audits=%d", status, responseCode, lastError, startedAt, finishedAt, jobCount, pendingJobs, auditCount)
	}
}
