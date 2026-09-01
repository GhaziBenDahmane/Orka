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

func TestCommitStatusDeliveryHistoryAndAuditedRedrive(t *testing.T) {
	pool, ctx := migrationTestPool(t)
	if err := Migrate(ctx, pool); err != nil {
		t.Fatal(err)
	}
	db := &Store{Pool: pool}
	organizationID, otherOrganizationID, userID := uuid.New(), uuid.New(), uuid.New()
	projectID, otherProjectID := uuid.New(), uuid.New()
	environmentID, otherEnvironmentID := uuid.New(), uuid.New()
	serviceID, otherServiceID := uuid.New(), uuid.New()
	deploymentID, otherDeploymentID := uuid.New(), uuid.New()
	statements := []struct {
		query string
		args  []any
	}{
		{`INSERT INTO organizations(id,name,slug) VALUES($1,'Commit status redrive',$2),($3,'Other commit status redrive',$4)`, []any{organizationID, "commit-redrive-" + organizationID.String(), otherOrganizationID, "other-commit-redrive-" + otherOrganizationID.String()}},
		{`INSERT INTO users(id,email,password_hash) VALUES($1,$2,'!test')`, []any{userID, userID.String() + "@example.test"}},
		{`INSERT INTO projects(id,organization_id,name,slug) VALUES($1,$2,'Project','project'),($3,$4,'Other','other')`, []any{projectID, organizationID, otherProjectID, otherOrganizationID}},
		{`INSERT INTO environments(id,project_id,name,slug) VALUES($1,$2,'Production','production'),($3,$4,'Production','production')`, []any{environmentID, projectID, otherEnvironmentID, otherProjectID}},
		{`INSERT INTO compose_services(id,environment_id,name,slug,stack_name,compose_yaml) VALUES($1,$2,'API','api',$3,'services: {}'),($4,$5,'Other API','other-api',$6,'services: {}')`, []any{serviceID, environmentID, "commit-redrive-" + serviceID.String(), otherServiceID, otherEnvironmentID, "other-commit-redrive-" + otherServiceID.String()}},
		{`INSERT INTO deployments(id,compose_service_id,revision,compose_snapshot,env_snapshot,status,trigger,commit_sha) VALUES($1,$2,1,'services: {}','','failed','manual',$3),($4,$5,1,'services: {}','','failed','manual',$6)`, []any{deploymentID, serviceID, strings.Repeat("a", 40), otherDeploymentID, otherServiceID, strings.Repeat("b", 40)}},
	}
	for _, statement := range statements {
		if _, err := pool.Exec(ctx, statement.query, statement.args...); err != nil {
			t.Fatal(err)
		}
	}
	principal := Principal{OrganizationID: organizationID, UserID: userID}
	failedID, rollbackID, activeID, succeededID, foreignID := uuid.New(), uuid.New(), uuid.New(), uuid.New(), uuid.New()
	for _, delivery := range []struct {
		id           uuid.UUID
		deploymentID uuid.UUID
		status       string
		provider     string
		state        string
	}{
		{failedID, deploymentID, "failed", "github", "failure"},
		{rollbackID, deploymentID, "failed", "github", "pending"},
		{activeID, deploymentID, "failed", "gitlab", "error"},
		{succeededID, deploymentID, "succeeded", "gitea", "success"},
		{foreignID, otherDeploymentID, "failed", "bitbucket", "failure"},
	} {
		_, err := pool.Exec(ctx, `INSERT INTO commit_status_deliveries(id,deployment_id,state,status,response_code,last_error,finished_at,provider,repository_url,status_context,credential_server,credential_username,encrypted_credential)
			VALUES($1,$2,$3,$4,503,'raw provider secret token',$5,$6,'https://git.example.test/private/repository','secret/context','secret-host','secret-user','encrypted-secret')`, delivery.id, delivery.deploymentID, delivery.state, delivery.status, nil, delivery.provider)
		if err != nil {
			t.Fatal(err)
		}
	}
	if _, err := pool.Exec(ctx, `INSERT INTO jobs(id,kind,payload,status,attempts,max_attempts,last_error,finished_at) VALUES($1,'commit.status',$2,'failed',8,8,'raw provider secret token',now())`, uuid.New(), []byte(`{"deliveryId":"`+failedID.String()+`"}`)); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO jobs(id,kind,payload,status,attempts,max_attempts,last_error,run_after) VALUES($1,'commit.status',$2,'pending',1,8,'raw provider secret token',now()+interval '1 minute')`, uuid.New(), []byte(`{"deliveryId":"`+activeID.String()+`"}`)); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO jobs(id,kind,payload,status) VALUES($1,'commit.status',$2,'pending')`, uuid.New(), []byte(`{"deliveryId":"`+activeID.String()+`"}`)); err == nil {
		t.Fatal("database accepted two active jobs for one commit status delivery")
	}

	items, err := db.ListCommitStatusDeliveries(ctx, organizationID, CommitStatusDeliveryFilter{Status: "failed", Limit: 200})
	if err != nil || len(items) != 3 {
		t.Fatalf("tenant history items=%v err=%v", items, err)
	}
	for _, item := range items {
		encoded, marshalErr := json.Marshal(item)
		body := string(encoded)
		if marshalErr != nil || strings.Contains(body, "secret") || strings.Contains(body, "repository") || strings.Contains(body, strings.Repeat("a", 40)) {
			t.Fatalf("commit status history leaked callback material: %s err=%v", body, marshalErr)
		}
	}
	if foreign, listErr := db.ListCommitStatusDeliveries(ctx, otherOrganizationID, CommitStatusDeliveryFilter{Limit: 200}); listErr != nil || len(foreign) != 1 || foreign[0].ID != foreignID {
		t.Fatalf("foreign tenant history=%v err=%v", foreign, listErr)
	}
	snapshot, err := db.BuildAIAuditSnapshot(ctx, organizationID)
	if err != nil || len(snapshot.CommitStatusPosture) != 2 {
		t.Fatalf("AI commit status posture=%#v err=%v", snapshot.CommitStatusPosture, err)
	}
	if encoded, marshalErr := json.Marshal(snapshot.CommitStatusPosture); marshalErr != nil || strings.Contains(string(encoded), "secret") || strings.Contains(string(encoded), "git.example") || strings.Contains(string(encoded), strings.Repeat("a", 40)) {
		t.Fatalf("AI commit status posture leaked callback material: %s err=%v", encoded, marshalErr)
	}
	if _, err = db.RetryCommitStatusDeliveryWithAudit(ctx, principal, activeID, "127.0.0.1:1234"); !errors.Is(err, ErrBusy) {
		t.Fatalf("active retry error=%v, want ErrBusy", err)
	}
	if _, err = db.RetryCommitStatusDeliveryWithAudit(ctx, principal, succeededID, "127.0.0.1:1234"); !errors.Is(err, ErrCommitStatusDeliveryNotRetryable) {
		t.Fatalf("successful retry error=%v, want ErrCommitStatusDeliveryNotRetryable", err)
	}
	if _, err = db.RetryCommitStatusDeliveryWithAudit(ctx, principal, foreignID, "127.0.0.1:1234"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("cross-tenant retry error=%v, want ErrNotFound", err)
	}
	if _, err = db.RetryCommitStatusDeliveryWithAudit(ctx, Principal{OrganizationID: organizationID, UserID: uuid.New()}, rollbackID, "127.0.0.1:1234"); err == nil {
		t.Fatal("redrive succeeded without durable audit evidence")
	}
	var rollbackStatus, rollbackError string
	var rollbackJobs int
	if err = pool.QueryRow(ctx, `SELECT status,last_error,(SELECT count(*) FROM jobs WHERE kind='commit.status' AND payload->>'deliveryId'=$1) FROM commit_status_deliveries WHERE id=$2`, rollbackID.String(), rollbackID).Scan(&rollbackStatus, &rollbackError, &rollbackJobs); err != nil || rollbackStatus != "failed" || rollbackError != "raw provider secret token" || rollbackJobs != 0 {
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
			_, retryErr := db.RetryCommitStatusDeliveryWithAudit(context.Background(), principal, failedID, "127.0.0.1:1234")
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
		t.Fatalf("concurrent retries successes=%d busy=%d", successes, busy)
	}
	var status, lastError, repositoryURL, credentialServer, encryptedCredential string
	var responseCode *int
	var startedAt, finishedAt any
	var jobCount, pendingJobs, auditCount int
	if err = pool.QueryRow(ctx, `SELECT status,response_code,last_error,started_at,finished_at,repository_url,credential_server,encrypted_credential FROM commit_status_deliveries WHERE id=$1`, failedID).Scan(&status, &responseCode, &lastError, &startedAt, &finishedAt, &repositoryURL, &credentialServer, &encryptedCredential); err != nil {
		t.Fatal(err)
	}
	if err = pool.QueryRow(ctx, `SELECT count(*),count(*) FILTER (WHERE status='pending') FROM jobs WHERE kind='commit.status' AND payload->>'deliveryId'=$1`, failedID.String()).Scan(&jobCount, &pendingJobs); err != nil {
		t.Fatal(err)
	}
	if err = pool.QueryRow(ctx, `SELECT count(*) FROM audit_events WHERE organization_id=$1 AND actor_user_id=$2 AND action='commit_status_delivery.retry' AND resource_id=$3`, organizationID, userID, failedID.String()).Scan(&auditCount); err != nil {
		t.Fatal(err)
	}
	if status != "pending" || responseCode != nil || lastError != "" || startedAt != nil || finishedAt != nil || jobCount != 2 || pendingJobs != 1 || auditCount != 1 || repositoryURL != "https://git.example.test/private/repository" || credentialServer != "secret-host" || encryptedCredential != "encrypted-secret" {
		t.Fatalf("redrive state status=%q response=%v started=%v finished=%v jobs=%d pending=%d audits=%d snapshot=%q/%q/%q", status, responseCode, startedAt, finishedAt, jobCount, pendingJobs, auditCount, repositoryURL, credentialServer, encryptedCredential)
	}
}
