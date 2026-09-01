package store

import (
	"context"
	"errors"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
)

func TestDeletionFinalizerHistoryAndAuditedRedrive(t *testing.T) {
	databaseURL := os.Getenv("DOCKYARD_TEST_DATABASE_URL")
	if databaseURL == "" {
		t.Skip("DOCKYARD_TEST_DATABASE_URL is not set")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	db, err := Open(ctx, databaseURL)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(db.Pool.Close)

	organizationID, otherOrganizationID, userID := uuid.New(), uuid.New(), uuid.New()
	projectID, otherProjectID, environmentID, otherEnvironmentID := uuid.New(), uuid.New(), uuid.New(), uuid.New()
	serviceID, activeServiceID, missingServiceID, otherServiceID := uuid.New(), uuid.New(), uuid.New(), uuid.New()
	failedJobID := uuid.New()
	statements := []struct {
		query string
		args  []any
	}{
		{`INSERT INTO organizations(id,name,slug) VALUES($1,'Finalizer history',$2),($3,'Other finalizers',$4)`, []any{organizationID, "finalizer-history-" + organizationID.String(), otherOrganizationID, "other-finalizers-" + otherOrganizationID.String()}},
		{`INSERT INTO users(id,email,password_hash) VALUES($1,$2,'!test')`, []any{userID, userID.String() + "@example.test"}},
		{`INSERT INTO memberships(organization_id,user_id,role) VALUES($1,$2,'admin')`, []any{organizationID, userID}},
		{`INSERT INTO projects(id,organization_id,name,slug) VALUES($1,$2,'Project','project'),($3,$4,'Other','other')`, []any{projectID, organizationID, otherProjectID, otherOrganizationID}},
		{`INSERT INTO environments(id,project_id,name,slug) VALUES($1,$2,'Production','production'),($3,$4,'Other','other')`, []any{environmentID, projectID, otherEnvironmentID, otherProjectID}},
		{`INSERT INTO compose_services(id,environment_id,name,slug,stack_name,compose_yaml,deletion_requested_at) VALUES($1,$2,'Failed service','failed',$3,'services: {}',now()-interval '20 minutes'),($4,$2,'Active service','active',$5,'services: {}',now()-interval '10 minutes'),($6,$2,'Missing service','missing',$7,'services: {}',now()-interval '5 minutes'),($8,$9,'Foreign service','foreign',$10,'services: {}',now()-interval '1 hour')`, []any{serviceID, environmentID, "failed-" + serviceID.String(), activeServiceID, "active-" + activeServiceID.String(), missingServiceID, "missing-" + missingServiceID.String(), otherServiceID, otherEnvironmentID, "foreign-" + otherServiceID.String()}},
		{`INSERT INTO jobs(id,kind,payload,resource_key,status,attempts,max_attempts,last_error,finished_at) VALUES($1,'delete.compose',$2,$3,'failed',10,10,'raw swarm secret output',now())`, []any{failedJobID, []byte(`{"serviceId":"` + serviceID.String() + `","stackName":"failed-stack","deleteVolumes":true}`), "service:" + serviceID.String()}},
		{`INSERT INTO jobs(id,kind,payload,resource_key,status,max_attempts) VALUES($1,'delete.compose',$2,$3,'pending',10),($4,'delete.compose',$5,$6,'failed',10)`, []any{uuid.New(), []byte(`{"serviceId":"` + activeServiceID.String() + `"}`), "service:" + activeServiceID.String(), uuid.New(), []byte(`{"serviceId":"` + otherServiceID.String() + `"}`), "service:" + otherServiceID.String()}},
	}
	for _, statement := range statements {
		if _, err = db.Pool.Exec(ctx, statement.query, statement.args...); err != nil {
			t.Fatal(err)
		}
	}
	t.Cleanup(func() {
		_, _ = db.Pool.Exec(context.Background(), `DELETE FROM jobs WHERE kind='delete.compose' AND payload->>'serviceId'=ANY($1)`, []string{serviceID.String(), activeServiceID.String(), missingServiceID.String(), otherServiceID.String()})
		_, _ = db.Pool.Exec(context.Background(), `DELETE FROM organizations WHERE id IN ($1,$2)`, organizationID, otherOrganizationID)
		_, _ = db.Pool.Exec(context.Background(), `DELETE FROM users WHERE id=$1`, userID)
	})

	items, err := db.ListDeletionFinalizers(ctx, organizationID, DeletionFinalizerFilter{Limit: 200})
	if err != nil {
		t.Fatal(err)
	}
	if len(items) != 3 {
		t.Fatalf("finalizers=%d, want 3: %#v", len(items), items)
	}
	byID := map[uuid.UUID]DeletionFinalizer{}
	for _, item := range items {
		byID[item.ResourceID] = item
	}
	if item := byID[serviceID]; item.Status != "failed" || !item.Retryable || item.LastError == "" || item.LastError == "raw swarm secret output" {
		t.Fatalf("failed finalizer not safely represented: %#v", item)
	}
	if item := byID[missingServiceID]; item.Status != "missing" || !item.Retryable || item.JobID != nil {
		t.Fatalf("missing finalizer not represented: %#v", item)
	}
	if _, ok := byID[otherServiceID]; ok {
		t.Fatal("cross-tenant finalizer leaked")
	}
	principal := Principal{OrganizationID: organizationID, UserID: userID, Role: "admin"}
	if _, err = db.RetryDeletionFinalizerWithAudit(ctx, principal, "service", activeServiceID, "127.0.0.1:1"); !errors.Is(err, ErrBusy) {
		t.Fatalf("active retry error=%v, want ErrBusy", err)
	}
	if _, err = db.RetryDeletionFinalizerWithAudit(ctx, principal, "service", otherServiceID, "127.0.0.1:1"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("cross-tenant retry error=%v, want ErrNotFound", err)
	}
	if _, err = db.RetryDeletionFinalizerWithAudit(ctx, Principal{OrganizationID: organizationID, UserID: uuid.New(), Role: "admin"}, "service", serviceID, "127.0.0.1:1"); err == nil {
		t.Fatal("redrive committed without valid audit actor")
	}
	var rollbackJobs int
	if err = db.Pool.QueryRow(ctx, `SELECT count(*) FROM jobs WHERE kind='delete.compose' AND payload->>'serviceId'=$1`, serviceID.String()).Scan(&rollbackJobs); err != nil || rollbackJobs != 1 {
		t.Fatalf("failed audit retained redrive: jobs=%d err=%v", rollbackJobs, err)
	}

	const workers = 8
	var wg sync.WaitGroup
	results := make(chan error, workers)
	for range workers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, retryErr := db.RetryDeletionFinalizerWithAudit(context.Background(), principal, "service", serviceID, "127.0.0.1:1")
			results <- retryErr
		}()
	}
	wg.Wait()
	close(results)
	succeeded := 0
	for retryErr := range results {
		if retryErr == nil {
			succeeded++
			continue
		}
		if !errors.Is(retryErr, ErrBusy) {
			t.Fatalf("concurrent retry error=%v", retryErr)
		}
	}
	if succeeded != 1 {
		t.Fatalf("successful concurrent retries=%d, want 1", succeeded)
	}
	var jobCount, auditCount int
	var deleteVolumes bool
	if err = db.Pool.QueryRow(ctx, `SELECT count(*),bool_and((payload->>'deleteVolumes')::boolean) FROM jobs WHERE kind='delete.compose' AND payload->>'serviceId'=$1`, serviceID.String()).Scan(&jobCount, &deleteVolumes); err != nil || jobCount != 2 || !deleteVolumes {
		t.Fatalf("redrive did not preserve destructive intent: jobs=%d deleteVolumes=%v err=%v", jobCount, deleteVolumes, err)
	}
	if err = db.Pool.QueryRow(ctx, `SELECT count(*) FROM audit_events WHERE organization_id=$1 AND action='deletion_finalizer.retry' AND resource_id=$2`, organizationID, serviceID.String()).Scan(&auditCount); err != nil || auditCount != 1 {
		t.Fatalf("redrive audit count=%d err=%v", auditCount, err)
	}
	missing, err := db.RetryDeletionFinalizerWithAudit(ctx, principal, "service", missingServiceID, "127.0.0.1:1")
	if err != nil || missing.Status != "pending" {
		t.Fatalf("missing redrive=%#v err=%v", missing, err)
	}
	var missingDeletesVolumes bool
	if err = db.Pool.QueryRow(ctx, `SELECT (payload->>'deleteVolumes')::boolean FROM jobs WHERE id=$1`, *missing.JobID).Scan(&missingDeletesVolumes); err != nil || missingDeletesVolumes {
		t.Fatalf("missing service redrive should conservatively retain volumes: deleteVolumes=%v err=%v", missingDeletesVolumes, err)
	}

	// Exercise reconstruction for every other advertised resource type. These
	// jobs have no prior payload to copy, so the generated kind, identity key,
	// resource serialization, and attempt policy are the recovery contract.
	databaseID, clusterID, networkID := uuid.New(), uuid.New(), uuid.New()
	for _, statement := range []struct {
		query string
		args  []any
	}{
		{`UPDATE projects SET deletion_requested_at=now() WHERE id=$1`, []any{projectID}},
		{`UPDATE environments SET deletion_requested_at=now() WHERE id=$1`, []any{environmentID}},
		{`INSERT INTO database_instances(id,environment_id,name,slug,engine,version,management_kind,connection_service_name,encrypted_credentials,compose_service_id,deletion_requested_at) VALUES($1,$2,'Deleting database','deleting-database','postgres','17','compose','postgres','encrypted',$3,now())`, []any{databaseID, environmentID, activeServiceID}},
		{`INSERT INTO clusters(id,organization_id,name,slug,state,deletion_requested_at) VALUES($1,$2,'Deleting cluster',$3,'disabled',now())`, []any{clusterID, organizationID, "deleting-cluster-" + clusterID.String()}},
		{`INSERT INTO managed_networks(id,organization_id,name,driver,status,deletion_requested_at) VALUES($1,$2,$3,'overlay','deleting',now())`, []any{networkID, organizationID, "deleting-network-" + networkID.String()}},
	} {
		if _, err = db.Pool.Exec(ctx, statement.query, statement.args...); err != nil {
			t.Fatal(err)
		}
	}
	for _, test := range []struct {
		resourceType string
		resourceID   uuid.UUID
		kind         string
		payloadKey   string
		resourceKey  string
		maxAttempts  int
	}{
		{resourceType: "project", resourceID: projectID, kind: "delete.project", payloadKey: "projectId", maxAttempts: 50},
		{resourceType: "environment", resourceID: environmentID, kind: "delete.environment", payloadKey: "environmentId", maxAttempts: 50},
		{resourceType: "database", resourceID: databaseID, kind: "delete.database-link", payloadKey: "databaseId", resourceKey: "database:" + databaseID.String(), maxAttempts: 10},
		{resourceType: "cluster", resourceID: clusterID, kind: "delete.cluster", payloadKey: "clusterId", maxAttempts: 10},
		{resourceType: "network", resourceID: networkID, kind: "network.delete", payloadKey: "networkId", resourceKey: "network:" + networkID.String(), maxAttempts: 10},
	} {
		item, retryErr := db.RetryDeletionFinalizerWithAudit(ctx, principal, test.resourceType, test.resourceID, "127.0.0.1:1")
		if retryErr != nil || item.JobID == nil || item.Kind != test.kind || item.Status != "pending" || item.MaxAttempts != test.maxAttempts {
			t.Fatalf("%s missing finalizer reconstruction=%#v err=%v", test.resourceType, item, retryErr)
		}
		var payload map[string]any
		var resourceKey *string
		var maxAttempts int
		if err = db.Pool.QueryRow(ctx, `SELECT payload,resource_key,max_attempts FROM jobs WHERE id=$1`, *item.JobID).Scan(&payload, &resourceKey, &maxAttempts); err != nil {
			t.Fatal(err)
		}
		if payload[test.payloadKey] != test.resourceID.String() || maxAttempts != test.maxAttempts || test.resourceKey == "" && resourceKey != nil || test.resourceKey != "" && (resourceKey == nil || *resourceKey != test.resourceKey) {
			t.Fatalf("%s reconstructed payload=%#v resourceKey=%v maxAttempts=%d", test.resourceType, payload, resourceKey, maxAttempts)
		}
	}
}
