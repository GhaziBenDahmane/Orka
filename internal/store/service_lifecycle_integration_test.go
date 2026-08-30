package store

import (
	"errors"
	"testing"

	"github.com/google/uuid"
)

func TestServiceStopStartIntentAndReconciliationFencing(t *testing.T) {
	pool, ctx := migrationTestPool(t)
	if err := Migrate(ctx, pool); err != nil {
		t.Fatal(err)
	}
	db := &Store{Pool: pool}
	organizationID, projectID, environmentID, serviceID := uuid.New(), uuid.New(), uuid.New(), uuid.New()
	stackName := "lifecycle-" + serviceID.String()
	statements := []struct {
		query string
		args  []any
	}{
		{`INSERT INTO organizations(id,name,slug) VALUES($1,'Lifecycle intent',$2)`, []any{organizationID, "lifecycle-intent-" + organizationID.String()}},
		{`INSERT INTO projects(id,organization_id,name,slug) VALUES($1,$2,'Project','project')`, []any{projectID, organizationID}},
		{`INSERT INTO environments(id,project_id,name,slug) VALUES($1,$2,'Production','production')`, []any{environmentID, projectID}},
		{`INSERT INTO compose_services(id,environment_id,name,slug,stack_name,compose_yaml) VALUES($1,$2,'API','api',$3,'services: {api: {image: nginx}}')`, []any{serviceID, environmentID, stackName}},
		{`INSERT INTO deployments(id,compose_service_id,revision,compose_snapshot,effective_compose,status,trigger,finished_at) VALUES($1,$2,1,'services: {api: {image: nginx}}','services: {api: {image: nginx@sha256:test}}','succeeded','manual',now())`, []any{uuid.New(), serviceID}},
	}
	for _, statement := range statements {
		if _, err := pool.Exec(ctx, statement.query, statement.args...); err != nil {
			t.Fatal(err)
		}
	}
	blockingJobID := uuid.New()
	if _, err := pool.Exec(ctx, `INSERT INTO jobs(id,kind,payload,resource_key) VALUES($1,'backup.volume','{}',$2)`, blockingJobID, "service:"+serviceID.String()); err != nil {
		t.Fatal(err)
	}
	if _, _, err := db.QueueServiceStop(ctx, organizationID, serviceID); !errors.Is(err, ErrBusy) {
		t.Fatalf("stop during data operation error=%v", err)
	}
	if _, err := pool.Exec(ctx, `DELETE FROM jobs WHERE id=$1`, blockingJobID); err != nil {
		t.Fatal(err)
	}

	jobID, queued, err := db.QueueServiceStop(ctx, organizationID, serviceID)
	if err != nil || !queued || jobID == uuid.Nil {
		t.Fatalf("stop job=%s queued=%v err=%v", jobID, queued, err)
	}
	service, _, err := db.GetComposeService(ctx, organizationID, serviceID)
	if err != nil || service.DesiredState != "stopped" {
		t.Fatalf("service desired state=%q err=%v", service.DesiredState, err)
	}
	candidates, err := db.ListReconciliationCandidates(ctx, 10)
	if err != nil || len(candidates) != 0 {
		t.Fatalf("stopped reconciliation candidates=%#v err=%v", candidates, err)
	}
	if repair, err := db.RecordReconciliation(ctx, ReconciliationCandidate{ServiceID: serviceID, OrganizationID: organizationID, StackName: stackName}, "missing", "intentionally absent"); !errors.Is(err, ErrNotFound) || repair != nil {
		t.Fatalf("stale reconciliation repair=%#v err=%v", repair, err)
	}
	repeatedID, repeatedQueued, err := db.QueueServiceStop(ctx, organizationID, serviceID)
	if err != nil || repeatedQueued || repeatedID != jobID {
		t.Fatalf("repeated stop job=%s queued=%v err=%v", repeatedID, repeatedQueued, err)
	}

	started, err := db.QueueServiceStart(ctx, organizationID, serviceID, uuid.Nil)
	if err != nil || started.Trigger != "start" {
		t.Fatalf("start deployment=%#v err=%v", started, err)
	}
	if err = pool.QueryRow(ctx, `SELECT desired_state FROM compose_services WHERE id=$1`, serviceID).Scan(&service.DesiredState); err != nil || service.DesiredState != "running" {
		t.Fatalf("started desired state=%q err=%v", service.DesiredState, err)
	}
	var stopKey, startKey string
	if err = pool.QueryRow(ctx, `SELECT resource_key FROM jobs WHERE id=$1`, jobID).Scan(&stopKey); err != nil {
		t.Fatal(err)
	}
	if err = pool.QueryRow(ctx, `SELECT resource_key FROM jobs WHERE payload->>'deploymentId'=$1`, started.ID.String()).Scan(&startKey); err != nil {
		t.Fatal(err)
	}
	if stopKey != "service:"+serviceID.String() || startKey != stopKey {
		t.Fatalf("resource keys stop=%q start=%q", stopKey, startKey)
	}
	if _, err = db.QueueServiceStart(ctx, organizationID, serviceID, uuid.Nil); !errors.Is(err, ErrServiceAlreadyRunning) {
		t.Fatalf("second start error=%v", err)
	}
	if _, _, err = db.QueueServiceStop(ctx, organizationID, serviceID); !errors.Is(err, ErrDeploymentActive) {
		t.Fatalf("stop during deployment error=%v", err)
	}
}
