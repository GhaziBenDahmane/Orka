package deploy

import (
	"context"
	"testing"

	"github.com/google/uuid"
)

type stopRecordingScheduler struct {
	removed []string
}

func (*stopRecordingScheduler) Deploy(context.Context, string, string, map[string]string, *Credential) (DeploymentResult, error) {
	return DeploymentResult{}, nil
}
func (s *stopRecordingScheduler) Remove(_ context.Context, stack string) (string, error) {
	s.removed = append(s.removed, stack)
	return "removed " + stack, nil
}
func (*stopRecordingScheduler) RemoveVolumes(context.Context, string) (string, error) { return "", nil }
func (*stopRecordingScheduler) Logs(context.Context, string, int) (string, error)     { return "", nil }
func (*stopRecordingScheduler) Nodes(context.Context) ([]Node, error)                 { return nil, nil }
func (*stopRecordingScheduler) RunContainerJob(context.Context, string, string, string, map[string]string, []string) (string, error) {
	return "", nil
}

func TestStopWorkerPreservesServiceAndCompletesWithLease(t *testing.T) {
	db, ctx := recoveryTestStore(t)
	organizationID, projectID, environmentID, serviceID, databaseID := uuid.New(), uuid.New(), uuid.New(), uuid.New(), uuid.New()
	stackName := "stop-worker-" + serviceID.String()
	statements := []struct {
		query string
		args  []any
	}{
		{`INSERT INTO organizations(id,name,slug) VALUES($1,'Stop worker',$2)`, []any{organizationID, "stop-worker-" + organizationID.String()}},
		{`INSERT INTO projects(id,organization_id,name,slug) VALUES($1,$2,'Project','project')`, []any{projectID, organizationID}},
		{`INSERT INTO environments(id,project_id,name,slug) VALUES($1,$2,'Production','production')`, []any{environmentID, projectID}},
		{`INSERT INTO compose_services(id,environment_id,name,slug,stack_name,compose_yaml) VALUES($1,$2,'Postgres','postgres',$3,'services: {postgres: {image: postgres}}')`, []any{serviceID, environmentID, stackName}},
		{`INSERT INTO database_instances(id,environment_id,name,slug,engine,version,compose_service_id,encrypted_credentials,status) VALUES($1,$2,'Postgres','postgres','postgres','17',$3,'encrypted','running')`, []any{databaseID, environmentID, serviceID}},
	}
	for _, statement := range statements {
		if _, err := db.Pool.Exec(ctx, statement.query, statement.args...); err != nil {
			t.Fatal(err)
		}
	}
	jobID, queued, err := db.QueueServiceStop(ctx, organizationID, serviceID)
	if err != nil || !queued {
		t.Fatalf("queue stop job=%s queued=%v err=%v", jobID, queued, err)
	}
	claimed, err := (&Worker{Store: db, ID: "stop-test"}).claim(ctx)
	if err != nil || claimed.ID != jobID || claimed.Kind != "stop.compose" {
		t.Fatalf("claimed=%#v err=%v", claimed, err)
	}
	scheduler := &stopRecordingScheduler{}
	worker := &Worker{Store: db, ID: "stop-test", Swarm: scheduler}
	if err = worker.execute(ctx, claimed); err != nil {
		t.Fatal(err)
	}
	// Re-execution before terminal job commit models recovery after the side
	// effect and proves completion evidence stays idempotent.
	if err = worker.execute(ctx, claimed); err != nil {
		t.Fatal(err)
	}
	if err = worker.finish(ctx, claimed, nil); err != nil {
		t.Fatal(err)
	}
	if len(scheduler.removed) != 2 || scheduler.removed[0] != stackName {
		t.Fatalf("removed stacks=%v", scheduler.removed)
	}
	var jobStatus, databaseStatus string
	var auditCount, serviceCount int
	if err = db.Pool.QueryRow(ctx, `SELECT status FROM jobs WHERE id=$1`, jobID).Scan(&jobStatus); err != nil {
		t.Fatal(err)
	}
	if err = db.Pool.QueryRow(ctx, `SELECT status FROM database_instances WHERE id=$1`, databaseID).Scan(&databaseStatus); err != nil {
		t.Fatal(err)
	}
	if err = db.Pool.QueryRow(ctx, `SELECT count(*) FROM audit_events WHERE organization_id=$1 AND action='service.stop.completed' AND resource_id=$2`, organizationID, serviceID.String()).Scan(&auditCount); err != nil {
		t.Fatal(err)
	}
	if err = db.Pool.QueryRow(ctx, `SELECT count(*) FROM compose_services WHERE id=$1 AND desired_state='stopped'`, serviceID).Scan(&serviceCount); err != nil {
		t.Fatal(err)
	}
	if jobStatus != "succeeded" || databaseStatus != "stopped" || auditCount != 1 || serviceCount != 1 {
		t.Fatalf("job=%q database=%q audits=%d services=%d", jobStatus, databaseStatus, auditCount, serviceCount)
	}
}
