package deploy

import (
	"context"
	"testing"

	"github.com/bendahma/dokploy-go/internal/store"
	"github.com/google/uuid"
)

type scheduleRecordingScheduler struct {
	stopRecordingScheduler
	stack, service, shell, command string
}

func (s *scheduleRecordingScheduler) RunServiceCommand(_ context.Context, stack, service, shell, command string) (string, error) {
	s.stack, s.service, s.shell, s.command = stack, service, shell, command
	return "command output", nil
}

func TestServiceScheduleWorkerRecordsExecution(t *testing.T) {
	db, ctx := recoveryTestStore(t)
	organizationID, projectID, environmentID, serviceID := uuid.New(), uuid.New(), uuid.New(), uuid.New()
	stackName := "schedule-worker-" + serviceID.String()
	statements := []struct {
		query string
		args  []any
	}{
		{`INSERT INTO organizations(id,name,slug) VALUES($1,'Schedule worker',$2)`, []any{organizationID, "schedule-worker-" + organizationID.String()}},
		{`INSERT INTO projects(id,organization_id,name,slug) VALUES($1,$2,'Project','project')`, []any{projectID, organizationID}},
		{`INSERT INTO environments(id,project_id,name,slug) VALUES($1,$2,'Production','production')`, []any{environmentID, projectID}},
		{`INSERT INTO compose_services(id,environment_id,name,slug,stack_name,compose_yaml) VALUES($1,$2,'API','api',$3,'services: {api: {image: alpine}}')`, []any{serviceID, environmentID, stackName}},
	}
	for _, statement := range statements {
		if _, err := db.Pool.Exec(ctx, statement.query, statement.args...); err != nil {
			t.Fatal(err)
		}
	}
	schedule, err := db.CreateServiceSchedule(ctx, organizationID, store.ServiceSchedule{ComposeServiceID: serviceID, Name: "cleanup", CronExpression: "0 * * * *", TargetService: "api", Shell: "sh", Command: "echo ok", Enabled: true, TimeoutSeconds: 30})
	if err != nil {
		t.Fatal(err)
	}
	execution, err := db.QueueServiceScheduleExecution(ctx, organizationID, serviceID, schedule.ID, uuid.Nil)
	if err != nil {
		t.Fatal(err)
	}
	claimed, err := (&Worker{Store: db, ID: "schedule-test"}).claim(ctx)
	if err != nil || claimed.Kind != "run.service-schedule" {
		t.Fatalf("claimed=%#v err=%v", claimed, err)
	}
	scheduler := &scheduleRecordingScheduler{}
	worker := &Worker{Store: db, ID: "schedule-test", Swarm: scheduler}
	if err = worker.execute(ctx, claimed); err != nil {
		t.Fatal(err)
	}
	if err = worker.finish(ctx, claimed, nil); err != nil {
		t.Fatal(err)
	}
	if scheduler.stack != stackName || scheduler.service != "api" || scheduler.shell != "sh" || scheduler.command != "echo ok" {
		t.Fatalf("command target=%#v", scheduler)
	}
	var status, output string
	if err = db.Pool.QueryRow(ctx, `SELECT status,output FROM service_schedule_executions WHERE id=$1`, execution.ID).Scan(&status, &output); err != nil {
		t.Fatal(err)
	}
	if status != "succeeded" || output != "command output" {
		t.Fatalf("status=%q output=%q", status, output)
	}
}
