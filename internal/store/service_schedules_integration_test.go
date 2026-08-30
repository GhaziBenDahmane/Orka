package store

import (
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"
)

func TestServiceScheduleLifecycleAndStoppedFencing(t *testing.T) {
	pool, ctx := migrationTestPool(t)
	if err := Migrate(ctx, pool); err != nil {
		t.Fatal(err)
	}
	db := &Store{Pool: pool}
	organizationID, projectID, environmentID, serviceID := uuid.New(), uuid.New(), uuid.New(), uuid.New()
	statements := []struct {
		query string
		args  []any
	}{
		{`INSERT INTO organizations(id,name,slug) VALUES($1,'Schedules',$2)`, []any{organizationID, "schedules-" + organizationID.String()}},
		{`INSERT INTO projects(id,organization_id,name,slug) VALUES($1,$2,'Project','project')`, []any{projectID, organizationID}},
		{`INSERT INTO environments(id,project_id,name,slug) VALUES($1,$2,'Production','production')`, []any{environmentID, projectID}},
		{`INSERT INTO compose_services(id,environment_id,name,slug,stack_name,compose_yaml) VALUES($1,$2,'API','api',$3,'services: {api: {image: alpine}}')`, []any{serviceID, environmentID, "schedules-" + serviceID.String()}},
	}
	for _, statement := range statements {
		if _, err := pool.Exec(ctx, statement.query, statement.args...); err != nil {
			t.Fatal(err)
		}
	}
	item, err := db.CreateServiceSchedule(ctx, organizationID, ServiceSchedule{ComposeServiceID: serviceID, Name: "cleanup", CronExpression: "*/5 * * * *", Timezone: "Europe/Paris", TargetService: "api", Shell: "sh", Command: "echo cleanup", Enabled: true, TimeoutSeconds: 30})
	if err != nil {
		t.Fatal(err)
	}
	if item.ID == uuid.Nil || !item.Enabled || item.NextRunAt.IsZero() {
		t.Fatalf("unexpected schedule: %#v", item)
	}
	if _, err = db.UpdateComposeService(ctx, organizationID, serviceID, "services: {worker: {image: alpine}}", ""); !errors.Is(err, ErrInvalidSchedule) {
		t.Fatalf("removing scheduled target error=%v", err)
	}
	if _, err = db.CreateServiceSchedule(ctx, organizationID, ServiceSchedule{ComposeServiceID: serviceID, Name: "invalid", CronExpression: "bad cron", TargetService: "api", Command: "true"}); !errors.Is(err, ErrInvalidSchedule) {
		t.Fatalf("invalid cron error=%v", err)
	}
	execution, err := db.QueueServiceScheduleExecution(ctx, organizationID, serviceID, item.ID, uuid.Nil)
	if err != nil || execution.Trigger != "manual" {
		t.Fatalf("manual execution=%#v err=%v", execution, err)
	}
	if _, err = db.QueueServiceScheduleExecution(ctx, organizationID, serviceID, item.ID, uuid.Nil); !errors.Is(err, ErrBusy) {
		t.Fatalf("overlapping execution error=%v", err)
	}
	if _, _, err = db.QueueServiceStop(ctx, organizationID, serviceID); !errors.Is(err, ErrBusy) {
		t.Fatalf("stop during scheduled command error=%v", err)
	}
	var resourceKey string
	if err = pool.QueryRow(ctx, `SELECT resource_key FROM jobs WHERE payload->>'executionId'=$1`, execution.ID.String()).Scan(&resourceKey); err != nil || resourceKey != "service:"+serviceID.String() {
		t.Fatalf("resource key=%q err=%v", resourceKey, err)
	}
	if _, err = pool.Exec(ctx, `UPDATE service_schedule_executions SET status='succeeded',finished_at=now() WHERE id=$1`, execution.ID); err != nil {
		t.Fatal(err)
	}
	if _, err = pool.Exec(ctx, `UPDATE jobs SET status='succeeded',finished_at=now() WHERE payload->>'executionId'=$1`, execution.ID.String()); err != nil {
		t.Fatal(err)
	}
	if _, err = pool.Exec(ctx, `UPDATE service_schedules SET next_run_at=now()-interval '1 minute' WHERE id=$1`, item.ID); err != nil {
		t.Fatal(err)
	}
	due, err := db.QueueNextDueServiceSchedule(ctx, time.Now())
	if err != nil || due.Trigger != "scheduled" {
		t.Fatalf("due execution=%#v err=%v", due, err)
	}
	if err = db.CancelServiceScheduleExecution(ctx, organizationID, serviceID, due.ID); err != nil {
		t.Fatal(err)
	}
	if _, err = pool.Exec(ctx, `UPDATE service_schedule_executions SET status='cancelled',finished_at=now() WHERE id=$1`, due.ID); err != nil {
		t.Fatal(err)
	}
	if _, err = pool.Exec(ctx, `UPDATE jobs SET status='cancelled',finished_at=now() WHERE payload->>'executionId'=$1`, due.ID.String()); err != nil {
		t.Fatal(err)
	}
	if _, err = pool.Exec(ctx, `UPDATE compose_services SET desired_state='stopped' WHERE id=$1`, serviceID); err != nil {
		t.Fatal(err)
	}
	if _, err = pool.Exec(ctx, `UPDATE service_schedules SET next_run_at=now()-interval '1 minute' WHERE id=$1`, item.ID); err != nil {
		t.Fatal(err)
	}
	var before time.Time
	if err = pool.QueryRow(ctx, `SELECT next_run_at FROM service_schedules WHERE id=$1`, item.ID).Scan(&before); err != nil {
		t.Fatal(err)
	}
	if _, err = db.QueueNextDueServiceSchedule(ctx, time.Now()); !errors.Is(err, ErrNotFound) {
		t.Fatalf("stopped scheduler error=%v", err)
	}
	var after time.Time
	if err = pool.QueryRow(ctx, `SELECT next_run_at FROM service_schedules WHERE id=$1`, item.ID).Scan(&after); err != nil || !after.Equal(before) {
		t.Fatalf("stopped cursor advanced before=%s after=%s err=%v", before, after, err)
	}
	if _, err = db.QueueServiceScheduleExecution(ctx, organizationID, serviceID, item.ID, uuid.Nil); !errors.Is(err, ErrServiceStopped) {
		t.Fatalf("manual stopped execution error=%v", err)
	}
}
