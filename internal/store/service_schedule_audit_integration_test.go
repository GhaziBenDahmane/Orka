package store

import (
	"context"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

func TestServiceScheduleMutationsCommitWithAudit(t *testing.T) {
	pool, ctx := migrationTestPool(t)
	if err := Migrate(ctx, pool); err != nil {
		t.Fatal(err)
	}
	db := &Store{Pool: pool}
	organizationID, userID, serviceAccountID := uuid.New(), uuid.New(), uuid.New()
	projectID, environmentID, serviceID := uuid.New(), uuid.New(), uuid.New()
	for _, statement := range []struct {
		query string
		args  []any
	}{
		{`INSERT INTO organizations(id,name,slug) VALUES($1,'Schedule audit',$2)`, []any{organizationID, "schedule-audit-" + organizationID.String()}},
		{`INSERT INTO users(id,email,password_hash) VALUES($1,$2,'!test')`, []any{userID, userID.String() + "@example.test"}},
		{`INSERT INTO service_accounts(id,organization_id,name,role) VALUES($1,$2,'schedule-operator','admin')`, []any{serviceAccountID, organizationID}},
		{`INSERT INTO projects(id,organization_id,name,slug) VALUES($1,$2,'Project','project')`, []any{projectID, organizationID}},
		{`INSERT INTO environments(id,project_id,name,slug) VALUES($1,$2,'Production','production')`, []any{environmentID, projectID}},
		{`INSERT INTO compose_services(id,environment_id,name,slug,stack_name,compose_yaml) VALUES($1,$2,'API','api',$3,'services: {api: {image: alpine}}')`, []any{serviceID, environmentID, "schedule-audit-" + serviceID.String()}},
	} {
		if _, err := pool.Exec(ctx, statement.query, statement.args...); err != nil {
			t.Fatal(err)
		}
	}
	scheduleInput := func(name, command string) ServiceSchedule {
		return ServiceSchedule{ComposeServiceID: serviceID, Name: name, CronExpression: "*/5 * * * *", Timezone: "UTC", TargetService: "api", Shell: "sh", Command: command, TimeoutSeconds: 30, Enabled: true}
	}
	mainSchedule, err := db.CreateServiceSchedule(ctx, organizationID, scheduleInput("main", "echo original"))
	if err != nil {
		t.Fatal(err)
	}
	cancelSchedule, err := db.CreateServiceSchedule(ctx, organizationID, scheduleInput("cancel", "echo cancel"))
	if err != nil {
		t.Fatal(err)
	}
	cancelExecution, err := db.QueueServiceScheduleExecution(ctx, organizationID, serviceID, cancelSchedule.ID, userID)
	if err != nil {
		t.Fatal(err)
	}
	principal := Principal{OrganizationID: organizationID, UserID: userID, Role: "owner"}
	servicePrincipal := Principal{OrganizationID: organizationID, ServiceAccountID: &serviceAccountID, Role: "admin"}
	if _, err = pool.Exec(ctx, `CREATE FUNCTION reject_service_schedule_audit() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF NEW.action IN ('service_schedule.create','service_schedule.update','service_schedule.delete','service_schedule.run','service_schedule.cancel') THEN RAISE EXCEPTION 'forced audit failure'; END IF; RETURN NEW; END $$`); err != nil {
		t.Fatal(err)
	}
	if _, err = pool.Exec(ctx, `CREATE TRIGGER reject_service_schedule_audit BEFORE INSERT ON audit_events FOR EACH ROW EXECUTE FUNCTION reject_service_schedule_audit()`); err != nil {
		t.Fatal(err)
	}
	if _, err = db.CreateServiceScheduleWithAudit(ctx, principal, scheduleInput("failed", "echo failed"), "127.0.0.1:1234"); err == nil {
		t.Fatal("schedule creation succeeded after audit rejection")
	}
	failedUpdate := scheduleInput("changed", "echo changed")
	failedUpdate.ID = mainSchedule.ID
	if _, err = db.UpdateServiceScheduleWithAudit(ctx, servicePrincipal, serviceID, failedUpdate, "127.0.0.1:1234"); err == nil {
		t.Fatal("schedule update succeeded after audit rejection")
	}
	stored, err := db.GetServiceSchedule(ctx, organizationID, serviceID, mainSchedule.ID)
	if err != nil || stored.Name != "main" || stored.Command != "echo original" {
		t.Fatalf("failed audit changed schedule: schedule=%#v err=%v", stored, err)
	}
	if err = db.DeleteServiceScheduleWithAudit(ctx, principal, serviceID, mainSchedule.ID, "127.0.0.1:1234"); err == nil {
		t.Fatal("schedule deletion succeeded after audit rejection")
	}
	if _, err = db.GetServiceSchedule(ctx, organizationID, serviceID, mainSchedule.ID); err != nil {
		t.Fatalf("failed audit removed schedule: %v", err)
	}
	if _, err = db.QueueServiceScheduleExecutionWithAudit(ctx, principal, serviceID, mainSchedule.ID, "127.0.0.1:1234"); err == nil {
		t.Fatal("schedule execution succeeded after audit rejection")
	}
	assertScheduleExecutionCount(t, pool, ctx, mainSchedule.ID, 0)
	if err = db.CancelServiceScheduleExecutionWithAudit(ctx, servicePrincipal, serviceID, cancelExecution.ID, "127.0.0.1:1234"); err == nil {
		t.Fatal("schedule cancellation succeeded after audit rejection")
	}
	assertScheduleExecutionStatus(t, pool, ctx, cancelExecution.ID, "queued", "pending", false)
	if _, err = pool.Exec(ctx, `DROP TRIGGER reject_service_schedule_audit ON audit_events`); err != nil {
		t.Fatal(err)
	}
	if _, err = pool.Exec(ctx, `DROP FUNCTION reject_service_schedule_audit()`); err != nil {
		t.Fatal(err)
	}

	created, err := db.CreateServiceScheduleWithAudit(ctx, principal, scheduleInput("created", "echo created"), "127.0.0.1:1234")
	if err != nil {
		t.Fatal(err)
	}
	updatedInput := scheduleInput("updated", "echo updated")
	updatedInput.ID = mainSchedule.ID
	if _, err = db.UpdateServiceScheduleWithAudit(ctx, servicePrincipal, serviceID, updatedInput, "127.0.0.1:1234"); err != nil {
		t.Fatal(err)
	}
	execution, err := db.QueueServiceScheduleExecutionWithAudit(ctx, principal, serviceID, mainSchedule.ID, "127.0.0.1:1234")
	if err != nil {
		t.Fatal(err)
	}
	if err = db.CancelServiceScheduleExecutionWithAudit(ctx, servicePrincipal, serviceID, cancelExecution.ID, "127.0.0.1:1234"); err != nil {
		t.Fatal(err)
	}
	if err = db.DeleteServiceScheduleWithAudit(ctx, principal, serviceID, created.ID, "127.0.0.1:1234"); err != nil {
		t.Fatal(err)
	}
	assertScheduleExecutionCount(t, pool, ctx, mainSchedule.ID, 1)
	assertScheduleExecutionStatus(t, pool, ctx, cancelExecution.ID, "cancelled", "cancelled", true)
	var userAudits, serviceAudits, executionActor int
	if err = pool.QueryRow(ctx, `SELECT count(*) FROM audit_events WHERE organization_id=$1 AND actor_user_id=$2 AND actor_service_account_id IS NULL AND action IN ('service_schedule.create','service_schedule.delete','service_schedule.run')`, organizationID, userID).Scan(&userAudits); err != nil {
		t.Fatal(err)
	}
	if err = pool.QueryRow(ctx, `SELECT count(*) FROM audit_events WHERE organization_id=$1 AND actor_user_id IS NULL AND actor_service_account_id=$2 AND action IN ('service_schedule.update','service_schedule.cancel')`, organizationID, serviceAccountID).Scan(&serviceAudits); err != nil {
		t.Fatal(err)
	}
	if err = pool.QueryRow(ctx, `SELECT count(*) FROM service_schedule_executions WHERE id=$1 AND actor_user_id=$2`, execution.ID, userID).Scan(&executionActor); err != nil {
		t.Fatal(err)
	}
	if userAudits != 3 || serviceAudits != 2 || executionActor != 1 {
		t.Fatalf("schedule audit attribution: user=%d service=%d execution actor=%d", userAudits, serviceAudits, executionActor)
	}
}

func assertScheduleExecutionCount(t *testing.T, pool interface {
	QueryRow(ctx context.Context, sql string, args ...any) pgx.Row
}, ctx context.Context, scheduleID uuid.UUID, want int) {
	t.Helper()
	var executions, jobs int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM service_schedule_executions WHERE schedule_id=$1`, scheduleID).Scan(&executions); err != nil {
		t.Fatal(err)
	}
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM jobs job JOIN service_schedule_executions execution ON job.payload->>'executionId'=execution.id::text WHERE job.kind='run.service-schedule' AND execution.schedule_id=$1`, scheduleID).Scan(&jobs); err != nil {
		t.Fatal(err)
	}
	if executions != want || jobs != want {
		t.Fatalf("schedule execution state: executions=%d jobs=%d", executions, jobs)
	}
}

func assertScheduleExecutionStatus(t *testing.T, pool interface {
	QueryRow(ctx context.Context, sql string, args ...any) pgx.Row
}, ctx context.Context, executionID uuid.UUID, executionStatus, jobStatus string, cancelled bool) {
	t.Helper()
	var storedExecutionStatus, storedJobStatus string
	var cancellationRequested bool
	if err := pool.QueryRow(ctx, `SELECT status FROM service_schedule_executions WHERE id=$1`, executionID).Scan(&storedExecutionStatus); err != nil {
		t.Fatal(err)
	}
	if err := pool.QueryRow(ctx, `SELECT status,cancel_requested_at IS NOT NULL FROM jobs WHERE kind='run.service-schedule' AND payload->>'executionId'=$1`, executionID.String()).Scan(&storedJobStatus, &cancellationRequested); err != nil {
		t.Fatal(err)
	}
	if storedExecutionStatus != executionStatus || storedJobStatus != jobStatus || cancellationRequested != cancelled {
		t.Fatalf("schedule cancellation state: execution=%q job=%q cancelled=%v", storedExecutionStatus, storedJobStatus, cancellationRequested)
	}
}
