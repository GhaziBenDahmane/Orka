package store

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	jobschedule "github.com/bendahma/dokploy-go/internal/schedule"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"gopkg.in/yaml.v3"
)

type ServiceSchedule struct {
	ID               uuid.UUID `json:"id"`
	ComposeServiceID uuid.UUID `json:"composeServiceId"`
	Name             string    `json:"name"`
	Description      string    `json:"description"`
	CronExpression   string    `json:"cronExpression"`
	Timezone         string    `json:"timezone"`
	TargetService    string    `json:"targetService"`
	Shell            string    `json:"shell"`
	Command          string    `json:"command"`
	TimeoutSeconds   int       `json:"timeoutSeconds"`
	Enabled          bool      `json:"enabled"`
	NextRunAt        time.Time `json:"nextRunAt"`
	CreatedAt        time.Time `json:"createdAt"`
	UpdatedAt        time.Time `json:"updatedAt"`
}

type ServiceScheduleExecution struct {
	ID               uuid.UUID  `json:"id"`
	ScheduleID       *uuid.UUID `json:"scheduleId,omitempty"`
	ComposeServiceID uuid.UUID  `json:"composeServiceId"`
	ScheduleName     string     `json:"scheduleName"`
	TargetService    string     `json:"targetService"`
	Shell            string     `json:"shell"`
	Command          string     `json:"command"`
	TimeoutSeconds   int        `json:"timeoutSeconds"`
	Trigger          string     `json:"trigger"`
	ActorUserID      *uuid.UUID `json:"actorUserId,omitempty"`
	Status           string     `json:"status"`
	Output           string     `json:"output"`
	Error            string     `json:"error"`
	CreatedAt        time.Time  `json:"createdAt"`
	StartedAt        *time.Time `json:"startedAt,omitempty"`
	FinishedAt       *time.Time `json:"finishedAt,omitempty"`
}

func normalizeServiceSchedule(item ServiceSchedule, now time.Time) (ServiceSchedule, error) {
	item.Name = strings.TrimSpace(item.Name)
	item.Description = strings.TrimSpace(item.Description)
	item.CronExpression = strings.TrimSpace(item.CronExpression)
	item.Timezone = strings.TrimSpace(item.Timezone)
	item.TargetService = strings.TrimSpace(item.TargetService)
	item.Shell = strings.TrimSpace(item.Shell)
	item.Command = strings.TrimSpace(item.Command)
	if item.Timezone == "" {
		item.Timezone = "UTC"
	}
	if item.Shell == "" {
		item.Shell = "sh"
	}
	if item.TimeoutSeconds == 0 {
		item.TimeoutSeconds = 900
	}
	if item.Name == "" || len(item.Name) > 120 || !utf8.ValidString(item.Name) || strings.IndexFunc(item.Name, unicode.IsControl) >= 0 ||
		len(item.Description) > 1000 || !utf8.ValidString(item.Description) || strings.ContainsRune(item.Description, 0) ||
		item.TargetService == "" || len(item.TargetService) > 128 || (item.Shell != "sh" && item.Shell != "bash") ||
		item.Command == "" || len(item.Command) > 16384 || strings.ContainsRune(item.Command, 0) || item.TimeoutSeconds < 1 || item.TimeoutSeconds > 86400 {
		return ServiceSchedule{}, ErrInvalidSchedule
	}
	for index, r := range item.TargetService {
		if !((r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '_' || r == '.' || r == '-') {
			return ServiceSchedule{}, ErrInvalidSchedule
		}
		if index == 0 && !((r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9')) {
			return ServiceSchedule{}, ErrInvalidSchedule
		}
	}
	next, err := jobschedule.Next(item.CronExpression, item.Timezone, now)
	if err != nil {
		return ServiceSchedule{}, errors.Join(ErrInvalidSchedule, err)
	}
	item.NextRunAt = next
	return item, nil
}

func scanServiceSchedule(row pgx.Row) (ServiceSchedule, error) {
	var item ServiceSchedule
	err := row.Scan(&item.ID, &item.ComposeServiceID, &item.Name, &item.Description, &item.CronExpression, &item.Timezone, &item.TargetService, &item.Shell, &item.Command, &item.TimeoutSeconds, &item.Enabled, &item.NextRunAt, &item.CreatedAt, &item.UpdatedAt)
	return item, err
}

const serviceScheduleColumns = `schedule.id,schedule.compose_service_id,schedule.name,schedule.description,schedule.cron_expression,schedule.timezone,schedule.target_service,schedule.shell,schedule.command,schedule.timeout_seconds,schedule.enabled,schedule.next_run_at,schedule.created_at,schedule.updated_at`

func (s *Store) CreateServiceSchedule(ctx context.Context, organizationID uuid.UUID, item ServiceSchedule) (ServiceSchedule, error) {
	tx, err := s.Pool.Begin(ctx)
	if err != nil {
		return ServiceSchedule{}, err
	}
	defer tx.Rollback(ctx)
	item, err = s.createServiceScheduleTx(ctx, tx, organizationID, item)
	if err != nil {
		return ServiceSchedule{}, err
	}
	if err = tx.Commit(ctx); err != nil {
		return ServiceSchedule{}, err
	}
	return item, nil
}

func (s *Store) CreateServiceScheduleWithAudit(ctx context.Context, principal Principal, item ServiceSchedule, remoteAddr string) (ServiceSchedule, error) {
	tx, err := s.Pool.Begin(ctx)
	if err != nil {
		return ServiceSchedule{}, err
	}
	defer tx.Rollback(ctx)
	item, err = s.createServiceScheduleTx(ctx, tx, principal.OrganizationID, item)
	if err != nil {
		return ServiceSchedule{}, err
	}
	if err = appendPrincipalAudit(ctx, tx, principal, "service_schedule.create", "service_schedule", item.ID.String(), remoteAddr, map[string]any{"serviceId": item.ComposeServiceID}); err != nil {
		return ServiceSchedule{}, err
	}
	if err = tx.Commit(ctx); err != nil {
		return ServiceSchedule{}, err
	}
	return item, nil
}

func (s *Store) createServiceScheduleTx(ctx context.Context, tx pgx.Tx, organizationID uuid.UUID, item ServiceSchedule) (ServiceSchedule, error) {
	item, err := normalizeServiceSchedule(item, time.Now())
	if err != nil {
		return ServiceSchedule{}, err
	}
	item.ID = uuid.New()
	var compose string
	err = tx.QueryRow(ctx, `SELECT service.compose_yaml FROM compose_services service JOIN environments environment ON environment.id=service.environment_id JOIN projects project ON project.id=environment.project_id WHERE service.id=$1 AND project.organization_id=$2 AND service.deletion_requested_at IS NULL AND environment.deletion_requested_at IS NULL AND project.deletion_requested_at IS NULL FOR UPDATE OF service`, item.ComposeServiceID, organizationID).Scan(&compose)
	if errors.Is(err, pgx.ErrNoRows) {
		return ServiceSchedule{}, ErrNotFound
	}
	if err != nil {
		return ServiceSchedule{}, err
	}
	if !composeDeclaresService(compose, item.TargetService) {
		return ServiceSchedule{}, errors.Join(ErrInvalidSchedule, errors.New("target service is not declared by the Compose document"))
	}
	row := tx.QueryRow(ctx, `INSERT INTO service_schedules AS schedule(id,compose_service_id,name,description,cron_expression,timezone,target_service,shell,command,timeout_seconds,enabled,next_run_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12) RETURNING `+serviceScheduleColumns,
		item.ID, item.ComposeServiceID, item.Name, item.Description, item.CronExpression, item.Timezone, item.TargetService, item.Shell, item.Command, item.TimeoutSeconds, item.Enabled, item.NextRunAt)
	item, err = scanServiceSchedule(row)
	if err != nil {
		return ServiceSchedule{}, err
	}
	return item, nil
}

func (s *Store) ListServiceSchedules(ctx context.Context, organizationID, serviceID uuid.UUID) ([]ServiceSchedule, error) {
	rows, err := s.Pool.Query(ctx, `SELECT `+serviceScheduleColumns+` FROM service_schedules schedule JOIN compose_services service ON service.id=schedule.compose_service_id JOIN environments environment ON environment.id=service.environment_id JOIN projects project ON project.id=environment.project_id WHERE service.id=$1 AND project.organization_id=$2 ORDER BY schedule.name,schedule.id`, serviceID, organizationID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	items := []ServiceSchedule{}
	for rows.Next() {
		item, scanErr := scanServiceSchedule(rows)
		if scanErr != nil {
			return nil, scanErr
		}
		items = append(items, item)
	}
	return items, rows.Err()
}

func (s *Store) GetServiceSchedule(ctx context.Context, organizationID, serviceID, scheduleID uuid.UUID) (ServiceSchedule, error) {
	item, err := scanServiceSchedule(s.Pool.QueryRow(ctx, `SELECT `+serviceScheduleColumns+` FROM service_schedules schedule JOIN compose_services service ON service.id=schedule.compose_service_id JOIN environments environment ON environment.id=service.environment_id JOIN projects project ON project.id=environment.project_id WHERE schedule.id=$1 AND service.id=$2 AND project.organization_id=$3`, scheduleID, serviceID, organizationID))
	if errors.Is(err, pgx.ErrNoRows) {
		return ServiceSchedule{}, ErrNotFound
	}
	return item, err
}

func (s *Store) UpdateServiceSchedule(ctx context.Context, organizationID, serviceID uuid.UUID, item ServiceSchedule) (ServiceSchedule, error) {
	tx, err := s.Pool.Begin(ctx)
	if err != nil {
		return ServiceSchedule{}, err
	}
	defer tx.Rollback(ctx)
	item, err = s.updateServiceScheduleTx(ctx, tx, organizationID, serviceID, item)
	if err != nil {
		return ServiceSchedule{}, err
	}
	if err = tx.Commit(ctx); err != nil {
		return ServiceSchedule{}, err
	}
	return item, nil
}

func (s *Store) UpdateServiceScheduleWithAudit(ctx context.Context, principal Principal, serviceID uuid.UUID, item ServiceSchedule, remoteAddr string) (ServiceSchedule, error) {
	tx, err := s.Pool.Begin(ctx)
	if err != nil {
		return ServiceSchedule{}, err
	}
	defer tx.Rollback(ctx)
	item, err = s.updateServiceScheduleTx(ctx, tx, principal.OrganizationID, serviceID, item)
	if err != nil {
		return ServiceSchedule{}, err
	}
	if err = appendPrincipalAudit(ctx, tx, principal, "service_schedule.update", "service_schedule", item.ID.String(), remoteAddr, map[string]any{"serviceId": serviceID}); err != nil {
		return ServiceSchedule{}, err
	}
	if err = tx.Commit(ctx); err != nil {
		return ServiceSchedule{}, err
	}
	return item, nil
}

func (s *Store) updateServiceScheduleTx(ctx context.Context, tx pgx.Tx, organizationID, serviceID uuid.UUID, item ServiceSchedule) (ServiceSchedule, error) {
	item.ComposeServiceID = serviceID
	item, err := normalizeServiceSchedule(item, time.Now())
	if err != nil {
		return ServiceSchedule{}, err
	}
	var compose string
	err = tx.QueryRow(ctx, `SELECT service.compose_yaml FROM compose_services service JOIN environments environment ON environment.id=service.environment_id JOIN projects project ON project.id=environment.project_id WHERE service.id=$1 AND project.organization_id=$2 AND service.deletion_requested_at IS NULL FOR UPDATE OF service`, serviceID, organizationID).Scan(&compose)
	if errors.Is(err, pgx.ErrNoRows) {
		return ServiceSchedule{}, ErrNotFound
	}
	if err != nil {
		return ServiceSchedule{}, err
	}
	if !composeDeclaresService(compose, item.TargetService) {
		return ServiceSchedule{}, errors.Join(ErrInvalidSchedule, errors.New("target service is not declared by the Compose document"))
	}
	row := tx.QueryRow(ctx, `UPDATE service_schedules schedule SET name=$4,description=$5,cron_expression=$6,timezone=$7,target_service=$8,shell=$9,command=$10,timeout_seconds=$11,enabled=$12,next_run_at=$13,updated_at=now() FROM compose_services service,environments environment,projects project WHERE schedule.id=$1 AND schedule.compose_service_id=$2 AND service.id=schedule.compose_service_id AND environment.id=service.environment_id AND project.id=environment.project_id AND project.organization_id=$3 AND service.deletion_requested_at IS NULL RETURNING `+serviceScheduleColumns, item.ID, serviceID, organizationID, item.Name, item.Description, item.CronExpression, item.Timezone, item.TargetService, item.Shell, item.Command, item.TimeoutSeconds, item.Enabled, item.NextRunAt)
	item, err = scanServiceSchedule(row)
	if errors.Is(err, pgx.ErrNoRows) {
		return ServiceSchedule{}, ErrNotFound
	}
	if err != nil {
		return ServiceSchedule{}, err
	}
	return item, nil
}

func composeDeclaresService(compose, target string) bool {
	var document struct {
		Services map[string]any `yaml:"services"`
	}
	if yaml.Unmarshal([]byte(compose), &document) != nil {
		return false
	}
	_, exists := document.Services[target]
	return exists
}

func ensureScheduledTargetsDeclared(ctx context.Context, tx pgx.Tx, serviceID uuid.UUID, compose string) error {
	rows, err := tx.Query(ctx, `SELECT target_service FROM service_schedules WHERE compose_service_id=$1 ORDER BY id`, serviceID)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var target string
		if err = rows.Scan(&target); err != nil {
			return err
		}
		if !composeDeclaresService(compose, target) {
			return errors.Join(ErrInvalidSchedule, errors.New("Compose update removes a scheduled command target"))
		}
	}
	return rows.Err()
}

func (s *Store) DeleteServiceSchedule(ctx context.Context, organizationID, serviceID, scheduleID uuid.UUID) error {
	tx, err := s.Pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	if err = deleteServiceScheduleTx(ctx, tx, organizationID, serviceID, scheduleID); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

func (s *Store) DeleteServiceScheduleWithAudit(ctx context.Context, principal Principal, serviceID, scheduleID uuid.UUID, remoteAddr string) error {
	tx, err := s.Pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	if err = deleteServiceScheduleTx(ctx, tx, principal.OrganizationID, serviceID, scheduleID); err != nil {
		return err
	}
	if err = appendPrincipalAudit(ctx, tx, principal, "service_schedule.delete", "service_schedule", scheduleID.String(), remoteAddr, map[string]any{"serviceId": serviceID}); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

func deleteServiceScheduleTx(ctx context.Context, tx pgx.Tx, organizationID, serviceID, scheduleID uuid.UUID) error {
	var found uuid.UUID
	err := tx.QueryRow(ctx, `SELECT schedule.id FROM service_schedules schedule JOIN compose_services service ON service.id=schedule.compose_service_id JOIN environments environment ON environment.id=service.environment_id JOIN projects project ON project.id=environment.project_id WHERE schedule.id=$1 AND service.id=$2 AND project.organization_id=$3 FOR UPDATE OF schedule`, scheduleID, serviceID, organizationID).Scan(&found)
	if errors.Is(err, pgx.ErrNoRows) {
		return ErrNotFound
	}
	if err != nil {
		return err
	}
	if _, err = tx.Exec(ctx, `UPDATE service_schedule_executions execution SET status='cancelled',error='schedule deleted',finished_at=now() FROM jobs job WHERE execution.schedule_id=$1 AND job.kind='run.service-schedule' AND job.payload->>'executionId'=execution.id::text AND job.status='pending'`, scheduleID); err != nil {
		return err
	}
	if _, err = tx.Exec(ctx, `UPDATE jobs job SET status=CASE WHEN job.status='pending' THEN 'cancelled' ELSE job.status END,cancel_requested_at=COALESCE(job.cancel_requested_at,now()),finished_at=CASE WHEN job.status='pending' THEN now() ELSE job.finished_at END FROM service_schedule_executions execution WHERE execution.schedule_id=$1 AND job.kind='run.service-schedule' AND job.payload->>'executionId'=execution.id::text AND job.status IN ('pending','running')`, scheduleID); err != nil {
		return err
	}
	if _, err = tx.Exec(ctx, `DELETE FROM service_schedules WHERE id=$1`, scheduleID); err != nil {
		return err
	}
	return nil
}

func (s *Store) QueueServiceScheduleExecution(ctx context.Context, organizationID, serviceID, scheduleID, actorID uuid.UUID) (ServiceScheduleExecution, error) {
	tx, err := s.Pool.Begin(ctx)
	if err != nil {
		return ServiceScheduleExecution{}, err
	}
	defer tx.Rollback(ctx)
	execution, err := s.queueManualServiceScheduleExecutionTx(ctx, tx, organizationID, serviceID, scheduleID, actorID)
	if err != nil {
		return ServiceScheduleExecution{}, err
	}
	if err = tx.Commit(ctx); err != nil {
		return ServiceScheduleExecution{}, err
	}
	return execution, nil
}

func (s *Store) QueueServiceScheduleExecutionWithAudit(ctx context.Context, principal Principal, serviceID, scheduleID uuid.UUID, remoteAddr string) (ServiceScheduleExecution, error) {
	tx, err := s.Pool.Begin(ctx)
	if err != nil {
		return ServiceScheduleExecution{}, err
	}
	defer tx.Rollback(ctx)
	execution, err := s.queueManualServiceScheduleExecutionTx(ctx, tx, principal.OrganizationID, serviceID, scheduleID, principal.UserID)
	if err != nil {
		return ServiceScheduleExecution{}, err
	}
	metadata := map[string]any{"scheduleId": scheduleID, "serviceId": serviceID}
	if err = appendPrincipalAudit(ctx, tx, principal, "service_schedule.run", "service_schedule_execution", execution.ID.String(), remoteAddr, metadata); err != nil {
		return ServiceScheduleExecution{}, err
	}
	if err = tx.Commit(ctx); err != nil {
		return ServiceScheduleExecution{}, err
	}
	return execution, nil
}

func (s *Store) queueManualServiceScheduleExecutionTx(ctx context.Context, tx pgx.Tx, organizationID, serviceID, scheduleID, actorID uuid.UUID) (ServiceScheduleExecution, error) {
	var item ServiceSchedule
	var projectID, environmentID uuid.UUID
	row := tx.QueryRow(ctx, `SELECT `+serviceScheduleColumns+`,project.id,environment.id FROM service_schedules schedule JOIN compose_services service ON service.id=schedule.compose_service_id JOIN environments environment ON environment.id=service.environment_id JOIN projects project ON project.id=environment.project_id WHERE schedule.id=$1 AND service.id=$2 AND project.organization_id=$3 AND service.deletion_requested_at IS NULL AND environment.deletion_requested_at IS NULL AND project.deletion_requested_at IS NULL AND service.desired_state='running' FOR UPDATE OF schedule,service`, scheduleID, serviceID, organizationID)
	err := row.Scan(&item.ID, &item.ComposeServiceID, &item.Name, &item.Description, &item.CronExpression, &item.Timezone, &item.TargetService, &item.Shell, &item.Command, &item.TimeoutSeconds, &item.Enabled, &item.NextRunAt, &item.CreatedAt, &item.UpdatedAt, &projectID, &environmentID)
	if errors.Is(err, pgx.ErrNoRows) {
		var stopped bool
		_ = tx.QueryRow(ctx, `SELECT service.desired_state='stopped' FROM compose_services service JOIN environments environment ON environment.id=service.environment_id JOIN projects project ON project.id=environment.project_id WHERE service.id=$1 AND project.organization_id=$2`, serviceID, organizationID).Scan(&stopped)
		if stopped {
			return ServiceScheduleExecution{}, ErrServiceStopped
		}
		return ServiceScheduleExecution{}, ErrNotFound
	}
	if err != nil {
		return ServiceScheduleExecution{}, err
	}
	if err = s.enforcePolicy(ctx, tx, organizationID, &projectID, &environmentID, "deployment"); err != nil {
		return ServiceScheduleExecution{}, err
	}
	if err = ensureEnvironmentClusterWritable(ctx, tx, environmentID); err != nil {
		return ServiceScheduleExecution{}, err
	}
	execution, err := queueServiceScheduleExecutionTx(ctx, tx, item, "manual", nullableUUID(actorID))
	if err != nil {
		return ServiceScheduleExecution{}, err
	}
	return execution, nil
}

func queueServiceScheduleExecutionTx(ctx context.Context, tx pgx.Tx, item ServiceSchedule, trigger string, actor any) (ServiceScheduleExecution, error) {
	var active bool
	if err := tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM service_schedule_executions WHERE schedule_id=$1 AND status IN ('queued','running'))`, item.ID).Scan(&active); err != nil {
		return ServiceScheduleExecution{}, err
	}
	if active {
		return ServiceScheduleExecution{}, ErrBusy
	}
	execution := ServiceScheduleExecution{ID: uuid.New(), ScheduleID: &item.ID, ComposeServiceID: item.ComposeServiceID, ScheduleName: item.Name, TargetService: item.TargetService, Shell: item.Shell, Command: item.Command, Trigger: trigger, Status: "queued"}
	execution.TimeoutSeconds = item.TimeoutSeconds
	err := tx.QueryRow(ctx, `INSERT INTO service_schedule_executions(id,schedule_id,compose_service_id,schedule_name,target_service,shell,command,timeout_seconds,trigger,actor_user_id) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10) RETURNING created_at`, execution.ID, item.ID, item.ComposeServiceID, item.Name, item.TargetService, item.Shell, item.Command, item.TimeoutSeconds, trigger, actor).Scan(&execution.CreatedAt)
	if err != nil {
		return ServiceScheduleExecution{}, err
	}
	payload, _ := json.Marshal(map[string]string{"executionId": execution.ID.String()})
	_, err = tx.Exec(ctx, `INSERT INTO jobs(id,kind,payload,resource_key,max_attempts) VALUES($1,'run.service-schedule',$2,$3,1)`, uuid.New(), payload, "service:"+item.ComposeServiceID.String())
	return execution, err
}

// QueueNextDueServiceSchedule atomically advances one cron cursor and creates
// one immutable execution snapshot. Stopped/deleting/unavailable services keep
// their due cursor so the command is not silently skipped.
func (s *Store) QueueNextDueServiceSchedule(ctx context.Context, now time.Time) (ServiceScheduleExecution, error) {
	tx, err := s.Pool.Begin(ctx)
	if err != nil {
		return ServiceScheduleExecution{}, err
	}
	defer tx.Rollback(ctx)
	var item ServiceSchedule
	var organizationID, projectID, environmentID uuid.UUID
	row := tx.QueryRow(ctx, `SELECT `+serviceScheduleColumns+`,project.organization_id,project.id,environment.id FROM service_schedules schedule JOIN compose_services service ON service.id=schedule.compose_service_id JOIN environments environment ON environment.id=service.environment_id JOIN projects project ON project.id=environment.project_id LEFT JOIN clusters cluster ON cluster.id=environment.cluster_id WHERE schedule.enabled AND schedule.next_run_at<=$1 AND service.desired_state='running' AND service.deletion_requested_at IS NULL AND environment.deletion_requested_at IS NULL AND project.deletion_requested_at IS NULL AND (environment.cluster_id IS NULL OR (cluster.state='active' AND cluster.last_seen_at>now()-interval '2 minutes' AND NOT COALESCE(now()>=cluster.maintenance_starts_at AND now()<cluster.maintenance_ends_at,false))) AND NOT EXISTS(SELECT 1 FROM service_schedule_executions execution WHERE execution.schedule_id=schedule.id AND execution.status IN ('queued','running')) ORDER BY schedule.next_run_at,schedule.id FOR UPDATE OF schedule,service SKIP LOCKED LIMIT 1`, now)
	err = row.Scan(&item.ID, &item.ComposeServiceID, &item.Name, &item.Description, &item.CronExpression, &item.Timezone, &item.TargetService, &item.Shell, &item.Command, &item.TimeoutSeconds, &item.Enabled, &item.NextRunAt, &item.CreatedAt, &item.UpdatedAt, &organizationID, &projectID, &environmentID)
	if errors.Is(err, pgx.ErrNoRows) {
		return ServiceScheduleExecution{}, ErrNotFound
	}
	if err != nil {
		return ServiceScheduleExecution{}, err
	}
	if err = s.enforcePolicy(ctx, tx, organizationID, &projectID, &environmentID, "deployment"); errors.Is(err, ErrMaintenance) {
		return ServiceScheduleExecution{}, ErrNotFound
	} else if err != nil {
		return ServiceScheduleExecution{}, err
	}
	if err = ensureEnvironmentClusterWritable(ctx, tx, environmentID); errors.Is(err, ErrMaintenance) || errors.Is(err, ErrClusterUnavailable) {
		return ServiceScheduleExecution{}, ErrNotFound
	} else if err != nil {
		return ServiceScheduleExecution{}, err
	}
	next, err := jobschedule.Next(item.CronExpression, item.Timezone, now)
	if err != nil {
		return ServiceScheduleExecution{}, err
	}
	if _, err = tx.Exec(ctx, `UPDATE service_schedules SET next_run_at=$2,updated_at=now() WHERE id=$1`, item.ID, next); err != nil {
		return ServiceScheduleExecution{}, err
	}
	execution, err := queueServiceScheduleExecutionTx(ctx, tx, item, "scheduled", nil)
	if err != nil {
		return ServiceScheduleExecution{}, err
	}
	return execution, tx.Commit(ctx)
}

func scanServiceScheduleExecution(row pgx.Row) (ServiceScheduleExecution, error) {
	var item ServiceScheduleExecution
	err := row.Scan(&item.ID, &item.ScheduleID, &item.ComposeServiceID, &item.ScheduleName, &item.TargetService, &item.Shell, &item.Command, &item.TimeoutSeconds, &item.Trigger, &item.ActorUserID, &item.Status, &item.Output, &item.Error, &item.CreatedAt, &item.StartedAt, &item.FinishedAt)
	return item, err
}

const serviceScheduleExecutionColumns = `execution.id,execution.schedule_id,execution.compose_service_id,execution.schedule_name,execution.target_service,execution.shell,execution.command,execution.timeout_seconds,execution.trigger,execution.actor_user_id,execution.status,execution.output,execution.error,execution.created_at,execution.started_at,execution.finished_at`

func (s *Store) ListServiceScheduleExecutions(ctx context.Context, organizationID, serviceID uuid.UUID, limit int) ([]ServiceScheduleExecution, error) {
	if limit < 1 || limit > 200 {
		limit = 50
	}
	rows, err := s.Pool.Query(ctx, `SELECT `+serviceScheduleExecutionColumns+` FROM service_schedule_executions execution JOIN compose_services service ON service.id=execution.compose_service_id JOIN environments environment ON environment.id=service.environment_id JOIN projects project ON project.id=environment.project_id WHERE service.id=$1 AND project.organization_id=$2 ORDER BY execution.created_at DESC,execution.id DESC LIMIT $3`, serviceID, organizationID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	items := []ServiceScheduleExecution{}
	for rows.Next() {
		item, scanErr := scanServiceScheduleExecution(rows)
		if scanErr != nil {
			return nil, scanErr
		}
		items = append(items, item)
	}
	return items, rows.Err()
}

func (s *Store) CancelServiceScheduleExecution(ctx context.Context, organizationID, serviceID, executionID uuid.UUID) error {
	tx, err := s.Pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	if err = cancelServiceScheduleExecutionTx(ctx, tx, organizationID, serviceID, executionID); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

func (s *Store) CancelServiceScheduleExecutionWithAudit(ctx context.Context, principal Principal, serviceID, executionID uuid.UUID, remoteAddr string) error {
	tx, err := s.Pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	if err = cancelServiceScheduleExecutionTx(ctx, tx, principal.OrganizationID, serviceID, executionID); err != nil {
		return err
	}
	if err = appendPrincipalAudit(ctx, tx, principal, "service_schedule.cancel", "service_schedule_execution", executionID.String(), remoteAddr, map[string]any{"serviceId": serviceID}); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

func cancelServiceScheduleExecutionTx(ctx context.Context, tx pgx.Tx, organizationID, serviceID, executionID uuid.UUID) error {
	var jobID uuid.UUID
	var status string
	err := tx.QueryRow(ctx, `SELECT job.id,job.status FROM service_schedule_executions execution JOIN compose_services service ON service.id=execution.compose_service_id JOIN environments environment ON environment.id=service.environment_id JOIN projects project ON project.id=environment.project_id JOIN jobs job ON job.kind='run.service-schedule' AND job.payload->>'executionId'=execution.id::text WHERE execution.id=$1 AND execution.compose_service_id=$2 AND project.organization_id=$3 FOR UPDATE OF execution,job`, executionID, serviceID, organizationID).Scan(&jobID, &status)
	if errors.Is(err, pgx.ErrNoRows) {
		return ErrNotFound
	}
	if err != nil {
		return err
	}
	switch status {
	case "pending":
		if _, err = tx.Exec(ctx, `UPDATE jobs SET status='cancelled',cancel_requested_at=now(),finished_at=now() WHERE id=$1`, jobID); err != nil {
			return err
		}
		if _, err = tx.Exec(ctx, `UPDATE service_schedule_executions SET status='cancelled',error='cancelled by user',finished_at=now() WHERE id=$1`, executionID); err != nil {
			return err
		}
	case "running":
		if _, err = tx.Exec(ctx, `UPDATE jobs SET cancel_requested_at=COALESCE(cancel_requested_at,now()) WHERE id=$1`, jobID); err != nil {
			return err
		}
	default:
		return ErrNotCancellable
	}
	return nil
}
