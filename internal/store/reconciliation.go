package store

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

type ReconciliationCandidate struct {
	ServiceID      uuid.UUID
	OrganizationID uuid.UUID
	StackName      string
	ClusterID      *uuid.UUID
}

type ServiceReconciliation struct {
	ComposeServiceID    uuid.UUID  `json:"composeServiceId"`
	State               string     `json:"state"`
	ConsecutiveFailures int        `json:"consecutiveFailures"`
	Detail              string     `json:"detail,omitempty"`
	LastCheckedAt       time.Time  `json:"lastCheckedAt"`
	LastRepairAt        *time.Time `json:"lastRepairAt,omitempty"`
}

func (s *Store) ListReconciliationCandidates(ctx context.Context, limit int) ([]ReconciliationCandidate, error) {
	if limit < 1 || limit > 1000 {
		limit = 250
	}
	rows, err := s.Pool.Query(ctx, `SELECT s.id,p.organization_id,s.stack_name,e.cluster_id
		FROM compose_services s
		JOIN environments e ON e.id=s.environment_id
		JOIN projects p ON p.id=e.project_id
		LEFT JOIN service_reconciliations r ON r.compose_service_id=s.id
		WHERE s.deletion_requested_at IS NULL AND e.deletion_requested_at IS NULL AND p.deletion_requested_at IS NULL
		AND EXISTS(SELECT 1 FROM deployments d WHERE d.compose_service_id=s.id AND d.status='succeeded')
		ORDER BY r.last_checked_at NULLS FIRST,s.id LIMIT $1`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	items := []ReconciliationCandidate{}
	for rows.Next() {
		var item ReconciliationCandidate
		if err = rows.Scan(&item.ServiceID, &item.OrganizationID, &item.StackName, &item.ClusterID); err != nil {
			return nil, err
		}
		items = append(items, item)
	}
	return items, rows.Err()
}

// RecordReconciliation persists an observation and, after two consecutive
// unhealthy observations, atomically queues a repair from the last known-good
// effective Compose snapshot. It never overwrites the user's desired source.
func (s *Store) RecordReconciliation(ctx context.Context, candidate ReconciliationCandidate, state, detail string) (*Deployment, error) {
	if state != "healthy" && state != "missing" && state != "degraded" && state != "unknown" {
		return nil, errors.New("invalid reconciliation state")
	}
	tx, err := s.Pool.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback(ctx)

	var projectID, environmentID uuid.UUID
	var clusterID *uuid.UUID
	err = tx.QueryRow(ctx, `SELECT p.id,e.id,e.cluster_id FROM compose_services s JOIN environments e ON e.id=s.environment_id JOIN projects p ON p.id=e.project_id
		WHERE s.id=$1 AND p.organization_id=$2 AND s.deletion_requested_at IS NULL AND e.deletion_requested_at IS NULL AND p.deletion_requested_at IS NULL FOR UPDATE OF s`, candidate.ServiceID, candidate.OrganizationID).Scan(&projectID, &environmentID, &clusterID)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	if !sameOptionalUUID(clusterID, candidate.ClusterID) {
		return nil, tx.Commit(ctx)
	}
	failures := 0
	if state == "missing" || state == "degraded" {
		err = tx.QueryRow(ctx, `INSERT INTO service_reconciliations(compose_service_id,state,consecutive_failures,detail)
			VALUES($1,$2,1,$3)
			ON CONFLICT(compose_service_id) DO UPDATE SET state=excluded.state,consecutive_failures=service_reconciliations.consecutive_failures+1,detail=excluded.detail,last_checked_at=now(),updated_at=now()
			RETURNING consecutive_failures`, candidate.ServiceID, state, truncateStore(detail, 4096)).Scan(&failures)
	} else {
		_, err = tx.Exec(ctx, `INSERT INTO service_reconciliations(compose_service_id,state,consecutive_failures,detail)
			VALUES($1,$2,0,$3)
			ON CONFLICT(compose_service_id) DO UPDATE SET state=excluded.state,consecutive_failures=0,detail=excluded.detail,last_checked_at=now(),updated_at=now()`, candidate.ServiceID, state, truncateStore(detail, 4096))
	}
	if err != nil || failures < 2 {
		if err != nil {
			return nil, err
		}
		if state == "healthy" {
			if err = cancelQueuedReconciliationTx(ctx, tx, candidate.ServiceID, "drift resolved before repair"); err != nil {
				return nil, err
			}
		}
		return nil, tx.Commit(ctx)
	}
	var activeRepair bool
	if err = tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM deployments WHERE compose_service_id=$1 AND trigger='reconcile' AND status IN ('queued','running'))`, candidate.ServiceID).Scan(&activeRepair); err != nil {
		return nil, err
	}
	if activeRepair {
		if _, err = tx.Exec(ctx, `UPDATE service_reconciliations SET state='repairing',updated_at=now() WHERE compose_service_id=$1`, candidate.ServiceID); err != nil {
			return nil, err
		}
		return nil, tx.Commit(ctx)
	}

	var permitted bool
	err = tx.QueryRow(ctx, `SELECT
		NOT EXISTS(SELECT 1 FROM jobs j JOIN deployments d ON j.kind='deploy.compose' AND d.id=(j.payload->>'deploymentId')::uuid WHERE d.compose_service_id=$1 AND j.status IN ('pending','running'))
		AND NOT EXISTS(SELECT 1 FROM jobs j WHERE j.kind='delete.compose' AND j.payload->>'serviceId'=$1::text AND j.status IN ('pending','running'))
		AND NOT EXISTS(SELECT 1 FROM resource_policies rp WHERE rp.organization_id=$2 AND rp.maintenance_enabled AND ((rp.scope_type='organization' AND rp.scope_id=$2) OR (rp.scope_type='project' AND rp.scope_id=$3) OR (rp.scope_type='environment' AND rp.scope_id=$4)))
		AND ($5::uuid IS NULL OR EXISTS(SELECT 1 FROM clusters c WHERE c.id=$5 AND c.state='active' AND c.deletion_requested_at IS NULL AND NOT COALESCE(now()>=c.maintenance_starts_at AND now()<c.maintenance_ends_at,false)))
		AND NOT EXISTS(SELECT 1 FROM service_reconciliations r WHERE r.compose_service_id=$1 AND r.last_repair_at>now()-interval '10 minutes')`, candidate.ServiceID, candidate.OrganizationID, projectID, environmentID, clusterID).Scan(&permitted)
	if err != nil {
		return nil, err
	}
	if !permitted {
		return nil, tx.Commit(ctx)
	}

	var revision int64
	var compose, encrypted string
	err = tx.QueryRow(ctx, `SELECT d.revision,d.effective_compose,d.env_snapshot
		FROM deployments d WHERE d.compose_service_id=$1 AND d.status='succeeded'
		ORDER BY d.finished_at DESC,d.created_at DESC LIMIT 1`, candidate.ServiceID).Scan(&revision, &compose, &encrypted)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, tx.Commit(ctx)
	}
	if err != nil {
		return nil, err
	}
	if compose == "" {
		_, updateErr := tx.Exec(ctx, `UPDATE service_reconciliations SET detail=$2,updated_at=now() WHERE compose_service_id=$1`, candidate.ServiceID, "repair unavailable: last successful deployment has no effective Compose snapshot")
		if updateErr != nil {
			return nil, updateErr
		}
		return nil, tx.Commit(ctx)
	}
	d := Deployment{ID: uuid.New(), ComposeServiceID: candidate.ServiceID, Revision: revision, Status: "queued", Trigger: "reconcile"}
	err = tx.QueryRow(ctx, `INSERT INTO deployments(id,compose_service_id,revision,compose_snapshot,effective_compose,env_snapshot,status,trigger)
		VALUES($1,$2,$3,$4,$4,$5,'queued','reconcile') ON CONFLICT DO NOTHING RETURNING created_at`, d.ID, d.ComposeServiceID, d.Revision, compose, encrypted).Scan(&d.CreatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, tx.Commit(ctx)
	}
	if err != nil {
		return nil, err
	}
	payload, _ := json.Marshal(map[string]string{"deploymentId": d.ID.String()})
	if _, err = tx.Exec(ctx, `INSERT INTO jobs(id,kind,payload,resource_key) VALUES($1,'deploy.compose',$2,$3)`, uuid.New(), payload, "service:"+candidate.ServiceID.String()); err != nil {
		return nil, err
	}
	if _, err = tx.Exec(ctx, `UPDATE service_reconciliations SET state='repairing',last_repair_at=now(),updated_at=now() WHERE compose_service_id=$1`, candidate.ServiceID); err != nil {
		return nil, err
	}
	if _, err = tx.Exec(ctx, `INSERT INTO audit_events(organization_id,action,resource_type,resource_id,metadata) VALUES($1,'service.reconcile.queued','compose_service',$2,jsonb_build_object('deploymentId',$3::text,'observedState',$4::text))`, candidate.OrganizationID, candidate.ServiceID.String(), d.ID, state); err != nil {
		return nil, err
	}
	return &d, tx.Commit(ctx)
}

func (s *Store) ListServiceReconciliations(ctx context.Context, organizationID uuid.UUID) ([]ServiceReconciliation, error) {
	rows, err := s.Pool.Query(ctx, `SELECT r.compose_service_id,r.state,r.consecutive_failures,r.detail,r.last_checked_at,r.last_repair_at
		FROM service_reconciliations r JOIN compose_services s ON s.id=r.compose_service_id JOIN environments e ON e.id=s.environment_id JOIN projects p ON p.id=e.project_id
		WHERE p.organization_id=$1 ORDER BY r.compose_service_id`, organizationID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	items := []ServiceReconciliation{}
	for rows.Next() {
		var item ServiceReconciliation
		if err = rows.Scan(&item.ComposeServiceID, &item.State, &item.ConsecutiveFailures, &item.Detail, &item.LastCheckedAt, &item.LastRepairAt); err != nil {
			return nil, err
		}
		items = append(items, item)
	}
	return items, rows.Err()
}

// GetServiceReconciliation returns the latest runtime observation for a
// service in the requested organization. A service can legitimately have no
// observation yet, in which case it returns nil without exposing whether a
// service with the same ID exists in another tenant.
func (s *Store) GetServiceReconciliation(ctx context.Context, organizationID, serviceID uuid.UUID) (*ServiceReconciliation, error) {
	var item ServiceReconciliation
	err := s.Pool.QueryRow(ctx, `SELECT r.compose_service_id,r.state,r.consecutive_failures,r.detail,r.last_checked_at,r.last_repair_at
		FROM service_reconciliations r
		JOIN compose_services s ON s.id=r.compose_service_id
		JOIN environments e ON e.id=s.environment_id
		JOIN projects p ON p.id=e.project_id
		WHERE r.compose_service_id=$1 AND p.organization_id=$2`, serviceID, organizationID).Scan(
		&item.ComposeServiceID, &item.State, &item.ConsecutiveFailures, &item.Detail, &item.LastCheckedAt, &item.LastRepairAt,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &item, nil
}

func sameOptionalUUID(left, right *uuid.UUID) bool {
	if left == nil || right == nil {
		return left == nil && right == nil
	}
	return *left == *right
}

func cancelQueuedReconciliationTx(ctx context.Context, tx pgx.Tx, serviceID uuid.UUID, reason string) error {
	if _, err := tx.Exec(ctx, `UPDATE jobs j SET status='cancelled',finished_at=now()
		FROM deployments d WHERE j.kind='deploy.compose' AND d.id=(j.payload->>'deploymentId')::uuid AND d.compose_service_id=$1 AND d.trigger='reconcile' AND d.status='queued' AND j.status='pending'`, serviceID); err != nil {
		return err
	}
	_, err := tx.Exec(ctx, `UPDATE deployments SET status='cancelled',error=$2,finished_at=now() WHERE compose_service_id=$1 AND trigger='reconcile' AND status='queued'`, serviceID, reason)
	return err
}
