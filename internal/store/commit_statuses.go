package store

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

type CommitStatusDelivery struct {
	ID                  uuid.UUID  `json:"id"`
	DeploymentID        uuid.UUID  `json:"deploymentId"`
	ServiceID           uuid.UUID  `json:"serviceId,omitempty"`
	ServiceName         string     `json:"serviceName,omitempty"`
	State               string     `json:"state"`
	Provider            string     `json:"provider"`
	Status              string     `json:"status"`
	ResponseCode        *int       `json:"responseCode,omitempty"`
	LastError           string     `json:"lastError,omitempty"`
	InProgress          bool       `json:"inProgress"`
	Retryable           bool       `json:"retryable"`
	CreatedAt           time.Time  `json:"createdAt"`
	StartedAt           *time.Time `json:"startedAt,omitempty"`
	FinishedAt          *time.Time `json:"finishedAt,omitempty"`
	RepositoryURL       string     `json:"-"`
	CommitSHA           string     `json:"-"`
	Context             string     `json:"-"`
	CredentialServer    string     `json:"-"`
	CredentialUsername  string     `json:"-"`
	CredentialID        *uuid.UUID `json:"-"`
	EncryptedCredential string     `json:"-"`
}

type CommitStatusDeliveryFilter struct {
	Status   string
	Provider string
	State    string
	Limit    int
}

func (s *Store) ListCommitStatusDeliveries(ctx context.Context, organizationID uuid.UUID, filter CommitStatusDeliveryFilter) ([]CommitStatusDelivery, error) {
	if filter.Limit <= 0 {
		filter.Limit = 100
	}
	if filter.Limit > 200 {
		filter.Limit = 200
	}
	rows, err := s.Pool.Query(ctx, `
		SELECT delivery.id,delivery.deployment_id,service.id,service.name,delivery.state,delivery.provider,
		       delivery.status,delivery.response_code,CASE
		           WHEN delivery.last_error='' THEN ''
		           WHEN delivery.response_code IS NOT NULL THEN 'provider returned HTTP ' || delivery.response_code::text
		           ELSE 'delivery failed; inspect controller logs using the delivery ID'
		       END,delivery.created_at,delivery.started_at,delivery.finished_at,state.active,
		       delivery.status='failed' AND NOT state.active AS retryable
		FROM commit_status_deliveries delivery
		JOIN deployments deployment ON deployment.id=delivery.deployment_id
		JOIN compose_services service ON service.id=deployment.compose_service_id
		JOIN environments environment ON environment.id=service.environment_id
		JOIN projects project ON project.id=environment.project_id
		CROSS JOIN LATERAL (
		    SELECT EXISTS(
		        SELECT 1 FROM jobs job
		        WHERE job.kind='commit.status' AND job.payload->>'deliveryId'=delivery.id::text
		          AND job.status IN ('pending','running')
		    ) AS active
		) state
		WHERE project.organization_id=$1 AND ($2='' OR delivery.status=$2)
		  AND ($3='' OR delivery.provider=$3) AND ($4='' OR delivery.state=$4)
		ORDER BY delivery.created_at DESC,delivery.id DESC
		LIMIT $5`, organizationID, filter.Status, filter.Provider, filter.State, filter.Limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	items := []CommitStatusDelivery{}
	for rows.Next() {
		var item CommitStatusDelivery
		if err = rows.Scan(&item.ID, &item.DeploymentID, &item.ServiceID, &item.ServiceName, &item.State, &item.Provider, &item.Status, &item.ResponseCode, &item.LastError, &item.CreatedAt, &item.StartedAt, &item.FinishedAt, &item.InProgress, &item.Retryable); err != nil {
			return nil, err
		}
		items = append(items, item)
	}
	return items, rows.Err()
}

func (s *Store) RetryCommitStatusDeliveryWithAudit(ctx context.Context, principal Principal, id uuid.UUID, remoteAddr string) (CommitStatusDelivery, error) {
	tx, err := s.Pool.Begin(ctx)
	if err != nil {
		return CommitStatusDelivery{}, err
	}
	defer tx.Rollback(ctx)
	var item CommitStatusDelivery
	err = tx.QueryRow(ctx, `
		SELECT delivery.id,delivery.deployment_id,service.id,service.name,delivery.state,delivery.provider,
		       delivery.status,delivery.response_code,delivery.last_error,delivery.created_at,delivery.started_at,delivery.finished_at
		FROM commit_status_deliveries delivery
		JOIN deployments deployment ON deployment.id=delivery.deployment_id
		JOIN compose_services service ON service.id=deployment.compose_service_id
		JOIN environments environment ON environment.id=service.environment_id
		JOIN projects project ON project.id=environment.project_id
		WHERE delivery.id=$1 AND project.organization_id=$2
		FOR UPDATE OF delivery`, id, principal.OrganizationID).Scan(
		&item.ID, &item.DeploymentID, &item.ServiceID, &item.ServiceName, &item.State, &item.Provider,
		&item.Status, &item.ResponseCode, &item.LastError, &item.CreatedAt, &item.StartedAt, &item.FinishedAt,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return CommitStatusDelivery{}, ErrNotFound
	}
	if err != nil {
		return CommitStatusDelivery{}, err
	}
	var active bool
	if err = tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM jobs WHERE kind='commit.status' AND payload->>'deliveryId'=$1 AND status IN ('pending','running'))`, id.String()).Scan(&active); err != nil {
		return CommitStatusDelivery{}, err
	}
	if active || item.Status == "pending" || item.Status == "running" {
		return CommitStatusDelivery{}, ErrBusy
	}
	if item.Status != "failed" {
		return CommitStatusDelivery{}, ErrCommitStatusDeliveryNotRetryable
	}
	if _, err = tx.Exec(ctx, `UPDATE commit_status_deliveries SET status='pending',response_code=NULL,last_error='',started_at=NULL,finished_at=NULL WHERE id=$1`, id); err != nil {
		return CommitStatusDelivery{}, err
	}
	jobPayload, _ := json.Marshal(map[string]string{"deliveryId": id.String()})
	if _, err = tx.Exec(ctx, `INSERT INTO jobs(id,kind,payload,max_attempts) VALUES($1,'commit.status',$2,8)`, uuid.New(), jobPayload); err != nil {
		return CommitStatusDelivery{}, err
	}
	if err = appendPrincipalAudit(ctx, tx, principal, "commit_status_delivery.retry", "commit_status_delivery", id.String(), remoteAddr, map[string]any{"deploymentId": item.DeploymentID, "serviceId": item.ServiceID, "provider": item.Provider, "state": item.State}); err != nil {
		return CommitStatusDelivery{}, err
	}
	if err = tx.Commit(ctx); err != nil {
		return CommitStatusDelivery{}, err
	}
	item.Status = "pending"
	item.ResponseCode = nil
	item.LastError = ""
	item.StartedAt = nil
	item.FinishedAt = nil
	item.InProgress = true
	item.Retryable = false
	return item, nil
}

func queueCommitStatusTx(ctx context.Context, tx pgx.Tx, deploymentID uuid.UUID, state string) error {
	deliveryID := uuid.New()
	tag, err := tx.Exec(ctx, `INSERT INTO commit_status_deliveries(id,deployment_id,state,provider,repository_url,status_context,credential_server,credential_username,credential_id,encrypted_credential)
		SELECT $1,d.id,$3,a.status_provider,a.repository_url,a.status_context,c.server,c.username,c.id,c.encrypted_secret
		FROM deployments d JOIN application_sources a ON a.compose_service_id=d.compose_service_id JOIN source_credentials c ON c.id=a.status_credential_id
		WHERE d.id=$2 AND d.commit_sha<>'' AND a.status_provider<>''
		ON CONFLICT(deployment_id,state) DO NOTHING`, deliveryID, deploymentID, state)
	if err != nil || tag.RowsAffected() == 0 {
		return err
	}
	payload, _ := json.Marshal(map[string]string{"deliveryId": deliveryID.String()})
	_, err = tx.Exec(ctx, `INSERT INTO jobs(id,kind,payload,max_attempts) VALUES($1,'commit.status',$2,8)`, uuid.New(), payload)
	return err
}

func (s *Store) QueueCommitStatus(ctx context.Context, deploymentID uuid.UUID, state string) error {
	tx, err := s.Pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	if err = queueCommitStatusTx(ctx, tx, deploymentID, state); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

func (s *Store) FinishDeployment(ctx context.Context, deploymentID uuid.UUID, status, output, message string) error {
	tx, err := s.Pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	if err = finishDeploymentTx(ctx, tx, deploymentID, status, output, message); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

func (s *Store) FinishDeploymentForJob(ctx context.Context, jobID, leaseID, deploymentID uuid.UUID, status, output, message string) error {
	return s.WithJobLease(ctx, jobID, leaseID, func(tx pgx.Tx) error {
		return finishDeploymentTx(ctx, tx, deploymentID, status, output, message)
	})
}

func (s *Store) SetDeploymentEffectiveComposeForJob(ctx context.Context, jobID, leaseID, deploymentID uuid.UUID, compose string) error {
	return s.WithJobLease(ctx, jobID, leaseID, func(tx pgx.Tx) error {
		tag, err := tx.Exec(ctx, `UPDATE deployments SET effective_compose=$2 WHERE id=$1`, deploymentID, compose)
		if err != nil {
			return err
		}
		if tag.RowsAffected() != 1 {
			return ErrNotFound
		}
		return nil
	})
}

func finishDeploymentTx(ctx context.Context, tx pgx.Tx, deploymentID uuid.UUID, status, output, message string) error {
	if _, err := tx.Exec(ctx, `UPDATE deployments SET status=$2,output=$3,error=$4,finished_at=now() WHERE id=$1`, deploymentID, status, truncateStore(output, 65536), truncateStore(message, 8192)); err != nil {
		return err
	}
	if databaseStatus := map[string]string{"succeeded": "running", "failed": "error"}[status]; databaseStatus != "" {
		if _, err := tx.Exec(ctx, `UPDATE database_instances db SET status=$2,updated_at=now() FROM deployments d WHERE d.id=$1 AND db.compose_service_id=d.compose_service_id`, deploymentID, databaseStatus); err != nil {
			return err
		}
	}
	state := map[string]string{"succeeded": "success", "failed": "failure", "cancelled": "error"}[status]
	if state != "" {
		if err := queueCommitStatusTx(ctx, tx, deploymentID, state); err != nil {
			return err
		}
	}
	return nil
}

func (s *Store) GetCommitStatusDeliveryForJob(ctx context.Context, jobID, leaseID, id uuid.UUID) (CommitStatusDelivery, error) {
	var item CommitStatusDelivery
	err := s.WithJobLease(ctx, jobID, leaseID, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `UPDATE commit_status_deliveries cs SET status='running',started_at=COALESCE(cs.started_at,now())
			FROM deployments d WHERE cs.id=$1 AND d.id=cs.deployment_id
			RETURNING cs.id,cs.deployment_id,cs.state,cs.repository_url,d.commit_sha,cs.provider,cs.status_context,cs.credential_server,cs.credential_username,cs.credential_id,cs.encrypted_credential`, id).Scan(&item.ID, &item.DeploymentID, &item.State, &item.RepositoryURL, &item.CommitSHA, &item.Provider, &item.Context, &item.CredentialServer, &item.CredentialUsername, &item.CredentialID, &item.EncryptedCredential)
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return CommitStatusDelivery{}, ErrNotFound
	}
	return item, err
}

func (s *Store) FinishCommitStatusDelivery(ctx context.Context, id uuid.UUID, code int, deliveryErr error) {
	if deliveryErr == nil {
		_, _ = s.Pool.Exec(ctx, `UPDATE commit_status_deliveries SET status='succeeded',response_code=$2,last_error='',finished_at=now() WHERE id=$1`, id, code)
		return
	}
	_, _ = s.Pool.Exec(ctx, `UPDATE commit_status_deliveries SET status='failed',response_code=NULLIF($2,0),last_error=$3,finished_at=now() WHERE id=$1`, id, code, truncateStore(deliveryErr.Error(), 8192))
}

func (s *Store) FinishCommitStatusDeliveryForJob(ctx context.Context, jobID, leaseID, id uuid.UUID, code int, deliveryErr error) error {
	return s.WithJobLease(ctx, jobID, leaseID, func(tx pgx.Tx) error {
		if deliveryErr == nil {
			_, err := tx.Exec(ctx, `UPDATE commit_status_deliveries SET status='succeeded',response_code=$2,last_error='',finished_at=now() WHERE id=$1`, id, code)
			return err
		}
		_, err := tx.Exec(ctx, `UPDATE commit_status_deliveries SET status='failed',response_code=NULLIF($2,0),last_error=$3,finished_at=now() WHERE id=$1`, id, code, truncateStore(deliveryErr.Error(), 8192))
		return err
	})
}
