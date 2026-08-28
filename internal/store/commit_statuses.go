package store

import (
	"context"
	"encoding/json"
	"errors"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

type CommitStatusDelivery struct {
	ID                  uuid.UUID
	DeploymentID        uuid.UUID
	State               string
	RepositoryURL       string
	CommitSHA           string
	Provider            string
	Context             string
	CredentialServer    string
	CredentialUsername  string
	EncryptedCredential string
}

func queueCommitStatusTx(ctx context.Context, tx pgx.Tx, deploymentID uuid.UUID, state string) error {
	deliveryID := uuid.New()
	tag, err := tx.Exec(ctx, `INSERT INTO commit_status_deliveries(id,deployment_id,state,provider,repository_url,status_context,credential_server,credential_username,encrypted_credential)
		SELECT $1,d.id,$3,a.status_provider,a.repository_url,a.status_context,c.server,c.username,c.encrypted_secret
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
		return tx.QueryRow(ctx, `UPDATE commit_status_deliveries cs SET status='running',started_at=COALESCE(started_at,now())
			FROM deployments d WHERE cs.id=$1 AND d.id=cs.deployment_id
			RETURNING cs.id,cs.deployment_id,cs.state,cs.repository_url,d.commit_sha,cs.provider,cs.status_context,cs.credential_server,cs.credential_username,cs.encrypted_credential`, id).Scan(&item.ID, &item.DeploymentID, &item.State, &item.RepositoryURL, &item.CommitSHA, &item.Provider, &item.Context, &item.CredentialServer, &item.CredentialUsername, &item.EncryptedCredential)
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
