package store

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

type DatabaseMigration struct {
	ID                    uuid.UUID  `json:"id"`
	DatabaseInstanceID    uuid.UUID  `json:"databaseInstanceId"`
	SourceKind            string     `json:"sourceKind"`
	SourceID              string     `json:"sourceId"`
	SourceEngine          string     `json:"sourceEngine"`
	SourceVersion         string     `json:"sourceVersion"`
	SourceHost            string     `json:"sourceHost"`
	EncryptedSourceConfig string     `json:"-"`
	Status                string     `json:"status"`
	SizeBytes             *int64     `json:"sizeBytes,omitempty"`
	SHA256                string     `json:"sha256,omitempty"`
	Output                string     `json:"output,omitempty"`
	Error                 string     `json:"error,omitempty"`
	CreatedAt             time.Time  `json:"createdAt"`
	StartedAt             *time.Time `json:"startedAt,omitempty"`
	FinishedAt            *time.Time `json:"finishedAt,omitempty"`
}

func (s *Store) QueueDatabaseMigration(ctx context.Context, organizationID uuid.UUID, item DatabaseMigration) (DatabaseMigration, error) {
	tx, err := s.Pool.Begin(ctx)
	if err != nil {
		return DatabaseMigration{}, err
	}
	defer tx.Rollback(ctx)
	var lockedID uuid.UUID
	var composeServiceID *uuid.UUID
	if err = tx.QueryRow(ctx, `SELECT d.id,d.compose_service_id FROM database_instances d JOIN environments e ON e.id=d.environment_id JOIN projects p ON p.id=e.project_id WHERE d.id=$1 AND p.organization_id=$2 FOR UPDATE OF d`, item.DatabaseInstanceID, organizationID).Scan(&lockedID, &composeServiceID); errors.Is(err, pgx.ErrNoRows) {
		return DatabaseMigration{}, ErrNotFound
	} else if err != nil {
		return DatabaseMigration{}, err
	}
	if err = lockDatabaseServiceForOperation(ctx, tx, composeServiceID); err != nil {
		return DatabaseMigration{}, err
	}
	if item.ID == uuid.Nil {
		item.ID = uuid.New()
	}
	item.Status = "queued"
	err = tx.QueryRow(ctx, `INSERT INTO database_migrations(id,database_instance_id,source_kind,source_id,source_engine,source_version,source_host,encrypted_source_config) VALUES($1,$2,$3,$4,$5,$6,$7,$8) RETURNING created_at`, item.ID, item.DatabaseInstanceID, item.SourceKind, item.SourceID, item.SourceEngine, item.SourceVersion, item.SourceHost, item.EncryptedSourceConfig).Scan(&item.CreatedAt)
	if err != nil {
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && pgErr.Code == "23505" {
			return DatabaseMigration{}, ErrBusy
		}
		return DatabaseMigration{}, err
	}
	payload, _ := json.Marshal(map[string]string{"migrationId": item.ID.String()})
	if _, err = tx.Exec(ctx, `INSERT INTO jobs(id,kind,payload,max_attempts,resource_key) VALUES($1,'migrate.database',$2,3,$3)`, uuid.New(), payload, "database:"+item.DatabaseInstanceID.String()); err != nil {
		return DatabaseMigration{}, err
	}
	item.EncryptedSourceConfig = ""
	return item, tx.Commit(ctx)
}

func (s *Store) GetDatabaseMigration(ctx context.Context, organizationID, id uuid.UUID) (DatabaseMigration, error) {
	var item DatabaseMigration
	err := s.Pool.QueryRow(ctx, `SELECT m.id,m.database_instance_id,m.source_kind,m.source_id,m.source_engine,m.source_version,m.source_host,m.status,m.size_bytes,m.sha256,m.output,m.error,m.created_at,m.started_at,m.finished_at FROM database_migrations m JOIN database_instances d ON d.id=m.database_instance_id JOIN environments e ON e.id=d.environment_id JOIN projects p ON p.id=e.project_id WHERE m.id=$1 AND p.organization_id=$2`, id, organizationID).Scan(&item.ID, &item.DatabaseInstanceID, &item.SourceKind, &item.SourceID, &item.SourceEngine, &item.SourceVersion, &item.SourceHost, &item.Status, &item.SizeBytes, &item.SHA256, &item.Output, &item.Error, &item.CreatedAt, &item.StartedAt, &item.FinishedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return DatabaseMigration{}, ErrNotFound
	}
	return item, err
}

func (s *Store) ListDatabaseMigrations(ctx context.Context, organizationID, databaseInstanceID uuid.UUID) ([]DatabaseMigration, error) {
	rows, err := s.Pool.Query(ctx, `SELECT m.id,m.database_instance_id,m.source_kind,m.source_id,m.source_engine,m.source_version,m.source_host,m.status,m.size_bytes,m.sha256,m.output,m.error,m.created_at,m.started_at,m.finished_at FROM database_migrations m JOIN database_instances d ON d.id=m.database_instance_id JOIN environments e ON e.id=d.environment_id JOIN projects p ON p.id=e.project_id WHERE m.database_instance_id=$1 AND p.organization_id=$2 ORDER BY m.created_at DESC LIMIT 100`, databaseInstanceID, organizationID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	items := []DatabaseMigration{}
	for rows.Next() {
		var item DatabaseMigration
		if err = rows.Scan(&item.ID, &item.DatabaseInstanceID, &item.SourceKind, &item.SourceID, &item.SourceEngine, &item.SourceVersion, &item.SourceHost, &item.Status, &item.SizeBytes, &item.SHA256, &item.Output, &item.Error, &item.CreatedAt, &item.StartedAt, &item.FinishedAt); err != nil {
			return nil, err
		}
		items = append(items, item)
	}
	return items, rows.Err()
}

func (s *Store) CancelDatabaseMigration(ctx context.Context, organizationID, id uuid.UUID) error {
	tx, err := s.Pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	var resourceStatus, jobStatus string
	var jobID uuid.UUID
	err = tx.QueryRow(ctx, `SELECT m.status,j.status,j.id FROM database_migrations m JOIN database_instances d ON d.id=m.database_instance_id JOIN environments e ON e.id=d.environment_id JOIN projects p ON p.id=e.project_id JOIN jobs j ON j.kind='migrate.database' AND j.payload->>'migrationId'=m.id::text WHERE m.id=$1 AND p.organization_id=$2 FOR UPDATE OF m,j`, id, organizationID).Scan(&resourceStatus, &jobStatus, &jobID)
	if errors.Is(err, pgx.ErrNoRows) {
		return ErrNotFound
	}
	if err != nil {
		return err
	}
	switch jobStatus {
	case "pending":
		if _, err = tx.Exec(ctx, `UPDATE database_migrations SET status='cancelled',error='cancelled by user',finished_at=now() WHERE id=$1`, id); err != nil {
			return err
		}
		if _, err = tx.Exec(ctx, `UPDATE jobs SET status='cancelled',cancel_requested_at=now(),finished_at=now() WHERE id=$1`, jobID); err != nil {
			return err
		}
	case "running":
		if resourceStatus != "running" {
			return ErrNotCancellable
		}
		if _, err = tx.Exec(ctx, `UPDATE jobs SET cancel_requested_at=COALESCE(cancel_requested_at,now()) WHERE id=$1`, jobID); err != nil {
			return err
		}
	default:
		return ErrNotCancellable
	}
	return tx.Commit(ctx)
}
