package store

import (
	"context"
	"errors"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

func (s *Store) ListDatabaseBackups(ctx context.Context, organizationID, databaseInstanceID uuid.UUID) ([]DatabaseBackup, error) {
	rows, err := s.Pool.Query(ctx, `SELECT b.id,b.database_instance_id,b.status,b.format,b.path,b.size_bytes,b.sha256,b.encrypted,b.plaintext_sha256,b.encrypted_data_key,b.destination_id,b.object_key,b.error,b.created_at,b.started_at,b.finished_at FROM database_backups b JOIN database_instances d ON d.id=b.database_instance_id JOIN environments e ON e.id=d.environment_id JOIN projects p ON p.id=e.project_id WHERE b.database_instance_id=$1 AND p.organization_id=$2 ORDER BY b.created_at DESC LIMIT 100`, databaseInstanceID, organizationID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	items := []DatabaseBackup{}
	for rows.Next() {
		var item DatabaseBackup
		if err = rows.Scan(&item.ID, &item.DatabaseInstanceID, &item.Status, &item.Format, &item.Path, &item.SizeBytes, &item.SHA256, &item.Encrypted, &item.PlaintextSHA256, &item.EncryptedDataKey, &item.DestinationID, &item.ObjectKey, &item.Error, &item.CreatedAt, &item.StartedAt, &item.FinishedAt); err != nil {
			return nil, err
		}
		items = append(items, item)
	}
	return items, rows.Err()
}

func (s *Store) CancelDatabaseBackup(ctx context.Context, organizationID, id uuid.UUID) error {
	tx, err := s.Pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	var resourceStatus, jobStatus string
	var jobID uuid.UUID
	err = tx.QueryRow(ctx, `SELECT b.status,j.status,j.id FROM database_backups b JOIN database_instances d ON d.id=b.database_instance_id JOIN environments e ON e.id=d.environment_id JOIN projects p ON p.id=e.project_id JOIN jobs j ON j.kind='backup.database' AND j.payload->>'backupId'=b.id::text WHERE b.id=$1 AND p.organization_id=$2 FOR UPDATE OF b,j`, id, organizationID).Scan(&resourceStatus, &jobStatus, &jobID)
	if errors.Is(err, pgx.ErrNoRows) {
		return ErrNotFound
	}
	if err != nil {
		return err
	}
	if err = cancelDatabaseJob(ctx, tx, "database_backups", id, jobID, resourceStatus, jobStatus); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

func (s *Store) ListDatabaseRestores(ctx context.Context, organizationID, databaseInstanceID uuid.UUID) ([]DatabaseRestore, error) {
	rows, err := s.Pool.Query(ctx, `SELECT r.id,r.database_backup_id,r.status,r.kind,r.error,r.created_at,r.started_at,r.finished_at FROM database_restores r JOIN database_backups b ON b.id=r.database_backup_id JOIN database_instances d ON d.id=b.database_instance_id JOIN environments e ON e.id=d.environment_id JOIN projects p ON p.id=e.project_id WHERE b.database_instance_id=$1 AND p.organization_id=$2 ORDER BY r.created_at DESC LIMIT 100`, databaseInstanceID, organizationID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	items := []DatabaseRestore{}
	for rows.Next() {
		var item DatabaseRestore
		if err = rows.Scan(&item.ID, &item.DatabaseBackupID, &item.Status, &item.Kind, &item.Error, &item.CreatedAt, &item.StartedAt, &item.FinishedAt); err != nil {
			return nil, err
		}
		items = append(items, item)
	}
	return items, rows.Err()
}

func (s *Store) CancelDatabaseRestore(ctx context.Context, organizationID, id uuid.UUID) error {
	tx, err := s.Pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	var resourceStatus, jobStatus string
	var jobID uuid.UUID
	err = tx.QueryRow(ctx, `SELECT r.status,j.status,j.id FROM database_restores r JOIN database_backups b ON b.id=r.database_backup_id JOIN database_instances d ON d.id=b.database_instance_id JOIN environments e ON e.id=d.environment_id JOIN projects p ON p.id=e.project_id JOIN jobs j ON j.kind='restore.database' AND j.payload->>'restoreId'=r.id::text WHERE r.id=$1 AND p.organization_id=$2 FOR UPDATE OF r,j`, id, organizationID).Scan(&resourceStatus, &jobStatus, &jobID)
	if errors.Is(err, pgx.ErrNoRows) {
		return ErrNotFound
	}
	if err != nil {
		return err
	}
	if err = cancelDatabaseJob(ctx, tx, "database_restores", id, jobID, resourceStatus, jobStatus); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

func cancelDatabaseJob(ctx context.Context, tx pgx.Tx, table string, resourceID, jobID uuid.UUID, resourceStatus, jobStatus string) error {
	switch jobStatus {
	case "pending":
		query := `UPDATE database_backups SET status='cancelled',error='cancelled by user',finished_at=now() WHERE id=$1`
		if table == "database_restores" {
			query = `UPDATE database_restores SET status='cancelled',error='cancelled by user',finished_at=now() WHERE id=$1`
		}
		if _, err := tx.Exec(ctx, query, resourceID); err != nil {
			return err
		}
		_, err := tx.Exec(ctx, `UPDATE jobs SET status='cancelled',cancel_requested_at=now(),finished_at=now() WHERE id=$1`, jobID)
		return err
	case "running":
		if resourceStatus != "running" {
			return ErrNotCancellable
		}
		_, err := tx.Exec(ctx, `UPDATE jobs SET cancel_requested_at=COALESCE(cancel_requested_at,now()) WHERE id=$1`, jobID)
		return err
	default:
		return ErrNotCancellable
	}
}
