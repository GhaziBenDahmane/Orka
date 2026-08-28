package store

import (
	"context"

	"github.com/google/uuid"
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
