package store

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

type VolumeBackupPolicy struct {
	ID               uuid.UUID  `json:"id"`
	ComposeServiceID uuid.UUID  `json:"composeServiceId"`
	VolumeName       string     `json:"volumeName"`
	DestinationID    uuid.UUID  `json:"destinationId"`
	IntervalSeconds  int        `json:"intervalSeconds"`
	RetentionCount   int        `json:"retentionCount"`
	Quiesce          bool       `json:"quiesce"`
	Enabled          bool       `json:"enabled"`
	NextRunAt        time.Time  `json:"nextRunAt"`
	LastRunAt        *time.Time `json:"lastRunAt,omitempty"`
	CreatedAt        time.Time  `json:"createdAt"`
	UpdatedAt        time.Time  `json:"updatedAt"`
}

type VolumeBackup struct {
	ID                   uuid.UUID  `json:"id"`
	VolumeBackupPolicyID *uuid.UUID `json:"volumeBackupPolicyId,omitempty"`
	ComposeServiceID     uuid.UUID  `json:"composeServiceId"`
	VolumeName           string     `json:"volumeName"`
	StorageNodeID        string     `json:"storageNodeId"`
	DestinationID        uuid.UUID  `json:"destinationId"`
	Quiesce              bool       `json:"quiesce"`
	Status               string     `json:"status"`
	ObjectKey            string     `json:"objectKey,omitempty"`
	SizeBytes            *int64     `json:"sizeBytes,omitempty"`
	SHA256               string     `json:"sha256,omitempty"`
	PlaintextSHA256      string     `json:"plaintextSha256,omitempty"`
	EncryptedDataKey     string     `json:"-"`
	Error                string     `json:"error,omitempty"`
	CreatedAt            time.Time  `json:"createdAt"`
	StartedAt            *time.Time `json:"startedAt,omitempty"`
	FinishedAt           *time.Time `json:"finishedAt,omitempty"`
}

type VolumeRestore struct {
	ID             uuid.UUID  `json:"id"`
	VolumeBackupID uuid.UUID  `json:"volumeBackupId"`
	Status         string     `json:"status"`
	Error          string     `json:"error,omitempty"`
	CreatedAt      time.Time  `json:"createdAt"`
	StartedAt      *time.Time `json:"startedAt,omitempty"`
	FinishedAt     *time.Time `json:"finishedAt,omitempty"`
}

func (s *Store) UpsertVolumeBackupPolicy(ctx context.Context, organizationID, serviceID uuid.UUID, volumeName, nodeID string, destinationID uuid.UUID, intervalSeconds, retentionCount int, quiesce, enabled bool) (VolumeBackupPolicy, error) {
	tx, err := s.Pool.Begin(ctx)
	if err != nil {
		return VolumeBackupPolicy{}, err
	}
	defer tx.Rollback(ctx)
	var lockedID uuid.UUID
	var composeYAML string
	if err = tx.QueryRow(ctx, `SELECT s.id,s.compose_yaml FROM compose_services s JOIN environments e ON e.id=s.environment_id JOIN projects p ON p.id=e.project_id WHERE s.id=$1 AND s.deletion_requested_at IS NULL AND p.organization_id=$2 AND EXISTS(SELECT 1 FROM backup_destinations d WHERE d.id=$3 AND d.organization_id=$2) FOR UPDATE OF s`, serviceID, organizationID, destinationID).Scan(&lockedID, &composeYAML); errors.Is(err, pgx.ErrNoRows) {
		return VolumeBackupPolicy{}, ErrNotFound
	} else if err != nil {
		return VolumeBackupPolicy{}, err
	}
	volumes, err := mountedNamedVolumesFromCompose(composeYAML)
	if err != nil {
		return VolumeBackupPolicy{}, err
	}
	declared := false
	for _, name := range volumes {
		if name == volumeName {
			declared = true
			break
		}
	}
	if !declared {
		return VolumeBackupPolicy{}, fmt.Errorf("%w: %s", ErrVolumeNotDeclared, volumeName)
	}
	tag, err := tx.Exec(ctx, `UPDATE compose_services SET storage_node_id=$2,updated_at=now() WHERE id=$1 AND (storage_node_id='' OR storage_node_id=$2)`, serviceID, nodeID)
	if err != nil {
		return VolumeBackupPolicy{}, err
	}
	if tag.RowsAffected() != 1 {
		return VolumeBackupPolicy{}, ErrStorageNodeMismatch
	}
	var item VolumeBackupPolicy
	err = tx.QueryRow(ctx, `INSERT INTO volume_backup_policies(id,compose_service_id,volume_name,destination_id,interval_seconds,retention_count,quiesce,enabled,next_run_at)
		VALUES($1,$2,$3,$4,$5,$6,$7,$8,now()+($5::int * interval '1 second'))
		ON CONFLICT(compose_service_id,volume_name) DO UPDATE SET destination_id=excluded.destination_id,interval_seconds=excluded.interval_seconds,retention_count=excluded.retention_count,quiesce=excluded.quiesce,enabled=excluded.enabled,next_run_at=CASE WHEN volume_backup_policies.enabled=false AND excluded.enabled=true THEN now()+(excluded.interval_seconds * interval '1 second') ELSE volume_backup_policies.next_run_at END,updated_at=now()
		RETURNING id,compose_service_id,volume_name,destination_id,interval_seconds,retention_count,quiesce,enabled,next_run_at,last_run_at,created_at,updated_at`, uuid.New(), serviceID, volumeName, destinationID, intervalSeconds, retentionCount, quiesce, enabled).Scan(&item.ID, &item.ComposeServiceID, &item.VolumeName, &item.DestinationID, &item.IntervalSeconds, &item.RetentionCount, &item.Quiesce, &item.Enabled, &item.NextRunAt, &item.LastRunAt, &item.CreatedAt, &item.UpdatedAt)
	if err != nil {
		return VolumeBackupPolicy{}, err
	}
	return item, tx.Commit(ctx)
}

func (s *Store) ListVolumeBackupPolicies(ctx context.Context, organizationID, serviceID uuid.UUID) ([]VolumeBackupPolicy, error) {
	rows, err := s.Pool.Query(ctx, `SELECT policy.id,policy.compose_service_id,policy.volume_name,policy.destination_id,policy.interval_seconds,policy.retention_count,policy.quiesce,policy.enabled,policy.next_run_at,policy.last_run_at,policy.created_at,policy.updated_at FROM volume_backup_policies policy JOIN compose_services service ON service.id=policy.compose_service_id JOIN environments e ON e.id=service.environment_id JOIN projects p ON p.id=e.project_id WHERE service.id=$1 AND p.organization_id=$2 ORDER BY policy.volume_name`, serviceID, organizationID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	items := []VolumeBackupPolicy{}
	for rows.Next() {
		var item VolumeBackupPolicy
		if err = rows.Scan(&item.ID, &item.ComposeServiceID, &item.VolumeName, &item.DestinationID, &item.IntervalSeconds, &item.RetentionCount, &item.Quiesce, &item.Enabled, &item.NextRunAt, &item.LastRunAt, &item.CreatedAt, &item.UpdatedAt); err != nil {
			return nil, err
		}
		items = append(items, item)
	}
	return items, rows.Err()
}

func (s *Store) DeleteVolumeBackupPolicy(ctx context.Context, organizationID, serviceID uuid.UUID, volumeName string) error {
	tx, err := s.Pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	var policyID uuid.UUID
	err = tx.QueryRow(ctx, `SELECT policy.id FROM volume_backup_policies policy JOIN compose_services service ON service.id=policy.compose_service_id JOIN environments e ON e.id=service.environment_id JOIN projects p ON p.id=e.project_id WHERE policy.compose_service_id=$1 AND policy.volume_name=$2 AND p.organization_id=$3 FOR UPDATE OF service,policy`, serviceID, volumeName, organizationID).Scan(&policyID)
	if errors.Is(err, pgx.ErrNoRows) {
		return ErrNotFound
	}
	if err != nil {
		return err
	}
	var busy bool
	err = tx.QueryRow(ctx, `SELECT
		EXISTS(SELECT 1 FROM volume_backups backup WHERE backup.compose_service_id=$1 AND backup.volume_name=$2 AND backup.status IN ('queued','running'))
		OR EXISTS(SELECT 1 FROM volume_restores restore JOIN volume_backups backup ON backup.id=restore.volume_backup_id WHERE backup.compose_service_id=$1 AND backup.volume_name=$2 AND restore.status IN ('queued','running'))
		OR EXISTS(SELECT 1 FROM jobs job JOIN volume_backups backup ON job.payload->>'backupId'=backup.id::text WHERE job.resource_key=$3 AND job.kind='backup.volume' AND job.status IN ('pending','running') AND backup.compose_service_id=$1 AND backup.volume_name=$2)
		OR EXISTS(SELECT 1 FROM jobs job JOIN volume_restores restore ON job.payload->>'restoreId'=restore.id::text JOIN volume_backups backup ON backup.id=restore.volume_backup_id WHERE job.resource_key=$3 AND job.kind='restore.volume' AND job.status IN ('pending','running') AND backup.compose_service_id=$1 AND backup.volume_name=$2)`, serviceID, volumeName, "service:"+serviceID.String()).Scan(&busy)
	if err != nil {
		return err
	}
	if busy {
		return ErrBusy
	}
	tag, err := tx.Exec(ctx, `DELETE FROM volume_backup_policies WHERE id=$1`, policyID)
	if err != nil {
		return err
	}
	if tag.RowsAffected() != 1 {
		return ErrNotFound
	}
	return tx.Commit(ctx)
}

func (s *Store) QueueVolumeBackup(ctx context.Context, organizationID, serviceID uuid.UUID, volumeName string, actorID uuid.UUID) (VolumeBackup, error) {
	tx, err := s.Pool.Begin(ctx)
	if err != nil {
		return VolumeBackup{}, err
	}
	defer tx.Rollback(ctx)
	var policyID, destinationID uuid.UUID
	var nodeID string
	var quiesce bool
	var deleting bool
	var desiredState string
	var retentionCount int
	err = tx.QueryRow(ctx, `SELECT policy.id,policy.destination_id,service.storage_node_id,policy.quiesce,policy.retention_count,service.deletion_requested_at IS NOT NULL,service.desired_state FROM volume_backup_policies policy JOIN compose_services service ON service.id=policy.compose_service_id JOIN environments e ON e.id=service.environment_id JOIN projects p ON p.id=e.project_id WHERE service.id=$1 AND policy.volume_name=$2 AND p.organization_id=$3 FOR UPDATE OF service,policy`, serviceID, volumeName, organizationID).Scan(&policyID, &destinationID, &nodeID, &quiesce, &retentionCount, &deleting, &desiredState)
	if errors.Is(err, pgx.ErrNoRows) {
		return VolumeBackup{}, ErrNotFound
	}
	if err != nil {
		return VolumeBackup{}, err
	}
	if deleting {
		return VolumeBackup{}, ErrDeleting
	}
	if desiredState != "running" {
		return VolumeBackup{}, ErrServiceStopped
	}
	if nodeID == "" {
		return VolumeBackup{}, errors.New("service storage node has not been assigned")
	}
	var active bool
	if err = tx.QueryRow(ctx, `SELECT
		EXISTS(SELECT 1 FROM volume_backups WHERE compose_service_id=$1 AND volume_name=$2 AND status IN ('queued','running'))
		OR EXISTS(SELECT 1 FROM jobs WHERE resource_key=$3 AND kind='backup.volume' AND status IN ('pending','running'))`, serviceID, volumeName, "service:"+serviceID.String()).Scan(&active); err != nil {
		return VolumeBackup{}, err
	}
	if active {
		return VolumeBackup{}, ErrBusy
	}
	item := VolumeBackup{ID: uuid.New(), VolumeBackupPolicyID: &policyID, ComposeServiceID: serviceID, VolumeName: volumeName, StorageNodeID: nodeID, DestinationID: destinationID, Quiesce: quiesce, Status: "queued"}
	if err = tx.QueryRow(ctx, `INSERT INTO volume_backups(id,volume_backup_policy_id,compose_service_id,volume_name,storage_node_id,destination_id,quiesce,status,actor_user_id) VALUES($1,$2,$3,$4,$5,$6,$7,'queued',$8) RETURNING created_at`, item.ID, policyID, serviceID, volumeName, nodeID, destinationID, quiesce, nullableUUID(actorID)).Scan(&item.CreatedAt); err != nil {
		return VolumeBackup{}, err
	}
	payload, _ := json.Marshal(map[string]any{"backupId": item.ID.String(), "retentionCount": retentionCount})
	if _, err = tx.Exec(ctx, `INSERT INTO jobs(id,kind,payload,resource_key) VALUES($1,'backup.volume',$2,$3)`, uuid.New(), payload, "service:"+serviceID.String()); err != nil {
		return VolumeBackup{}, err
	}
	return item, tx.Commit(ctx)
}

func (s *Store) ListVolumeBackups(ctx context.Context, organizationID, serviceID uuid.UUID) ([]VolumeBackup, error) {
	rows, err := s.Pool.Query(ctx, `SELECT backup.id,backup.volume_backup_policy_id,backup.compose_service_id,backup.volume_name,backup.storage_node_id,backup.destination_id,backup.quiesce,backup.status,backup.object_key,backup.size_bytes,backup.sha256,backup.plaintext_sha256,backup.error,backup.created_at,backup.started_at,backup.finished_at FROM volume_backups backup JOIN compose_services service ON service.id=backup.compose_service_id JOIN environments e ON e.id=service.environment_id JOIN projects p ON p.id=e.project_id WHERE service.id=$1 AND p.organization_id=$2 ORDER BY backup.created_at DESC LIMIT 100`, serviceID, organizationID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	items := []VolumeBackup{}
	for rows.Next() {
		var item VolumeBackup
		if err = rows.Scan(&item.ID, &item.VolumeBackupPolicyID, &item.ComposeServiceID, &item.VolumeName, &item.StorageNodeID, &item.DestinationID, &item.Quiesce, &item.Status, &item.ObjectKey, &item.SizeBytes, &item.SHA256, &item.PlaintextSHA256, &item.Error, &item.CreatedAt, &item.StartedAt, &item.FinishedAt); err != nil {
			return nil, err
		}
		items = append(items, item)
	}
	return items, rows.Err()
}

func (s *Store) GetVolumeBackup(ctx context.Context, organizationID, id uuid.UUID, includeSecret bool) (VolumeBackup, error) {
	var item VolumeBackup
	err := s.Pool.QueryRow(ctx, `SELECT backup.id,backup.volume_backup_policy_id,backup.compose_service_id,backup.volume_name,backup.storage_node_id,backup.destination_id,backup.quiesce,backup.status,backup.object_key,backup.size_bytes,backup.sha256,backup.plaintext_sha256,CASE WHEN $3 THEN backup.encrypted_data_key ELSE '' END,backup.error,backup.created_at,backup.started_at,backup.finished_at FROM volume_backups backup JOIN compose_services service ON service.id=backup.compose_service_id JOIN environments e ON e.id=service.environment_id JOIN projects p ON p.id=e.project_id WHERE backup.id=$1 AND p.organization_id=$2`, id, organizationID, includeSecret).Scan(&item.ID, &item.VolumeBackupPolicyID, &item.ComposeServiceID, &item.VolumeName, &item.StorageNodeID, &item.DestinationID, &item.Quiesce, &item.Status, &item.ObjectKey, &item.SizeBytes, &item.SHA256, &item.PlaintextSHA256, &item.EncryptedDataKey, &item.Error, &item.CreatedAt, &item.StartedAt, &item.FinishedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return VolumeBackup{}, ErrNotFound
	}
	return item, err
}

func (s *Store) QueueVolumeRestore(ctx context.Context, organizationID, backupID, actorID uuid.UUID, confirmation string) (VolumeRestore, error) {
	tx, err := s.Pool.Begin(ctx)
	if err != nil {
		return VolumeRestore{}, err
	}
	defer tx.Rollback(ctx)
	var serviceID uuid.UUID
	var slug, status string
	var deleting bool
	var desiredState string
	err = tx.QueryRow(ctx, `SELECT service.id,service.slug,backup.status,service.deletion_requested_at IS NOT NULL,service.desired_state FROM volume_backups backup JOIN compose_services service ON service.id=backup.compose_service_id JOIN environments e ON e.id=service.environment_id JOIN projects p ON p.id=e.project_id WHERE backup.id=$1 AND p.organization_id=$2 FOR UPDATE OF service,backup`, backupID, organizationID).Scan(&serviceID, &slug, &status, &deleting, &desiredState)
	if errors.Is(err, pgx.ErrNoRows) {
		return VolumeRestore{}, ErrNotFound
	}
	if err != nil {
		return VolumeRestore{}, err
	}
	if deleting {
		return VolumeRestore{}, ErrDeleting
	}
	if desiredState != "running" {
		return VolumeRestore{}, ErrServiceStopped
	}
	if status != "succeeded" {
		return VolumeRestore{}, errors.New("volume backup is not restorable")
	}
	if confirmation != slug {
		return VolumeRestore{}, errors.New("restore confirmation must match service slug")
	}
	var active bool
	if err = tx.QueryRow(ctx, `SELECT
		EXISTS(SELECT 1 FROM volume_restores restore JOIN volume_backups backup ON backup.id=restore.volume_backup_id WHERE backup.compose_service_id=$1 AND restore.status IN ('queued','running'))
		OR EXISTS(SELECT 1 FROM jobs WHERE resource_key=$2 AND kind='restore.volume' AND status IN ('pending','running'))`, serviceID, "service:"+serviceID.String()).Scan(&active); err != nil {
		return VolumeRestore{}, err
	}
	if active {
		return VolumeRestore{}, ErrBusy
	}
	item := VolumeRestore{ID: uuid.New(), VolumeBackupID: backupID, Status: "queued"}
	if err = tx.QueryRow(ctx, `INSERT INTO volume_restores(id,volume_backup_id,status,actor_user_id) VALUES($1,$2,'queued',$3) RETURNING created_at`, item.ID, backupID, nullableUUID(actorID)).Scan(&item.CreatedAt); err != nil {
		return VolumeRestore{}, err
	}
	payload, _ := json.Marshal(map[string]string{"restoreId": item.ID.String()})
	if _, err = tx.Exec(ctx, `INSERT INTO jobs(id,kind,payload,resource_key) VALUES($1,'restore.volume',$2,$3)`, uuid.New(), payload, "service:"+serviceID.String()); err != nil {
		return VolumeRestore{}, err
	}
	return item, tx.Commit(ctx)
}

func (s *Store) GetVolumeRestore(ctx context.Context, organizationID, id uuid.UUID) (VolumeRestore, error) {
	var item VolumeRestore
	err := s.Pool.QueryRow(ctx, `SELECT restore.id,restore.volume_backup_id,restore.status,restore.error,restore.created_at,restore.started_at,restore.finished_at FROM volume_restores restore JOIN volume_backups backup ON backup.id=restore.volume_backup_id JOIN compose_services service ON service.id=backup.compose_service_id JOIN environments e ON e.id=service.environment_id JOIN projects p ON p.id=e.project_id WHERE restore.id=$1 AND p.organization_id=$2`, id, organizationID).Scan(&item.ID, &item.VolumeBackupID, &item.Status, &item.Error, &item.CreatedAt, &item.StartedAt, &item.FinishedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return VolumeRestore{}, ErrNotFound
	}
	return item, err
}

func (s *Store) ListVolumeRestores(ctx context.Context, organizationID, serviceID uuid.UUID) ([]VolumeRestore, error) {
	rows, err := s.Pool.Query(ctx, `SELECT restore.id,restore.volume_backup_id,restore.status,restore.error,restore.created_at,restore.started_at,restore.finished_at FROM volume_restores restore JOIN volume_backups backup ON backup.id=restore.volume_backup_id JOIN compose_services service ON service.id=backup.compose_service_id JOIN environments e ON e.id=service.environment_id JOIN projects p ON p.id=e.project_id WHERE service.id=$1 AND p.organization_id=$2 ORDER BY restore.created_at DESC LIMIT 100`, serviceID, organizationID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	items := []VolumeRestore{}
	for rows.Next() {
		var item VolumeRestore
		if err = rows.Scan(&item.ID, &item.VolumeBackupID, &item.Status, &item.Error, &item.CreatedAt, &item.StartedAt, &item.FinishedAt); err != nil {
			return nil, err
		}
		items = append(items, item)
	}
	return items, rows.Err()
}

func (s *Store) CancelVolumeBackup(ctx context.Context, organizationID, id uuid.UUID) error {
	return s.cancelVolumeJob(ctx, organizationID, id, "backup.volume", "volume_backups", "backupId", `JOIN compose_services service ON service.id=resource.compose_service_id`)
}

func (s *Store) CancelVolumeRestore(ctx context.Context, organizationID, id uuid.UUID) error {
	return s.cancelVolumeJob(ctx, organizationID, id, "restore.volume", "volume_restores", "restoreId", `JOIN volume_backups backup ON backup.id=resource.volume_backup_id JOIN compose_services service ON service.id=backup.compose_service_id`)
}

func (s *Store) cancelVolumeJob(ctx context.Context, organizationID, id uuid.UUID, kind, table, payloadKey, resourceJoin string) error {
	if table != "volume_backups" && table != "volume_restores" {
		return errors.New("invalid volume job resource")
	}
	tx, err := s.Pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	query := `SELECT resource.status,job.status,job.id FROM ` + table + ` resource ` + resourceJoin + ` JOIN environments environment ON environment.id=service.environment_id JOIN projects project ON project.id=environment.project_id JOIN jobs job ON job.kind=$3 AND job.payload->>$4=resource.id::text WHERE resource.id=$1 AND project.organization_id=$2 FOR UPDATE OF resource,job`
	var resourceStatus, jobStatus string
	var jobID uuid.UUID
	if err = tx.QueryRow(ctx, query, id, organizationID, kind, payloadKey).Scan(&resourceStatus, &jobStatus, &jobID); errors.Is(err, pgx.ErrNoRows) {
		return ErrNotFound
	} else if err != nil {
		return err
	}
	switch jobStatus {
	case "pending":
		if _, err = tx.Exec(ctx, `UPDATE `+table+` SET status='cancelled',error='cancelled by user',finished_at=now() WHERE id=$1`, id); err != nil {
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
