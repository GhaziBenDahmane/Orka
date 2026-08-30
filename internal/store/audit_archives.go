package store

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

type AuditArchiveDestination struct {
	ID                  uuid.UUID `json:"id"`
	OrganizationID      uuid.UUID `json:"organizationId"`
	BackupDestinationID uuid.UUID `json:"backupDestinationId"`
	Name                string    `json:"name"`
	ObjectPrefix        string    `json:"objectPrefix"`
	RetentionDays       int       `json:"retentionDays"`
	Enabled             bool      `json:"enabled"`
	LastArchivedID      int64     `json:"lastArchivedId"`
	LastChainHash       string    `json:"lastChainHash,omitempty"`
	CreatedAt           time.Time `json:"createdAt"`
	UpdatedAt           time.Time `json:"updatedAt"`
}

type AuditArchiveBatch struct {
	ID                uuid.UUID         `json:"id"`
	DestinationID     uuid.UUID         `json:"destinationId"`
	OrganizationID    uuid.UUID         `json:"organizationId"`
	FirstEventID      int64             `json:"firstEventId"`
	LastEventID       int64             `json:"lastEventId"`
	PreviousSHA256    string            `json:"previousSha256"`
	SHA256            string            `json:"sha256,omitempty"`
	ObjectKey         string            `json:"objectKey"`
	SizeBytes         *int64            `json:"sizeBytes,omitempty"`
	Status            string            `json:"status"`
	LastError         string            `json:"lastError,omitempty"`
	RetentionDays     int               `json:"retentionDays,omitempty"`
	CreatedAt         time.Time         `json:"createdAt"`
	StartedAt         *time.Time        `json:"startedAt,omitempty"`
	FinishedAt        *time.Time        `json:"finishedAt,omitempty"`
	BackupDestination BackupDestination `json:"-"`
}

func (s *Store) CreateAuditArchiveDestination(ctx context.Context, item AuditArchiveDestination) (AuditArchiveDestination, error) {
	if item.ID == uuid.Nil {
		item.ID = uuid.New()
	}
	err := s.Pool.QueryRow(ctx, `INSERT INTO audit_archive_destinations(id,organization_id,backup_destination_id,name,object_prefix,retention_days)
		SELECT $1,$2,b.id,$4,$5,$6 FROM backup_destinations b WHERE b.id=$3 AND b.organization_id=$2 AND b.use_tls
		RETURNING enabled,last_archived_id,last_chain_hash,created_at,updated_at`, item.ID, item.OrganizationID, item.BackupDestinationID, item.Name, item.ObjectPrefix, item.RetentionDays).Scan(&item.Enabled, &item.LastArchivedID, &item.LastChainHash, &item.CreatedAt, &item.UpdatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return AuditArchiveDestination{}, ErrNotFound
	}
	return item, err
}

func (s *Store) ListAuditArchiveDestinations(ctx context.Context, organizationID uuid.UUID) ([]AuditArchiveDestination, error) {
	rows, err := s.Pool.Query(ctx, `SELECT id,organization_id,backup_destination_id,name,object_prefix,retention_days,enabled,last_archived_id,last_chain_hash,created_at,updated_at FROM audit_archive_destinations WHERE organization_id=$1 ORDER BY name`, organizationID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	items := []AuditArchiveDestination{}
	for rows.Next() {
		var item AuditArchiveDestination
		if err = rows.Scan(&item.ID, &item.OrganizationID, &item.BackupDestinationID, &item.Name, &item.ObjectPrefix, &item.RetentionDays, &item.Enabled, &item.LastArchivedID, &item.LastChainHash, &item.CreatedAt, &item.UpdatedAt); err != nil {
			return nil, err
		}
		items = append(items, item)
	}
	return items, rows.Err()
}

func (s *Store) GetAuditArchiveDestination(ctx context.Context, organizationID, id uuid.UUID) (AuditArchiveDestination, error) {
	var item AuditArchiveDestination
	err := s.Pool.QueryRow(ctx, `SELECT id,organization_id,backup_destination_id,name,object_prefix,retention_days,enabled,last_archived_id,last_chain_hash,created_at,updated_at FROM audit_archive_destinations WHERE id=$1 AND organization_id=$2`, id, organizationID).Scan(
		&item.ID, &item.OrganizationID, &item.BackupDestinationID, &item.Name, &item.ObjectPrefix, &item.RetentionDays, &item.Enabled, &item.LastArchivedID, &item.LastChainHash, &item.CreatedAt, &item.UpdatedAt,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return AuditArchiveDestination{}, ErrNotFound
	}
	return item, err
}

func (s *Store) DisableAuditArchiveDestination(ctx context.Context, organizationID, id uuid.UUID) error {
	tx, err := s.Pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	tag, err := tx.Exec(ctx, `UPDATE audit_archive_destinations SET enabled=false,updated_at=now() WHERE id=$1 AND organization_id=$2`, id, organizationID)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	if _, err = tx.Exec(ctx, `UPDATE jobs SET status='cancelled',cancel_requested_at=now(),finished_at=now() WHERE kind='audit.archive' AND status='pending' AND payload->>'batchId' IN (SELECT id::text FROM audit_archive_batches WHERE destination_id=$1)`, id); err != nil {
		return err
	}
	if _, err = tx.Exec(ctx, `UPDATE audit_archive_batches SET status='failed',last_error='archive disabled',finished_at=now() WHERE destination_id=$1 AND status='pending'`, id); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

func (s *Store) QueueNextAuditArchive(ctx context.Context) (AuditArchiveBatch, error) {
	return s.queueAuditArchive(ctx, uuid.Nil, uuid.Nil)
}

func (s *Store) QueueAuditArchive(ctx context.Context, organizationID, destinationID uuid.UUID) (AuditArchiveBatch, error) {
	return s.queueAuditArchive(ctx, organizationID, destinationID)
}

func (s *Store) queueAuditArchive(ctx context.Context, organizationID, destinationID uuid.UUID) (AuditArchiveBatch, error) {
	tx, err := s.Pool.Begin(ctx)
	if err != nil {
		return AuditArchiveBatch{}, err
	}
	defer tx.Rollback(ctx)
	var destination AuditArchiveDestination
	query := `SELECT id,organization_id,object_prefix,retention_days,last_archived_id,last_chain_hash FROM audit_archive_destinations a
		WHERE enabled AND ($1::uuid='00000000-0000-0000-0000-000000000000' OR organization_id=$1) AND ($2::uuid='00000000-0000-0000-0000-000000000000' OR id=$2)
		AND NOT EXISTS(SELECT 1 FROM audit_archive_batches b WHERE b.destination_id=a.id AND b.status<>'succeeded')
		AND EXISTS(SELECT 1 FROM audit_events e WHERE e.organization_id=a.organization_id AND e.id>a.last_archived_id)
		ORDER BY updated_at FOR UPDATE SKIP LOCKED LIMIT 1`
	if err = tx.QueryRow(ctx, query, organizationID, destinationID).Scan(&destination.ID, &destination.OrganizationID, &destination.ObjectPrefix, &destination.RetentionDays, &destination.LastArchivedID, &destination.LastChainHash); errors.Is(err, pgx.ErrNoRows) {
		if destinationID != uuid.Nil {
			var retry AuditArchiveBatch
			retryErr := tx.QueryRow(ctx, `SELECT b.id,b.destination_id,a.organization_id,b.first_event_id,b.last_event_id,b.previous_sha256,b.object_key,a.retention_days,b.created_at FROM audit_archive_batches b JOIN audit_archive_destinations a ON a.id=b.destination_id WHERE b.destination_id=$1 AND a.organization_id=$2 AND a.enabled AND b.status='failed' AND NOT EXISTS(SELECT 1 FROM jobs j WHERE j.kind='audit.archive' AND j.payload->>'batchId'=b.id::text AND j.status IN ('pending','running')) ORDER BY b.created_at LIMIT 1 FOR UPDATE OF b`, destinationID, organizationID).Scan(&retry.ID, &retry.DestinationID, &retry.OrganizationID, &retry.FirstEventID, &retry.LastEventID, &retry.PreviousSHA256, &retry.ObjectKey, &retry.RetentionDays, &retry.CreatedAt)
			if retryErr == nil {
				if _, err = tx.Exec(ctx, `UPDATE audit_archive_batches SET status='pending',last_error='',started_at=NULL,finished_at=NULL WHERE id=$1`, retry.ID); err != nil {
					return AuditArchiveBatch{}, err
				}
				payload, _ := json.Marshal(map[string]string{"batchId": retry.ID.String()})
				if _, err = tx.Exec(ctx, `INSERT INTO jobs(id,kind,payload,max_attempts) VALUES($1,'audit.archive',$2,12)`, uuid.New(), payload); err != nil {
					return AuditArchiveBatch{}, err
				}
				retry.Status = "pending"
				return retry, tx.Commit(ctx)
			}
			if retryErr != nil && !errors.Is(retryErr, pgx.ErrNoRows) {
				return AuditArchiveBatch{}, retryErr
			}
			var exists bool
			if checkErr := tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM audit_archive_destinations WHERE id=$1 AND organization_id=$2)`, destinationID, organizationID).Scan(&exists); checkErr != nil {
				return AuditArchiveBatch{}, checkErr
			}
			if exists {
				return AuditArchiveBatch{}, ErrBusy
			}
		}
		return AuditArchiveBatch{}, ErrNotFound
	} else if err != nil {
		return AuditArchiveBatch{}, err
	}
	var firstID, lastID int64
	if err = tx.QueryRow(ctx, `SELECT min(id),max(id) FROM (SELECT id FROM audit_events WHERE organization_id=$1 AND id>$2 ORDER BY id LIMIT 1000) events`, destination.OrganizationID, destination.LastArchivedID).Scan(&firstID, &lastID); err != nil {
		return AuditArchiveBatch{}, err
	}
	item := AuditArchiveBatch{ID: uuid.New(), DestinationID: destination.ID, OrganizationID: destination.OrganizationID, FirstEventID: firstID, LastEventID: lastID, PreviousSHA256: destination.LastChainHash, RetentionDays: destination.RetentionDays, Status: "pending"}
	item.ObjectKey = strings.Trim(destination.ObjectPrefix, "/") + "/" + destination.OrganizationID.String() + "/" + time.Now().UTC().Format("2006/01/02") + "/" + item.ID.String() + ".ndjson"
	if err = tx.QueryRow(ctx, `INSERT INTO audit_archive_batches(id,destination_id,first_event_id,last_event_id,previous_sha256,object_key) VALUES($1,$2,$3,$4,$5,$6) RETURNING created_at`, item.ID, item.DestinationID, item.FirstEventID, item.LastEventID, item.PreviousSHA256, item.ObjectKey).Scan(&item.CreatedAt); err != nil {
		return AuditArchiveBatch{}, err
	}
	payload, _ := json.Marshal(map[string]string{"batchId": item.ID.String()})
	if _, err = tx.Exec(ctx, `INSERT INTO jobs(id,kind,payload,max_attempts) VALUES($1,'audit.archive',$2,12)`, uuid.New(), payload); err != nil {
		return AuditArchiveBatch{}, err
	}
	return item, tx.Commit(ctx)
}

func (s *Store) GetAuditArchiveBatchForJob(ctx context.Context, jobID, leaseID, id uuid.UUID) (AuditArchiveBatch, error) {
	var item AuditArchiveBatch
	err := s.WithJobLease(ctx, jobID, leaseID, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `UPDATE audit_archive_batches b SET status='running',started_at=COALESCE(started_at,now()) FROM audit_archive_destinations a,backup_destinations d WHERE b.id=$1 AND a.id=b.destination_id AND d.id=a.backup_destination_id AND a.enabled RETURNING b.id,b.destination_id,a.organization_id,b.first_event_id,b.last_event_id,b.previous_sha256,b.object_key,a.retention_days,b.created_at,d.id,d.organization_id,d.name,d.endpoint,d.region,d.bucket,d.prefix,d.use_tls,d.encrypted_credentials,d.created_at,d.updated_at`, id).Scan(&item.ID, &item.DestinationID, &item.OrganizationID, &item.FirstEventID, &item.LastEventID, &item.PreviousSHA256, &item.ObjectKey, &item.RetentionDays, &item.CreatedAt, &item.BackupDestination.ID, &item.BackupDestination.OrganizationID, &item.BackupDestination.Name, &item.BackupDestination.Endpoint, &item.BackupDestination.Region, &item.BackupDestination.Bucket, &item.BackupDestination.Prefix, &item.BackupDestination.UseTLS, &item.BackupDestination.EncryptedCredentials, &item.BackupDestination.CreatedAt, &item.BackupDestination.UpdatedAt)
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return AuditArchiveBatch{}, ErrNotFound
	}
	return item, err
}

func (s *Store) FinishAuditArchiveBatch(ctx context.Context, id uuid.UUID, digest string, size int64, archiveErr error) error {
	tx, err := s.Pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	if err = finishAuditArchiveBatchTx(ctx, tx, id, digest, size, archiveErr); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

func (s *Store) FinishAuditArchiveBatchForJob(ctx context.Context, jobID, leaseID, id uuid.UUID, digest string, size int64, archiveErr error) error {
	return s.WithJobLease(ctx, jobID, leaseID, func(tx pgx.Tx) error {
		return finishAuditArchiveBatchTx(ctx, tx, id, digest, size, archiveErr)
	})
}

func finishAuditArchiveBatchTx(ctx context.Context, tx pgx.Tx, id uuid.UUID, digest string, size int64, archiveErr error) error {
	if archiveErr != nil {
		_, err := tx.Exec(ctx, `UPDATE audit_archive_batches SET status='failed',last_error=$2,finished_at=now() WHERE id=$1`, id, truncateStore(archiveErr.Error(), 8192))
		return err
	}
	var destinationID uuid.UUID
	var lastID int64
	var previous string
	if err := tx.QueryRow(ctx, `UPDATE audit_archive_batches SET status='succeeded',sha256=$2,size_bytes=$3,last_error='',finished_at=now() WHERE id=$1 RETURNING destination_id,last_event_id,previous_sha256`, id, digest, size).Scan(&destinationID, &lastID, &previous); err != nil {
		return err
	}
	tag, err := tx.Exec(ctx, `UPDATE audit_archive_destinations SET last_archived_id=$2,last_chain_hash=$3,updated_at=now() WHERE id=$1 AND last_archived_id<$2 AND last_chain_hash=$4`, destinationID, lastID, digest, previous)
	if err != nil {
		return err
	}
	if tag.RowsAffected() != 1 {
		return errors.New("audit archive chain checkpoint changed")
	}
	return nil
}

func (s *Store) ListAuditArchiveBatches(ctx context.Context, organizationID, destinationID uuid.UUID) ([]AuditArchiveBatch, error) {
	rows, err := s.Pool.Query(ctx, `SELECT b.id,b.destination_id,a.organization_id,b.first_event_id,b.last_event_id,b.previous_sha256,b.sha256,b.object_key,b.size_bytes,b.status,b.last_error,b.created_at,b.started_at,b.finished_at FROM audit_archive_batches b JOIN audit_archive_destinations a ON a.id=b.destination_id WHERE b.destination_id=$1 AND a.organization_id=$2 ORDER BY b.created_at DESC LIMIT 100`, destinationID, organizationID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	items := []AuditArchiveBatch{}
	for rows.Next() {
		var item AuditArchiveBatch
		if err = rows.Scan(&item.ID, &item.DestinationID, &item.OrganizationID, &item.FirstEventID, &item.LastEventID, &item.PreviousSHA256, &item.SHA256, &item.ObjectKey, &item.SizeBytes, &item.Status, &item.LastError, &item.CreatedAt, &item.StartedAt, &item.FinishedAt); err != nil {
			return nil, err
		}
		items = append(items, item)
	}
	return items, rows.Err()
}
