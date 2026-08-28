package store

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

type AuditEvent struct {
	ID                    int64           `json:"id"`
	ActorUserID           *uuid.UUID      `json:"actorUserId,omitempty"`
	ActorServiceAccountID *uuid.UUID      `json:"actorServiceAccountId,omitempty"`
	Action                string          `json:"action"`
	ResourceType          string          `json:"resourceType"`
	ResourceID            string          `json:"resourceId"`
	RemoteAddr            string          `json:"remoteAddr"`
	Metadata              json.RawMessage `json:"metadata"`
	CreatedAt             time.Time       `json:"createdAt"`
}

type AuditRetentionPolicy struct {
	OrganizationID uuid.UUID `json:"organizationId"`
	RetentionDays  int       `json:"retentionDays"`
	UpdatedAt      time.Time `json:"updatedAt"`
}

func (s *Store) ListAuditEvents(ctx context.Context, organizationID uuid.UUID, afterID int64, limit int, ascending bool) ([]AuditEvent, error) {
	if limit < 1 || limit > 10000 {
		limit = 200
	}
	comparison, ordering := "<", "DESC"
	if ascending {
		comparison, ordering = ">", "ASC"
		if afterID == 0 {
			afterID = -1
		}
	} else if afterID == 0 {
		afterID = 1<<63 - 1
	}
	rows, err := s.Pool.Query(ctx, `SELECT id,actor_user_id,actor_service_account_id,action,resource_type,resource_id,remote_addr,metadata,created_at FROM audit_events WHERE organization_id=$1 AND id `+comparison+` $2 ORDER BY id `+ordering+` LIMIT $3`, organizationID, afterID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	items := []AuditEvent{}
	for rows.Next() {
		var item AuditEvent
		if err = rows.Scan(&item.ID, &item.ActorUserID, &item.ActorServiceAccountID, &item.Action, &item.ResourceType, &item.ResourceID, &item.RemoteAddr, &item.Metadata, &item.CreatedAt); err != nil {
			return nil, err
		}
		items = append(items, item)
	}
	return items, rows.Err()
}

func (s *Store) GetAuditRetentionPolicy(ctx context.Context, organizationID uuid.UUID) (AuditRetentionPolicy, error) {
	item := AuditRetentionPolicy{OrganizationID: organizationID, RetentionDays: 365}
	err := s.Pool.QueryRow(ctx, `SELECT retention_days,updated_at FROM audit_retention_policies WHERE organization_id=$1`, organizationID).Scan(&item.RetentionDays, &item.UpdatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		if err = s.Pool.QueryRow(ctx, `SELECT created_at FROM organizations WHERE id=$1`, organizationID).Scan(&item.UpdatedAt); errors.Is(err, pgx.ErrNoRows) {
			return AuditRetentionPolicy{}, ErrNotFound
		}
		return item, err
	}
	return item, err
}

func (s *Store) UpsertAuditRetentionPolicy(ctx context.Context, organizationID uuid.UUID, days int) (AuditRetentionPolicy, error) {
	if days < 30 || days > 3650 {
		return AuditRetentionPolicy{}, errors.New("retention days must be between 30 and 3650")
	}
	item := AuditRetentionPolicy{OrganizationID: organizationID, RetentionDays: days}
	err := s.Pool.QueryRow(ctx, `INSERT INTO audit_retention_policies(organization_id,retention_days) SELECT id,$2 FROM organizations WHERE id=$1 ON CONFLICT(organization_id) DO UPDATE SET retention_days=excluded.retention_days,updated_at=now() RETURNING updated_at`, organizationID, days).Scan(&item.UpdatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return AuditRetentionPolicy{}, ErrNotFound
	}
	return item, err
}

func (s *Store) PruneAuditEvents(ctx context.Context) (int64, error) {
	tag, err := s.Pool.Exec(ctx, `DELETE FROM audit_events a USING audit_retention_policies p WHERE a.organization_id=p.organization_id AND a.created_at < now()-(p.retention_days * interval '1 day')`)
	return tag.RowsAffected(), err
}
