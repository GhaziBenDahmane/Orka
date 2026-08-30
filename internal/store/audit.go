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
	tag, err := s.Pool.Exec(ctx, `DELETE FROM audit_events a WHERE a.created_at < now()-(COALESCE((SELECT p.retention_days FROM audit_retention_policies p WHERE p.organization_id=a.organization_id),365) * interval '1 day') AND (NOT EXISTS(SELECT 1 FROM audit_archive_destinations d WHERE d.organization_id=a.organization_id AND d.enabled) OR a.id<=(SELECT min(d.last_archived_id) FROM audit_archive_destinations d WHERE d.organization_id=a.organization_id AND d.enabled))`)
	return tag.RowsAffected(), err
}

func (s *Store) PruneAIAuditRuns(ctx context.Context) (int64, error) {
	tag, err := s.Pool.Exec(ctx, `WITH candidates AS (
		SELECT r.id,COALESCE(p.retention_days,365) AS retention_days,
			row_number() OVER (PARTITION BY r.organization_id,r.service_account_id,r.agent_name ORDER BY r.started_at DESC,r.id DESC) AS lineage_position
		FROM ai_audit_runs r
		LEFT JOIN audit_retention_policies p ON p.organization_id=r.organization_id
		WHERE r.status<>'running'
	)
	DELETE FROM ai_audit_runs r USING candidates c
	WHERE r.id=c.id AND c.lineage_position>1
		AND COALESCE(r.completed_at,r.started_at) < now()-(c.retention_days * interval '1 day')`)
	return tag.RowsAffected(), err
}
