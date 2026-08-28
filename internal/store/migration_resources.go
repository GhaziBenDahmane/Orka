package store

import (
	"context"
	"encoding/json"
	"time"

	"github.com/google/uuid"
)

type MigrationResource struct {
	TargetOrganizationID uuid.UUID       `json:"targetOrganizationId"`
	SourceOrganizationID string          `json:"sourceOrganizationId"`
	SourceKind           string          `json:"sourceKind"`
	SourceID             string          `json:"sourceId"`
	TargetID             *uuid.UUID      `json:"targetId,omitempty"`
	Status               string          `json:"status"`
	Reason               string          `json:"reason,omitempty"`
	Metadata             json.RawMessage `json:"metadata"`
	UpdatedAt            time.Time       `json:"updatedAt"`
}

func (s *Store) ListMigrationResources(ctx context.Context, organizationID uuid.UUID, sourceOrganizationID string) ([]MigrationResource, error) {
	rows, err := s.Pool.Query(ctx, `SELECT target_organization_id,source_organization_id,source_kind,source_id,target_id,status,reason,metadata,updated_at FROM dokploy_migration_resources WHERE target_organization_id=$1 AND ($2='' OR source_organization_id=$2) ORDER BY source_organization_id,source_kind,source_id LIMIT 10000`, organizationID, sourceOrganizationID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	items := []MigrationResource{}
	for rows.Next() {
		var item MigrationResource
		if err = rows.Scan(&item.TargetOrganizationID, &item.SourceOrganizationID, &item.SourceKind, &item.SourceID, &item.TargetID, &item.Status, &item.Reason, &item.Metadata, &item.UpdatedAt); err != nil {
			return nil, err
		}
		items = append(items, item)
	}
	return items, rows.Err()
}
