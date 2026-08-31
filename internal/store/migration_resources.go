package store

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/google/uuid"
)

type MigrationResourcePageCursor struct {
	SourceOrganizationID string
	SourceKind           string
	SourceID             string
}

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
	items := []MigrationResource{}
	var cursor *MigrationResourcePageCursor
	for {
		page, hasMore, err := s.ListMigrationResourcesPage(ctx, organizationID, sourceOrganizationID, cursor, 1000)
		if err != nil {
			return nil, err
		}
		items = append(items, page...)
		if !hasMore {
			return items, nil
		}
		last := page[len(page)-1]
		cursor = &MigrationResourcePageCursor{SourceOrganizationID: last.SourceOrganizationID, SourceKind: last.SourceKind, SourceID: last.SourceID}
	}
}

func (s *Store) ListMigrationResourcesPage(ctx context.Context, organizationID uuid.UUID, sourceOrganizationID string, cursor *MigrationResourcePageCursor, limit int) ([]MigrationResource, bool, error) {
	if limit < 1 || limit > 1000 {
		return nil, false, errors.New("migration resource page limit must be between 1 and 1000")
	}
	var cursorOrganization, cursorKind, cursorID string
	if cursor != nil {
		cursorOrganization, cursorKind, cursorID = cursor.SourceOrganizationID, cursor.SourceKind, cursor.SourceID
	}
	rows, err := s.Pool.Query(ctx, `SELECT target_organization_id,source_organization_id,source_kind,source_id,target_id,status,reason,metadata,updated_at
		FROM dokploy_migration_resources
		WHERE target_organization_id=$1 AND ($2='' OR source_organization_id=$2)
		AND (NOT $3 OR (source_organization_id,source_kind,source_id)>($4,$5,$6))
		ORDER BY source_organization_id,source_kind,source_id LIMIT $7`, organizationID, sourceOrganizationID, cursor != nil, cursorOrganization, cursorKind, cursorID, limit+1)
	if err != nil {
		return nil, false, err
	}
	defer rows.Close()
	items := []MigrationResource{}
	for rows.Next() {
		var item MigrationResource
		if err = rows.Scan(&item.TargetOrganizationID, &item.SourceOrganizationID, &item.SourceKind, &item.SourceID, &item.TargetID, &item.Status, &item.Reason, &item.Metadata, &item.UpdatedAt); err != nil {
			return nil, false, err
		}
		items = append(items, item)
	}
	if err = rows.Err(); err != nil {
		return nil, false, err
	}
	hasMore := len(items) > limit
	if hasMore {
		items = items[:limit]
	}
	return items, hasMore, nil
}
