package store

import (
	"context"
	"errors"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

type Tag struct {
	ID             uuid.UUID `json:"id"`
	OrganizationID uuid.UUID `json:"organizationId"`
	Name           string    `json:"name"`
	Color          string    `json:"color"`
	ServiceCount   int       `json:"serviceCount"`
	CreatedAt      time.Time `json:"createdAt"`
	UpdatedAt      time.Time `json:"updatedAt"`
}

func (s *Store) CreateTag(ctx context.Context, organizationID uuid.UUID, item Tag) (Tag, error) {
	if item.ID == uuid.Nil {
		item.ID = uuid.New()
	}
	err := s.Pool.QueryRow(ctx, `INSERT INTO tags(id,organization_id,name,color)
		SELECT $1,o.id,$3,$4 FROM organizations o WHERE o.id=$2
		RETURNING created_at,updated_at`, item.ID, organizationID, item.Name, item.Color).Scan(&item.CreatedAt, &item.UpdatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return Tag{}, ErrNotFound
	}
	item.OrganizationID = organizationID
	return item, err
}

func (s *Store) GetTag(ctx context.Context, organizationID, id uuid.UUID) (Tag, error) {
	var item Tag
	err := s.Pool.QueryRow(ctx, `SELECT t.id,t.organization_id,t.name,t.color,count(st.compose_service_id),t.created_at,t.updated_at
		FROM tags t LEFT JOIN compose_service_tags st ON st.tag_id=t.id
		WHERE t.id=$1 AND t.organization_id=$2 GROUP BY t.id`, id, organizationID).
		Scan(&item.ID, &item.OrganizationID, &item.Name, &item.Color, &item.ServiceCount, &item.CreatedAt, &item.UpdatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return Tag{}, ErrNotFound
	}
	return item, err
}

func (s *Store) ListTags(ctx context.Context, organizationID uuid.UUID) ([]Tag, error) {
	rows, err := s.Pool.Query(ctx, `SELECT t.id,t.organization_id,t.name,t.color,count(st.compose_service_id),t.created_at,t.updated_at
		FROM tags t LEFT JOIN compose_service_tags st ON st.tag_id=t.id
		WHERE t.organization_id=$1 GROUP BY t.id ORDER BY lower(t.name),t.id`, organizationID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	items := []Tag{}
	for rows.Next() {
		var item Tag
		if err = rows.Scan(&item.ID, &item.OrganizationID, &item.Name, &item.Color, &item.ServiceCount, &item.CreatedAt, &item.UpdatedAt); err != nil {
			return nil, err
		}
		items = append(items, item)
	}
	return items, rows.Err()
}

func (s *Store) UpdateTag(ctx context.Context, organizationID, id uuid.UUID, name, color string) (Tag, error) {
	var item Tag
	err := s.Pool.QueryRow(ctx, `UPDATE tags SET name=$3,color=$4,updated_at=now()
		WHERE id=$1 AND organization_id=$2
		RETURNING id,organization_id,name,color,created_at,updated_at`, id, organizationID, name, color).
		Scan(&item.ID, &item.OrganizationID, &item.Name, &item.Color, &item.CreatedAt, &item.UpdatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return Tag{}, ErrNotFound
	}
	if err != nil {
		return Tag{}, err
	}
	if err = s.Pool.QueryRow(ctx, `SELECT count(*) FROM compose_service_tags WHERE tag_id=$1`, id).Scan(&item.ServiceCount); err != nil {
		return Tag{}, err
	}
	return item, nil
}

func (s *Store) DeleteTag(ctx context.Context, organizationID, id uuid.UUID) error {
	result, err := s.Pool.Exec(ctx, `DELETE FROM tags WHERE id=$1 AND organization_id=$2`, id, organizationID)
	if err == nil && result.RowsAffected() == 0 {
		return ErrNotFound
	}
	return err
}

func (s *Store) ListServiceTags(ctx context.Context, organizationID, serviceID uuid.UUID) ([]Tag, error) {
	var exists bool
	if err := s.Pool.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM compose_services s JOIN environments e ON e.id=s.environment_id JOIN projects p ON p.id=e.project_id WHERE s.id=$1 AND s.deletion_requested_at IS NULL AND p.organization_id=$2)`, serviceID, organizationID).Scan(&exists); err != nil {
		return nil, err
	}
	if !exists {
		return nil, ErrNotFound
	}
	rows, err := s.Pool.Query(ctx, `SELECT t.id,t.organization_id,t.name,t.color,t.created_at,t.updated_at
		FROM tags t JOIN compose_service_tags st ON st.tag_id=t.id
		WHERE st.compose_service_id=$1 AND t.organization_id=$2 ORDER BY lower(t.name),t.id`, serviceID, organizationID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	items := []Tag{}
	for rows.Next() {
		var item Tag
		if err = rows.Scan(&item.ID, &item.OrganizationID, &item.Name, &item.Color, &item.CreatedAt, &item.UpdatedAt); err != nil {
			return nil, err
		}
		items = append(items, item)
	}
	return items, rows.Err()
}

func (s *Store) ReplaceServiceTags(ctx context.Context, organizationID, serviceID uuid.UUID, tagIDs []uuid.UUID) ([]Tag, error) {
	tx, err := s.Pool.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback(ctx)
	if _, _, err = lockActiveServiceForMutation(ctx, tx, organizationID, serviceID); err != nil {
		return nil, err
	}
	if len(tagIDs) > 0 {
		var count int
		if err = tx.QueryRow(ctx, `SELECT count(*) FROM tags WHERE organization_id=$1 AND id=ANY($2::uuid[])`, organizationID, tagIDs).Scan(&count); err != nil {
			return nil, err
		}
		if count != len(tagIDs) {
			return nil, ErrNotFound
		}
	}
	if _, err = tx.Exec(ctx, `DELETE FROM compose_service_tags WHERE compose_service_id=$1`, serviceID); err != nil {
		return nil, err
	}
	if len(tagIDs) > 0 {
		if _, err = tx.Exec(ctx, `INSERT INTO compose_service_tags(compose_service_id,tag_id) SELECT $1,unnest($2::uuid[])`, serviceID, tagIDs); err != nil {
			return nil, err
		}
	}
	if err = tx.Commit(ctx); err != nil {
		return nil, err
	}
	return s.ListServiceTags(ctx, organizationID, serviceID)
}
