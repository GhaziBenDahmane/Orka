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
	ProjectCount   int       `json:"projectCount"`
	CreatedAt      time.Time `json:"createdAt"`
	UpdatedAt      time.Time `json:"updatedAt"`
}

func (s *Store) CreateTag(ctx context.Context, organizationID uuid.UUID, item Tag) (Tag, error) {
	tx, err := s.Pool.Begin(ctx)
	if err != nil {
		return Tag{}, err
	}
	defer tx.Rollback(ctx)
	item, err = createTagTx(ctx, tx, organizationID, item)
	if err != nil {
		return Tag{}, err
	}
	if err = tx.Commit(ctx); err != nil {
		return Tag{}, err
	}
	return item, nil
}

func (s *Store) CreateTagWithAudit(ctx context.Context, principal Principal, item Tag, remoteAddr string) (Tag, error) {
	tx, err := s.Pool.Begin(ctx)
	if err != nil {
		return Tag{}, err
	}
	defer tx.Rollback(ctx)
	item, err = createTagTx(ctx, tx, principal.OrganizationID, item)
	if err != nil {
		return Tag{}, err
	}
	if err = appendPrincipalAudit(ctx, tx, principal, "tag.create", "tag", item.ID.String(), remoteAddr, map[string]any{"name": item.Name}); err != nil {
		return Tag{}, err
	}
	if err = tx.Commit(ctx); err != nil {
		return Tag{}, err
	}
	return item, nil
}

func createTagTx(ctx context.Context, tx pgx.Tx, organizationID uuid.UUID, item Tag) (Tag, error) {
	if item.ID == uuid.Nil {
		item.ID = uuid.New()
	}
	err := tx.QueryRow(ctx, `INSERT INTO tags(id,organization_id,name,color)
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
	err := s.Pool.QueryRow(ctx, `SELECT t.id,t.organization_id,t.name,t.color,
		(SELECT count(*) FROM compose_service_tags st WHERE st.tag_id=t.id),
		(SELECT count(*) FROM project_tags pt WHERE pt.tag_id=t.id),t.created_at,t.updated_at
		FROM tags t WHERE t.id=$1 AND t.organization_id=$2`, id, organizationID).
		Scan(&item.ID, &item.OrganizationID, &item.Name, &item.Color, &item.ServiceCount, &item.ProjectCount, &item.CreatedAt, &item.UpdatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return Tag{}, ErrNotFound
	}
	return item, err
}

func (s *Store) ListTags(ctx context.Context, organizationID uuid.UUID) ([]Tag, error) {
	rows, err := s.Pool.Query(ctx, `SELECT t.id,t.organization_id,t.name,t.color,
		(SELECT count(*) FROM compose_service_tags st WHERE st.tag_id=t.id),
		(SELECT count(*) FROM project_tags pt WHERE pt.tag_id=t.id),t.created_at,t.updated_at
		FROM tags t WHERE t.organization_id=$1 ORDER BY lower(t.name),t.id`, organizationID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	items := []Tag{}
	for rows.Next() {
		var item Tag
		if err = rows.Scan(&item.ID, &item.OrganizationID, &item.Name, &item.Color, &item.ServiceCount, &item.ProjectCount, &item.CreatedAt, &item.UpdatedAt); err != nil {
			return nil, err
		}
		items = append(items, item)
	}
	return items, rows.Err()
}

func (s *Store) UpdateTag(ctx context.Context, organizationID, id uuid.UUID, name, color string) (Tag, error) {
	tx, err := s.Pool.Begin(ctx)
	if err != nil {
		return Tag{}, err
	}
	defer tx.Rollback(ctx)
	item, err := updateTagTx(ctx, tx, organizationID, id, name, color)
	if err != nil {
		return Tag{}, err
	}
	if err = tx.Commit(ctx); err != nil {
		return Tag{}, err
	}
	return item, nil
}

func (s *Store) UpdateTagWithAudit(ctx context.Context, principal Principal, id uuid.UUID, name, color, remoteAddr string) (Tag, error) {
	tx, err := s.Pool.Begin(ctx)
	if err != nil {
		return Tag{}, err
	}
	defer tx.Rollback(ctx)
	item, err := updateTagTx(ctx, tx, principal.OrganizationID, id, name, color)
	if err != nil {
		return Tag{}, err
	}
	if err = appendPrincipalAudit(ctx, tx, principal, "tag.update", "tag", id.String(), remoteAddr, map[string]any{"name": item.Name}); err != nil {
		return Tag{}, err
	}
	if err = tx.Commit(ctx); err != nil {
		return Tag{}, err
	}
	return item, nil
}

func updateTagTx(ctx context.Context, tx pgx.Tx, organizationID, id uuid.UUID, name, color string) (Tag, error) {
	var item Tag
	err := tx.QueryRow(ctx, `UPDATE tags SET name=$3,color=$4,updated_at=now()
		WHERE id=$1 AND organization_id=$2
		RETURNING id,organization_id,name,color,created_at,updated_at`, id, organizationID, name, color).
		Scan(&item.ID, &item.OrganizationID, &item.Name, &item.Color, &item.CreatedAt, &item.UpdatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return Tag{}, ErrNotFound
	}
	if err != nil {
		return Tag{}, err
	}
	if err = tx.QueryRow(ctx, `SELECT count(*) FROM compose_service_tags WHERE tag_id=$1`, id).Scan(&item.ServiceCount); err != nil {
		return Tag{}, err
	}
	if err = tx.QueryRow(ctx, `SELECT count(*) FROM project_tags WHERE tag_id=$1`, id).Scan(&item.ProjectCount); err != nil {
		return Tag{}, err
	}
	return item, nil
}

func (s *Store) ListProjectTags(ctx context.Context, organizationID, projectID uuid.UUID) ([]Tag, error) {
	var exists bool
	if err := s.Pool.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM projects WHERE id=$1 AND organization_id=$2 AND deletion_requested_at IS NULL)`, projectID, organizationID).Scan(&exists); err != nil {
		return nil, err
	}
	if !exists {
		return nil, ErrNotFound
	}
	rows, err := s.Pool.Query(ctx, `SELECT t.id,t.organization_id,t.name,t.color,t.created_at,t.updated_at
		FROM tags t JOIN project_tags pt ON pt.tag_id=t.id
		WHERE pt.project_id=$1 AND t.organization_id=$2 ORDER BY lower(t.name),t.id`, projectID, organizationID)
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

func (s *Store) ReplaceProjectTags(ctx context.Context, organizationID, projectID uuid.UUID, tagIDs []uuid.UUID) ([]Tag, error) {
	tx, err := s.Pool.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback(ctx)
	if err = replaceProjectTagsTx(ctx, tx, organizationID, projectID, tagIDs); err != nil {
		return nil, err
	}
	if err = tx.Commit(ctx); err != nil {
		return nil, err
	}
	return s.ListProjectTags(ctx, organizationID, projectID)
}

func (s *Store) ReplaceProjectTagsWithAudit(ctx context.Context, principal Principal, projectID uuid.UUID, tagIDs []uuid.UUID, remoteAddr string) ([]Tag, error) {
	tx, err := s.Pool.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback(ctx)
	if err = replaceProjectTagsTx(ctx, tx, principal.OrganizationID, projectID, tagIDs); err != nil {
		return nil, err
	}
	if err = appendPrincipalAudit(ctx, tx, principal, "project.tags.replace", "project", projectID.String(), remoteAddr, map[string]any{"count": len(tagIDs)}); err != nil {
		return nil, err
	}
	if err = tx.Commit(ctx); err != nil {
		return nil, err
	}
	return s.ListProjectTags(ctx, principal.OrganizationID, projectID)
}

func replaceProjectTagsTx(ctx context.Context, tx pgx.Tx, organizationID, projectID uuid.UUID, tagIDs []uuid.UUID) error {
	var lockedID uuid.UUID
	var err error
	if err = tx.QueryRow(ctx, `SELECT id FROM projects WHERE id=$1 AND organization_id=$2 AND deletion_requested_at IS NULL FOR UPDATE`, projectID, organizationID).Scan(&lockedID); errors.Is(err, pgx.ErrNoRows) {
		return ErrNotFound
	} else if err != nil {
		return err
	}
	if len(tagIDs) > 0 {
		var count int
		if err = tx.QueryRow(ctx, `SELECT count(*) FROM tags WHERE organization_id=$1 AND id=ANY($2::uuid[])`, organizationID, tagIDs).Scan(&count); err != nil {
			return err
		}
		if count != len(tagIDs) {
			return ErrNotFound
		}
	}
	if _, err = tx.Exec(ctx, `DELETE FROM project_tags WHERE project_id=$1`, projectID); err != nil {
		return err
	}
	if len(tagIDs) > 0 {
		if _, err = tx.Exec(ctx, `INSERT INTO project_tags(project_id,tag_id) SELECT $1,unnest($2::uuid[])`, projectID, tagIDs); err != nil {
			return err
		}
	}
	return nil
}

func (s *Store) DeleteTag(ctx context.Context, organizationID, id uuid.UUID) error {
	tx, err := s.Pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	if err = deleteTagTx(ctx, tx, organizationID, id); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

func (s *Store) DeleteTagWithAudit(ctx context.Context, principal Principal, id uuid.UUID, remoteAddr string) error {
	tx, err := s.Pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	if err = deleteTagTx(ctx, tx, principal.OrganizationID, id); err != nil {
		return err
	}
	if err = appendPrincipalAudit(ctx, tx, principal, "tag.delete", "tag", id.String(), remoteAddr, nil); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

func deleteTagTx(ctx context.Context, tx pgx.Tx, organizationID, id uuid.UUID) error {
	result, err := tx.Exec(ctx, `DELETE FROM tags WHERE id=$1 AND organization_id=$2`, id, organizationID)
	if err == nil && result.RowsAffected() == 0 {
		return ErrNotFound
	}
	return err
}

func (s *Store) ListServiceTags(ctx context.Context, organizationID, serviceID uuid.UUID) ([]Tag, error) {
	var exists bool
	if err := s.Pool.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM compose_services s JOIN environments e ON e.id=s.environment_id JOIN projects p ON p.id=e.project_id WHERE s.id=$1 AND p.organization_id=$2)`, serviceID, organizationID).Scan(&exists); err != nil {
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
	if err = replaceServiceTagsTx(ctx, tx, organizationID, serviceID, tagIDs); err != nil {
		return nil, err
	}
	if err = tx.Commit(ctx); err != nil {
		return nil, err
	}
	return s.ListServiceTags(ctx, organizationID, serviceID)
}

func (s *Store) ReplaceServiceTagsWithAudit(ctx context.Context, principal Principal, serviceID uuid.UUID, tagIDs []uuid.UUID, remoteAddr string) ([]Tag, error) {
	tx, err := s.Pool.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback(ctx)
	if err = replaceServiceTagsTx(ctx, tx, principal.OrganizationID, serviceID, tagIDs); err != nil {
		return nil, err
	}
	if err = appendPrincipalAudit(ctx, tx, principal, "service.tags.replace", "compose_service", serviceID.String(), remoteAddr, map[string]any{"count": len(tagIDs)}); err != nil {
		return nil, err
	}
	if err = tx.Commit(ctx); err != nil {
		return nil, err
	}
	return s.ListServiceTags(ctx, principal.OrganizationID, serviceID)
}

func replaceServiceTagsTx(ctx context.Context, tx pgx.Tx, organizationID, serviceID uuid.UUID, tagIDs []uuid.UUID) error {
	if _, _, err := lockActiveServiceForMutation(ctx, tx, organizationID, serviceID); err != nil {
		return err
	}
	var err error
	if len(tagIDs) > 0 {
		var count int
		if err = tx.QueryRow(ctx, `SELECT count(*) FROM tags WHERE organization_id=$1 AND id=ANY($2::uuid[])`, organizationID, tagIDs).Scan(&count); err != nil {
			return err
		}
		if count != len(tagIDs) {
			return ErrNotFound
		}
	}
	if _, err = tx.Exec(ctx, `DELETE FROM compose_service_tags WHERE compose_service_id=$1`, serviceID); err != nil {
		return err
	}
	if len(tagIDs) > 0 {
		if _, err = tx.Exec(ctx, `INSERT INTO compose_service_tags(compose_service_id,tag_id) SELECT $1,unnest($2::uuid[])`, serviceID, tagIDs); err != nil {
			return err
		}
	}
	return nil
}
