package store

import (
	"context"
	"errors"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

type TemplateRepository struct {
	ID             uuid.UUID  `json:"id"`
	OrganizationID uuid.UUID  `json:"organizationId"`
	Name           string     `json:"name"`
	Slug           string     `json:"slug"`
	RepositoryURL  string     `json:"repositoryUrl"`
	GitRef         string     `json:"gitRef"`
	CatalogPath    string     `json:"catalogPath"`
	Enabled        bool       `json:"enabled"`
	LastSyncStatus string     `json:"lastSyncStatus"`
	LastSyncError  string     `json:"lastSyncError,omitempty"`
	LastSyncedAt   *time.Time `json:"lastSyncedAt,omitempty"`
	CreatedAt      time.Time  `json:"createdAt"`
	UpdatedAt      time.Time  `json:"updatedAt"`
}

func (s *Store) CreateTemplateRepository(ctx context.Context, item TemplateRepository) (TemplateRepository, error) {
	item.ID = uuid.New()
	item.Enabled = true
	err := s.Pool.QueryRow(ctx, `INSERT INTO template_repositories(id,organization_id,name,slug,repository_url,git_ref,catalog_path) SELECT $1,o.id,$3,$4,$5,$6,$7 FROM organizations o WHERE o.id=$2 RETURNING enabled,last_sync_status,last_sync_error,created_at,updated_at`, item.ID, item.OrganizationID, item.Name, item.Slug, item.RepositoryURL, item.GitRef, item.CatalogPath).Scan(&item.Enabled, &item.LastSyncStatus, &item.LastSyncError, &item.CreatedAt, &item.UpdatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return TemplateRepository{}, ErrNotFound
	}
	return item, err
}

func (s *Store) ListTemplateRepositories(ctx context.Context, organizationID uuid.UUID) ([]TemplateRepository, error) {
	rows, err := s.Pool.Query(ctx, `SELECT id,organization_id,name,slug,repository_url,git_ref,catalog_path,enabled,last_sync_status,last_sync_error,last_synced_at,created_at,updated_at FROM template_repositories WHERE organization_id=$1 ORDER BY name`, organizationID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	items := []TemplateRepository{}
	for rows.Next() {
		var item TemplateRepository
		if err = rows.Scan(&item.ID, &item.OrganizationID, &item.Name, &item.Slug, &item.RepositoryURL, &item.GitRef, &item.CatalogPath, &item.Enabled, &item.LastSyncStatus, &item.LastSyncError, &item.LastSyncedAt, &item.CreatedAt, &item.UpdatedAt); err != nil {
			return nil, err
		}
		items = append(items, item)
	}
	return items, rows.Err()
}

func (s *Store) GetTemplateRepository(ctx context.Context, organizationID, id uuid.UUID) (TemplateRepository, error) {
	var item TemplateRepository
	err := s.Pool.QueryRow(ctx, `SELECT id,organization_id,name,slug,repository_url,git_ref,catalog_path,enabled,last_sync_status,last_sync_error,last_synced_at,created_at,updated_at FROM template_repositories WHERE id=$1 AND organization_id=$2`, id, organizationID).Scan(&item.ID, &item.OrganizationID, &item.Name, &item.Slug, &item.RepositoryURL, &item.GitRef, &item.CatalogPath, &item.Enabled, &item.LastSyncStatus, &item.LastSyncError, &item.LastSyncedAt, &item.CreatedAt, &item.UpdatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return TemplateRepository{}, ErrNotFound
	}
	return item, err
}

func (s *Store) SetTemplateRepositorySync(ctx context.Context, organizationID, id uuid.UUID, status, message string) error {
	tag, err := s.Pool.Exec(ctx, `UPDATE template_repositories SET last_sync_status=$3,last_sync_error=$4,last_synced_at=CASE WHEN $3 IN ('succeeded','failed') THEN now() ELSE last_synced_at END,updated_at=now() WHERE id=$1 AND organization_id=$2`, id, organizationID, status, message)
	if err == nil && tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return err
}

func (s *Store) DeleteTemplateRepository(ctx context.Context, organizationID, id uuid.UUID) error {
	tx, err := s.Pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	if _, err = tx.Exec(ctx, `DELETE FROM templates WHERE repository_id=$1 AND organization_id=$2`, id, organizationID); err != nil {
		return err
	}
	tag, err := tx.Exec(ctx, `DELETE FROM template_repositories WHERE id=$1 AND organization_id=$2`, id, organizationID)
	if err == nil && tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	if err != nil {
		return err
	}
	return tx.Commit(ctx)
}

func (s *Store) UpsertRepositoryTemplate(ctx context.Context, item Template) (Template, error) {
	if item.RepositoryID == nil || item.OrganizationID == nil {
		return Template{}, errors.New("repository and organization are required")
	}
	var existing uuid.UUID
	err := s.Pool.QueryRow(ctx, `SELECT id FROM templates WHERE repository_id=$1 AND template_key=$2 AND version=$3`, *item.RepositoryID, item.Key, item.Version).Scan(&existing)
	if err == nil {
		item.ID = existing
		err = s.Pool.QueryRow(ctx, `UPDATE templates SET name=$2,description=$3,compose_yaml=$4,config=$5,source=$6,source_path=$7,checksum=$8 WHERE id=$1 RETURNING created_at`, item.ID, item.Name, item.Description, item.ComposeYAML, item.Config, item.Source, item.SourcePath, item.Checksum).Scan(&item.CreatedAt)
		return item, err
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		return Template{}, err
	}
	return s.CreateTemplate(ctx, item)
}
