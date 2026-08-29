package store

import (
	"context"
	"errors"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

type TemplateRepository struct {
	ID                  uuid.UUID  `json:"id"`
	OrganizationID      uuid.UUID  `json:"organizationId"`
	Name                string     `json:"name"`
	Slug                string     `json:"slug"`
	RepositoryURL       string     `json:"repositoryUrl"`
	GitRef              string     `json:"gitRef"`
	CatalogPath         string     `json:"catalogPath"`
	TrustedPublicKey    string     `json:"trustedPublicKey,omitempty"`
	RequireSignature    bool       `json:"requireSignature"`
	SyncIntervalSeconds int        `json:"syncIntervalSeconds"`
	NextSyncAt          *time.Time `json:"nextSyncAt,omitempty"`
	Enabled             bool       `json:"enabled"`
	LastSyncStatus      string     `json:"lastSyncStatus"`
	LastSyncError       string     `json:"lastSyncError,omitempty"`
	LastSyncedAt        *time.Time `json:"lastSyncedAt,omitempty"`
	CreatedAt           time.Time  `json:"createdAt"`
	UpdatedAt           time.Time  `json:"updatedAt"`
}

func (s *Store) CreateTemplateRepository(ctx context.Context, item TemplateRepository) (TemplateRepository, error) {
	item.ID = uuid.New()
	item.Enabled = true
	err := s.Pool.QueryRow(ctx, `INSERT INTO template_repositories(id,organization_id,name,slug,repository_url,git_ref,catalog_path,trusted_public_key,require_signature,sync_interval_seconds,next_sync_at) SELECT $1,o.id,$3,$4,$5,$6,$7,$8,$9,$10,CASE WHEN $10>0 THEN now() ELSE NULL END FROM organizations o WHERE o.id=$2 RETURNING enabled,last_sync_status,last_sync_error,next_sync_at,created_at,updated_at`, item.ID, item.OrganizationID, item.Name, item.Slug, item.RepositoryURL, item.GitRef, item.CatalogPath, item.TrustedPublicKey, item.RequireSignature, item.SyncIntervalSeconds).Scan(&item.Enabled, &item.LastSyncStatus, &item.LastSyncError, &item.NextSyncAt, &item.CreatedAt, &item.UpdatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return TemplateRepository{}, ErrNotFound
	}
	return item, err
}

func (s *Store) ListTemplateRepositories(ctx context.Context, organizationID uuid.UUID) ([]TemplateRepository, error) {
	rows, err := s.Pool.Query(ctx, `SELECT id,organization_id,name,slug,repository_url,git_ref,catalog_path,trusted_public_key,require_signature,sync_interval_seconds,next_sync_at,enabled,last_sync_status,last_sync_error,last_synced_at,created_at,updated_at FROM template_repositories WHERE organization_id=$1 ORDER BY name`, organizationID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	items := []TemplateRepository{}
	for rows.Next() {
		var item TemplateRepository
		if err = rows.Scan(&item.ID, &item.OrganizationID, &item.Name, &item.Slug, &item.RepositoryURL, &item.GitRef, &item.CatalogPath, &item.TrustedPublicKey, &item.RequireSignature, &item.SyncIntervalSeconds, &item.NextSyncAt, &item.Enabled, &item.LastSyncStatus, &item.LastSyncError, &item.LastSyncedAt, &item.CreatedAt, &item.UpdatedAt); err != nil {
			return nil, err
		}
		items = append(items, item)
	}
	return items, rows.Err()
}

func (s *Store) GetTemplateRepository(ctx context.Context, organizationID, id uuid.UUID) (TemplateRepository, error) {
	var item TemplateRepository
	err := s.Pool.QueryRow(ctx, `SELECT id,organization_id,name,slug,repository_url,git_ref,catalog_path,trusted_public_key,require_signature,sync_interval_seconds,next_sync_at,enabled,last_sync_status,last_sync_error,last_synced_at,created_at,updated_at FROM template_repositories WHERE id=$1 AND organization_id=$2`, id, organizationID).Scan(&item.ID, &item.OrganizationID, &item.Name, &item.Slug, &item.RepositoryURL, &item.GitRef, &item.CatalogPath, &item.TrustedPublicKey, &item.RequireSignature, &item.SyncIntervalSeconds, &item.NextSyncAt, &item.Enabled, &item.LastSyncStatus, &item.LastSyncError, &item.LastSyncedAt, &item.CreatedAt, &item.UpdatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return TemplateRepository{}, ErrNotFound
	}
	return item, err
}

func (s *Store) BeginTemplateRepositorySync(ctx context.Context, organizationID, id uuid.UUID) (TemplateRepository, error) {
	var item TemplateRepository
	err := s.Pool.QueryRow(ctx, `UPDATE template_repositories SET last_sync_status='running',last_sync_error='',updated_at=now()
		WHERE id=$1 AND organization_id=$2 AND enabled AND (last_sync_status<>'running' OR updated_at<now()-interval '5 minutes')
		RETURNING id,organization_id,name,slug,repository_url,git_ref,catalog_path,trusted_public_key,require_signature,sync_interval_seconds,next_sync_at,enabled,last_sync_status,last_sync_error,last_synced_at,created_at,updated_at`, id, organizationID).Scan(&item.ID, &item.OrganizationID, &item.Name, &item.Slug, &item.RepositoryURL, &item.GitRef, &item.CatalogPath, &item.TrustedPublicKey, &item.RequireSignature, &item.SyncIntervalSeconds, &item.NextSyncAt, &item.Enabled, &item.LastSyncStatus, &item.LastSyncError, &item.LastSyncedAt, &item.CreatedAt, &item.UpdatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return TemplateRepository{}, ErrBusy
	}
	return item, err
}

func (s *Store) ClaimDueTemplateRepository(ctx context.Context) (TemplateRepository, error) {
	var item TemplateRepository
	err := s.Pool.QueryRow(ctx, `WITH candidate AS (
		SELECT id FROM template_repositories
		WHERE enabled AND sync_interval_seconds>0 AND next_sync_at<=now()
		AND (last_sync_status<>'running' OR updated_at<now()-interval '5 minutes')
		ORDER BY next_sync_at,id FOR UPDATE SKIP LOCKED LIMIT 1
	)
	UPDATE template_repositories r SET last_sync_status='running',last_sync_error='',updated_at=now()
	FROM candidate c WHERE r.id=c.id
	RETURNING r.id,r.organization_id,r.name,r.slug,r.repository_url,r.git_ref,r.catalog_path,r.trusted_public_key,r.require_signature,r.sync_interval_seconds,r.next_sync_at,r.enabled,r.last_sync_status,r.last_sync_error,r.last_synced_at,r.created_at,r.updated_at`).Scan(&item.ID, &item.OrganizationID, &item.Name, &item.Slug, &item.RepositoryURL, &item.GitRef, &item.CatalogPath, &item.TrustedPublicKey, &item.RequireSignature, &item.SyncIntervalSeconds, &item.NextSyncAt, &item.Enabled, &item.LastSyncStatus, &item.LastSyncError, &item.LastSyncedAt, &item.CreatedAt, &item.UpdatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return TemplateRepository{}, ErrNotFound
	}
	return item, err
}

func (s *Store) FinishTemplateRepositorySync(ctx context.Context, repository TemplateRepository, status, message string) error {
	if status != "succeeded" && status != "failed" {
		return errors.New("invalid template repository sync status")
	}
	tag, err := s.Pool.Exec(ctx, `UPDATE template_repositories SET last_sync_status=$3,last_sync_error=$4,last_synced_at=now(),next_sync_at=CASE WHEN sync_interval_seconds>0 THEN now()+(sync_interval_seconds * interval '1 second') ELSE NULL END,updated_at=now() WHERE id=$1 AND organization_id=$2 AND last_sync_status='running'`, repository.ID, repository.OrganizationID, status, message)
	if err == nil && tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return err
}

func (s *Store) UpdateTemplateRepositorySettings(ctx context.Context, organizationID, id uuid.UUID, trustedPublicKey string, requireSignature bool, syncIntervalSeconds int) error {
	tag, err := s.Pool.Exec(ctx, `UPDATE template_repositories SET trusted_public_key=$3,require_signature=$4,sync_interval_seconds=$5,next_sync_at=CASE WHEN $5>0 THEN now() ELSE NULL END,updated_at=now() WHERE id=$1 AND organization_id=$2`, id, organizationID, trustedPublicKey, requireSignature, syncIntervalSeconds)
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

// ReplaceRepositoryTemplates atomically reconciles one repository snapshot.
// Existing template instances retain their copied provenance when a removed
// catalog version is deleted because their template foreign key uses SET NULL.
func (s *Store) ReplaceRepositoryTemplates(ctx context.Context, organizationID, repositoryID uuid.UUID, items []Template) error {
	if len(items) == 0 {
		return errors.New("repository catalog must contain at least one template")
	}
	tx, err := s.Pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	var exists bool
	if err = tx.QueryRow(ctx, `SELECT true FROM template_repositories WHERE id=$1 AND organization_id=$2 FOR UPDATE`, repositoryID, organizationID).Scan(&exists); errors.Is(err, pgx.ErrNoRows) {
		return ErrNotFound
	} else if err != nil {
		return err
	}
	ids := make([]uuid.UUID, 0, len(items))
	for _, item := range items {
		if item.RepositoryID == nil || item.OrganizationID == nil || *item.RepositoryID != repositoryID || *item.OrganizationID != organizationID {
			return errors.New("template repository scope mismatch")
		}
		item.ID = uuid.New()
		var id uuid.UUID
		if err = tx.QueryRow(ctx, `INSERT INTO templates(id,organization_id,repository_id,template_key,version,name,description,compose_yaml,config,source,source_path,checksum)
			VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)
			ON CONFLICT (organization_id,template_key,version) DO UPDATE SET repository_id=excluded.repository_id,name=excluded.name,description=excluded.description,compose_yaml=excluded.compose_yaml,config=excluded.config,source=excluded.source,source_path=excluded.source_path,checksum=excluded.checksum
			RETURNING id`, item.ID, organizationID, repositoryID, item.Key, item.Version, item.Name, item.Description, item.ComposeYAML, item.Config, item.Source, item.SourcePath, item.Checksum).Scan(&id); err != nil {
			return err
		}
		ids = append(ids, id)
	}
	if _, err = tx.Exec(ctx, `DELETE FROM templates WHERE repository_id=$1 AND organization_id=$2 AND NOT (id=ANY($3::uuid[]))`, repositoryID, organizationID, ids); err != nil {
		return err
	}
	return tx.Commit(ctx)
}
