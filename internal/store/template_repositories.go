package store

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

type TemplateRepository struct {
	ID                     uuid.UUID  `json:"id"`
	OrganizationID         uuid.UUID  `json:"organizationId"`
	Name                   string     `json:"name"`
	Slug                   string     `json:"slug"`
	RepositoryURL          string     `json:"repositoryUrl"`
	GitRef                 string     `json:"gitRef"`
	CatalogPath            string     `json:"catalogPath"`
	TrustedPublicKey       string     `json:"trustedPublicKey,omitempty"`
	RequireSignature       bool       `json:"requireSignature"`
	CredentialID           *uuid.UUID `json:"credentialId,omitempty"`
	EncryptedWebhookSecret string     `json:"-"`
	WebhookConfigured      bool       `json:"webhookConfigured"`
	SyncIntervalSeconds    int        `json:"syncIntervalSeconds"`
	SyncRequestedAt        *time.Time `json:"syncRequestedAt,omitempty"`
	SyncStartedAt          *time.Time `json:"syncStartedAt,omitempty"`
	SyncAttemptID          *uuid.UUID `json:"-"`
	NextSyncAt             *time.Time `json:"nextSyncAt,omitempty"`
	Enabled                bool       `json:"enabled"`
	LastSyncStatus         string     `json:"lastSyncStatus"`
	LastSyncError          string     `json:"lastSyncError,omitempty"`
	LastSyncedAt           *time.Time `json:"lastSyncedAt,omitempty"`
	CreatedAt              time.Time  `json:"createdAt"`
	UpdatedAt              time.Time  `json:"updatedAt"`
}

func (s *Store) CreateTemplateRepository(ctx context.Context, item TemplateRepository) (TemplateRepository, error) {
	tx, err := s.Pool.Begin(ctx)
	if err != nil {
		return TemplateRepository{}, err
	}
	defer tx.Rollback(ctx)
	item, err = createTemplateRepositoryTx(ctx, tx, item)
	if err != nil {
		return TemplateRepository{}, err
	}
	return item, tx.Commit(ctx)
}

func (s *Store) CreateTemplateRepositoryWithAudit(ctx context.Context, principal Principal, item TemplateRepository, remoteAddr string, metadata any) (TemplateRepository, error) {
	item.OrganizationID = principal.OrganizationID
	tx, err := s.Pool.Begin(ctx)
	if err != nil {
		return TemplateRepository{}, err
	}
	defer tx.Rollback(ctx)
	item, err = createTemplateRepositoryTx(ctx, tx, item)
	if err != nil {
		return TemplateRepository{}, err
	}
	if err = appendPrincipalAudit(ctx, tx, principal, "template_repository.create", "template_repository", item.ID.String(), remoteAddr, metadata); err != nil {
		return TemplateRepository{}, err
	}
	return item, tx.Commit(ctx)
}

func createTemplateRepositoryTx(ctx context.Context, tx pgx.Tx, item TemplateRepository) (TemplateRepository, error) {
	item.ID = uuid.New()
	item.Enabled = true
	err := tx.QueryRow(ctx, `INSERT INTO template_repositories(id,organization_id,name,slug,repository_url,git_ref,catalog_path,trusted_public_key,require_signature,credential_id,sync_interval_seconds,next_sync_at) SELECT $1,o.id,$3,$4,$5,$6,$7,$8,$9,$10,$11,CASE WHEN $11>0 THEN now() ELSE NULL END FROM organizations o WHERE o.id=$2 AND ($10::uuid IS NULL OR EXISTS(SELECT 1 FROM source_credentials c WHERE c.id=$10 AND c.organization_id=o.id AND c.kind='git' AND lower(c.server)='github.com')) RETURNING enabled,last_sync_status,last_sync_error,next_sync_at,created_at,updated_at`, item.ID, item.OrganizationID, item.Name, item.Slug, item.RepositoryURL, item.GitRef, item.CatalogPath, item.TrustedPublicKey, item.RequireSignature, item.CredentialID, item.SyncIntervalSeconds).Scan(&item.Enabled, &item.LastSyncStatus, &item.LastSyncError, &item.NextSyncAt, &item.CreatedAt, &item.UpdatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return TemplateRepository{}, ErrNotFound
	}
	return item, err
}

func (s *Store) ListTemplateRepositories(ctx context.Context, organizationID uuid.UUID) ([]TemplateRepository, error) {
	rows, err := s.Pool.Query(ctx, `SELECT id,organization_id,name,slug,repository_url,git_ref,catalog_path,trusted_public_key,require_signature,credential_id,encrypted_webhook_secret,encrypted_webhook_secret<>'',sync_interval_seconds,next_sync_at,sync_requested_at,sync_started_at,sync_attempt_id,enabled,last_sync_status,last_sync_error,last_synced_at,created_at,updated_at FROM template_repositories WHERE organization_id=$1 ORDER BY name`, organizationID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	items := []TemplateRepository{}
	for rows.Next() {
		var item TemplateRepository
		if err = rows.Scan(&item.ID, &item.OrganizationID, &item.Name, &item.Slug, &item.RepositoryURL, &item.GitRef, &item.CatalogPath, &item.TrustedPublicKey, &item.RequireSignature, &item.CredentialID, &item.EncryptedWebhookSecret, &item.WebhookConfigured, &item.SyncIntervalSeconds, &item.NextSyncAt, &item.SyncRequestedAt, &item.SyncStartedAt, &item.SyncAttemptID, &item.Enabled, &item.LastSyncStatus, &item.LastSyncError, &item.LastSyncedAt, &item.CreatedAt, &item.UpdatedAt); err != nil {
			return nil, err
		}
		items = append(items, item)
	}
	return items, rows.Err()
}

func (s *Store) GetTemplateRepository(ctx context.Context, organizationID, id uuid.UUID) (TemplateRepository, error) {
	var item TemplateRepository
	err := s.Pool.QueryRow(ctx, `SELECT id,organization_id,name,slug,repository_url,git_ref,catalog_path,trusted_public_key,require_signature,credential_id,encrypted_webhook_secret,encrypted_webhook_secret<>'',sync_interval_seconds,next_sync_at,sync_requested_at,sync_started_at,sync_attempt_id,enabled,last_sync_status,last_sync_error,last_synced_at,created_at,updated_at FROM template_repositories WHERE id=$1 AND organization_id=$2`, id, organizationID).Scan(&item.ID, &item.OrganizationID, &item.Name, &item.Slug, &item.RepositoryURL, &item.GitRef, &item.CatalogPath, &item.TrustedPublicKey, &item.RequireSignature, &item.CredentialID, &item.EncryptedWebhookSecret, &item.WebhookConfigured, &item.SyncIntervalSeconds, &item.NextSyncAt, &item.SyncRequestedAt, &item.SyncStartedAt, &item.SyncAttemptID, &item.Enabled, &item.LastSyncStatus, &item.LastSyncError, &item.LastSyncedAt, &item.CreatedAt, &item.UpdatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return TemplateRepository{}, ErrNotFound
	}
	return item, err
}

func (s *Store) GetTemplateRepositoryForWebhook(ctx context.Context, id uuid.UUID) (TemplateRepository, error) {
	var item TemplateRepository
	err := s.Pool.QueryRow(ctx, `SELECT id,organization_id,name,slug,repository_url,git_ref,catalog_path,trusted_public_key,require_signature,credential_id,encrypted_webhook_secret,encrypted_webhook_secret<>'',sync_interval_seconds,next_sync_at,sync_requested_at,sync_started_at,sync_attempt_id,enabled,last_sync_status,last_sync_error,last_synced_at,created_at,updated_at FROM template_repositories WHERE id=$1 AND enabled AND encrypted_webhook_secret<>''`, id).Scan(&item.ID, &item.OrganizationID, &item.Name, &item.Slug, &item.RepositoryURL, &item.GitRef, &item.CatalogPath, &item.TrustedPublicKey, &item.RequireSignature, &item.CredentialID, &item.EncryptedWebhookSecret, &item.WebhookConfigured, &item.SyncIntervalSeconds, &item.NextSyncAt, &item.SyncRequestedAt, &item.SyncStartedAt, &item.SyncAttemptID, &item.Enabled, &item.LastSyncStatus, &item.LastSyncError, &item.LastSyncedAt, &item.CreatedAt, &item.UpdatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return TemplateRepository{}, ErrNotFound
	}
	return item, err
}

func (s *Store) SetTemplateRepositoryWebhookSecret(ctx context.Context, organizationID, id uuid.UUID, encryptedSecret string) error {
	tx, err := s.Pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	if err = setTemplateRepositoryWebhookSecretTx(ctx, tx, organizationID, id, encryptedSecret); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

func (s *Store) SetTemplateRepositoryWebhookSecretWithAudit(ctx context.Context, principal Principal, id uuid.UUID, encryptedSecret, remoteAddr string) error {
	tx, err := s.Pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	if err = setTemplateRepositoryWebhookSecretTx(ctx, tx, principal.OrganizationID, id, encryptedSecret); err != nil {
		return err
	}
	if err = appendPrincipalAudit(ctx, tx, principal, "template_repository.webhook.rotate", "template_repository", id.String(), remoteAddr, nil); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

func setTemplateRepositoryWebhookSecretTx(ctx context.Context, tx pgx.Tx, organizationID, id uuid.UUID, encryptedSecret string) error {
	tag, err := tx.Exec(ctx, `UPDATE template_repositories SET encrypted_webhook_secret=$3,updated_at=now() WHERE id=$1 AND organization_id=$2`, id, organizationID, encryptedSecret)
	if err == nil && tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return err
}

func (s *Store) ClearTemplateRepositoryWebhookSecret(ctx context.Context, organizationID, id uuid.UUID) error {
	tx, err := s.Pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	if err = clearTemplateRepositoryWebhookSecretTx(ctx, tx, organizationID, id); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

func (s *Store) ClearTemplateRepositoryWebhookSecretWithAudit(ctx context.Context, principal Principal, id uuid.UUID, remoteAddr string) error {
	tx, err := s.Pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	if err = clearTemplateRepositoryWebhookSecretTx(ctx, tx, principal.OrganizationID, id); err != nil {
		return err
	}
	if err = appendPrincipalAudit(ctx, tx, principal, "template_repository.webhook.disable", "template_repository", id.String(), remoteAddr, nil); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

func clearTemplateRepositoryWebhookSecretTx(ctx context.Context, tx pgx.Tx, organizationID, id uuid.UUID) error {
	tag, err := tx.Exec(ctx, `UPDATE template_repositories SET encrypted_webhook_secret='',sync_requested_at=NULL,updated_at=now() WHERE id=$1 AND organization_id=$2`, id, organizationID)
	if err == nil && tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return err
}

func (s *Store) RequestTemplateRepositorySync(ctx context.Context, id uuid.UUID, deliveryID string) error {
	tx, err := s.Pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	if err = requestTemplateRepositorySyncTx(ctx, tx, id, deliveryID); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

func (s *Store) RequestTemplateRepositorySyncWithAudit(ctx context.Context, organizationID, id uuid.UUID, deliveryID, expectedGitRef, expectedEncryptedSecret, remoteAddr string) error {
	tx, err := s.Pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	var gitRef string
	err = tx.QueryRow(ctx, `SELECT git_ref FROM template_repositories WHERE id=$1 AND organization_id=$2 AND enabled AND git_ref=$3 AND encrypted_webhook_secret<>'' AND encrypted_webhook_secret=$4 FOR UPDATE`, id, organizationID, expectedGitRef, expectedEncryptedSecret).Scan(&gitRef)
	if errors.Is(err, pgx.ErrNoRows) {
		return ErrNotFound
	}
	if err != nil {
		return err
	}
	if err = requestTemplateRepositorySyncTx(ctx, tx, id, deliveryID); err != nil {
		return err
	}
	if err = s.AuditOrganizationTx(ctx, tx, organizationID, "template_repository.webhook", "template_repository", id.String(), remoteAddr, map[string]any{"deliveryId": deliveryID, "gitRef": gitRef}); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

func requestTemplateRepositorySyncTx(ctx context.Context, tx pgx.Tx, id uuid.UUID, deliveryID string) error {
	if _, err := tx.Exec(ctx, `DELETE FROM template_repository_webhook_deliveries WHERE received_at<now()-interval '30 days'`); err != nil {
		return err
	}
	var inserted bool
	err := tx.QueryRow(ctx, `INSERT INTO template_repository_webhook_deliveries(repository_id,delivery_id) SELECT id,$2 FROM template_repositories WHERE id=$1 AND enabled ON CONFLICT DO NOTHING RETURNING true`, id, deliveryID).Scan(&inserted)
	if errors.Is(err, pgx.ErrNoRows) {
		var exists bool
		if countErr := tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM template_repositories WHERE id=$1 AND enabled)`, id).Scan(&exists); countErr != nil {
			return countErr
		}
		if exists {
			return ErrDuplicateDelivery
		}
		return ErrNotFound
	}
	if err != nil {
		return err
	}
	tag, err := tx.Exec(ctx, `UPDATE template_repositories SET sync_requested_at=now(),updated_at=now() WHERE id=$1 AND enabled`, id)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

// QueueTemplateRepositorySync durably coalesces operator refresh requests.
// If a sync is already running, sync_requested_at remains set so the scheduler
// performs one more refresh after the in-flight attempt finishes.
func (s *Store) QueueTemplateRepositorySync(ctx context.Context, organizationID, id uuid.UUID) (time.Time, error) {
	tx, err := s.Pool.Begin(ctx)
	if err != nil {
		return time.Time{}, err
	}
	defer tx.Rollback(ctx)
	requestedAt, err := queueTemplateRepositorySyncTx(ctx, tx, organizationID, id)
	if err != nil {
		return time.Time{}, err
	}
	return requestedAt, tx.Commit(ctx)
}

func (s *Store) QueueTemplateRepositorySyncWithAudit(ctx context.Context, principal Principal, id uuid.UUID, remoteAddr string) (time.Time, error) {
	tx, err := s.Pool.Begin(ctx)
	if err != nil {
		return time.Time{}, err
	}
	defer tx.Rollback(ctx)
	requestedAt, err := queueTemplateRepositorySyncTx(ctx, tx, principal.OrganizationID, id)
	if err != nil {
		return time.Time{}, err
	}
	if err = appendPrincipalAudit(ctx, tx, principal, "template_repository.sync.queued", "template_repository", id.String(), remoteAddr, map[string]any{"requestedAt": requestedAt}); err != nil {
		return time.Time{}, err
	}
	return requestedAt, tx.Commit(ctx)
}

func queueTemplateRepositorySyncTx(ctx context.Context, tx pgx.Tx, organizationID, id uuid.UUID) (time.Time, error) {
	var requestedAt time.Time
	err := tx.QueryRow(ctx, `UPDATE template_repositories
		SET sync_requested_at=COALESCE(sync_requested_at,now()),updated_at=now()
		WHERE id=$1 AND organization_id=$2 AND enabled
		RETURNING sync_requested_at`, id, organizationID).Scan(&requestedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return time.Time{}, ErrNotFound
	}
	return requestedAt, err
}

func (s *Store) BeginTemplateRepositorySync(ctx context.Context, organizationID, id uuid.UUID) (TemplateRepository, error) {
	var item TemplateRepository
	attemptID := uuid.New()
	err := s.Pool.QueryRow(ctx, `UPDATE template_repositories SET last_sync_status='running',last_sync_error='',sync_requested_at=NULL,sync_started_at=now(),sync_attempt_id=$3,updated_at=now()
		WHERE id=$1 AND organization_id=$2 AND enabled AND (last_sync_status<>'running' OR sync_started_at IS NULL OR sync_started_at<now()-interval '5 minutes')
		RETURNING id,organization_id,name,slug,repository_url,git_ref,catalog_path,trusted_public_key,require_signature,credential_id,encrypted_webhook_secret,encrypted_webhook_secret<>'',sync_interval_seconds,next_sync_at,sync_requested_at,sync_started_at,sync_attempt_id,enabled,last_sync_status,last_sync_error,last_synced_at,created_at,updated_at`, id, organizationID, attemptID).Scan(&item.ID, &item.OrganizationID, &item.Name, &item.Slug, &item.RepositoryURL, &item.GitRef, &item.CatalogPath, &item.TrustedPublicKey, &item.RequireSignature, &item.CredentialID, &item.EncryptedWebhookSecret, &item.WebhookConfigured, &item.SyncIntervalSeconds, &item.NextSyncAt, &item.SyncRequestedAt, &item.SyncStartedAt, &item.SyncAttemptID, &item.Enabled, &item.LastSyncStatus, &item.LastSyncError, &item.LastSyncedAt, &item.CreatedAt, &item.UpdatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return TemplateRepository{}, ErrBusy
	}
	return item, err
}

func (s *Store) ClaimDueTemplateRepository(ctx context.Context) (TemplateRepository, error) {
	var item TemplateRepository
	attemptID := uuid.New()
	err := s.Pool.QueryRow(ctx, `WITH candidate AS (
		SELECT id FROM template_repositories
		WHERE enabled AND (
			(last_sync_status='running' AND (sync_started_at IS NULL OR sync_started_at<now()-interval '5 minutes'))
			OR (last_sync_status<>'running' AND ((sync_interval_seconds>0 AND next_sync_at<=now()) OR sync_requested_at IS NOT NULL))
		)
		ORDER BY COALESCE(sync_requested_at,sync_started_at,next_sync_at),id FOR UPDATE SKIP LOCKED LIMIT 1
	)
	UPDATE template_repositories r SET last_sync_status='running',last_sync_error='',sync_requested_at=NULL,sync_started_at=now(),sync_attempt_id=$1,updated_at=now()
	FROM candidate c WHERE r.id=c.id
	RETURNING r.id,r.organization_id,r.name,r.slug,r.repository_url,r.git_ref,r.catalog_path,r.trusted_public_key,r.require_signature,r.credential_id,r.encrypted_webhook_secret,r.encrypted_webhook_secret<>'',r.sync_interval_seconds,r.next_sync_at,r.sync_requested_at,r.sync_started_at,r.sync_attempt_id,r.enabled,r.last_sync_status,r.last_sync_error,r.last_synced_at,r.created_at,r.updated_at`, attemptID).Scan(&item.ID, &item.OrganizationID, &item.Name, &item.Slug, &item.RepositoryURL, &item.GitRef, &item.CatalogPath, &item.TrustedPublicKey, &item.RequireSignature, &item.CredentialID, &item.EncryptedWebhookSecret, &item.WebhookConfigured, &item.SyncIntervalSeconds, &item.NextSyncAt, &item.SyncRequestedAt, &item.SyncStartedAt, &item.SyncAttemptID, &item.Enabled, &item.LastSyncStatus, &item.LastSyncError, &item.LastSyncedAt, &item.CreatedAt, &item.UpdatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return TemplateRepository{}, ErrNotFound
	}
	return item, err
}

func (s *Store) FinishTemplateRepositorySync(ctx context.Context, repository TemplateRepository, status, message string) error {
	return s.finishTemplateRepositorySync(ctx, repository, status, message, "", nil, false)
}

func (s *Store) FinishTemplateRepositorySyncWithAudit(ctx context.Context, repository TemplateRepository, status, message, remoteAddr string, metadata any) error {
	return s.finishTemplateRepositorySync(ctx, repository, status, message, remoteAddr, metadata, true)
}

func (s *Store) finishTemplateRepositorySync(ctx context.Context, repository TemplateRepository, status, message, remoteAddr string, metadata any, audit bool) error {
	if status != "succeeded" && status != "failed" {
		return errors.New("invalid template repository sync status")
	}
	if repository.SyncAttemptID == nil {
		return ErrBusy
	}
	tx, err := s.Pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	tag, err := tx.Exec(ctx, `UPDATE template_repositories SET last_sync_status=$3,last_sync_error=$4,last_synced_at=now(),sync_started_at=NULL,sync_attempt_id=NULL,next_sync_at=CASE WHEN sync_interval_seconds>0 THEN now()+(sync_interval_seconds * interval '1 second') ELSE NULL END,updated_at=now() WHERE id=$1 AND organization_id=$2 AND last_sync_status='running' AND sync_attempt_id=$5`, repository.ID, repository.OrganizationID, status, message, *repository.SyncAttemptID)
	if err == nil && tag.RowsAffected() == 0 {
		return ErrBusy
	}
	if err != nil {
		return err
	}
	if audit {
		if err = s.AuditOrganizationTx(ctx, tx, repository.OrganizationID, "template_repository.sync", "template_repository", repository.ID.String(), remoteAddr, metadata); err != nil {
			return err
		}
	}
	if status == "failed" {
		payload, marshalErr := json.Marshal(map[string]any{
			"event":                "template.sync.failed",
			"resourceType":         "template_repository_sync",
			"resourceId":           repository.SyncAttemptID.String(),
			"templateRepositoryId": repository.ID.String(),
			"error":                truncateStore(message, 8192),
			"occurredAt":           time.Now().UTC(),
			"text":                 "Dockyard template.sync.failed for template repository " + repository.ID.String(),
		})
		if marshalErr != nil {
			return marshalErr
		}
		if err = queueNotificationDeliveries(ctx, tx, repository.OrganizationID, "template.sync.failed", "template_repository_sync", repository.SyncAttemptID.String(), "", payload); err != nil {
			return err
		}
	}
	return tx.Commit(ctx)
}

func (s *Store) UpdateTemplateRepositorySettings(ctx context.Context, organizationID, id uuid.UUID, trustedPublicKey string, requireSignature bool, credentialID *uuid.UUID, syncIntervalSeconds int) error {
	tx, err := s.Pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	if err = updateTemplateRepositorySettingsTx(ctx, tx, organizationID, id, trustedPublicKey, requireSignature, credentialID, syncIntervalSeconds); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

func (s *Store) UpdateTemplateRepositorySettingsWithAudit(ctx context.Context, principal Principal, id uuid.UUID, trustedPublicKey string, requireSignature bool, credentialID *uuid.UUID, syncIntervalSeconds int, remoteAddr string, metadata any) error {
	tx, err := s.Pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	if err = updateTemplateRepositorySettingsTx(ctx, tx, principal.OrganizationID, id, trustedPublicKey, requireSignature, credentialID, syncIntervalSeconds); err != nil {
		return err
	}
	if err = appendPrincipalAudit(ctx, tx, principal, "template_repository.settings.update", "template_repository", id.String(), remoteAddr, metadata); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

func updateTemplateRepositorySettingsTx(ctx context.Context, tx pgx.Tx, organizationID, id uuid.UUID, trustedPublicKey string, requireSignature bool, credentialID *uuid.UUID, syncIntervalSeconds int) error {
	var currentKey string
	var currentRequireSignature bool
	var currentCredentialID *uuid.UUID
	err := tx.QueryRow(ctx, `SELECT trusted_public_key,require_signature,credential_id FROM template_repositories WHERE id=$1 AND organization_id=$2 FOR UPDATE`, id, organizationID).Scan(&currentKey, &currentRequireSignature, &currentCredentialID)
	if errors.Is(err, pgx.ErrNoRows) {
		return ErrNotFound
	}
	if err != nil {
		return err
	}
	if credentialID != nil {
		var lockedCredential uuid.UUID
		err = tx.QueryRow(ctx, `SELECT id FROM source_credentials WHERE id=$1 AND organization_id=$2 AND kind='git' AND lower(server)='github.com' FOR KEY SHARE`, *credentialID, organizationID).Scan(&lockedCredential)
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrNotFound
		}
		if err != nil {
			return err
		}
	}
	trustChanged := currentKey != trustedPublicKey || currentRequireSignature != requireSignature
	credentialChanged := !equalOptionalUUID(currentCredentialID, credentialID)
	if trustChanged {
		if _, err = tx.Exec(ctx, `DELETE FROM templates WHERE repository_id=$1 AND organization_id=$2`, id, organizationID); err != nil {
			return err
		}
		_, err = tx.Exec(ctx, `UPDATE template_repositories SET trusted_public_key=$3,require_signature=$4,credential_id=$5,sync_interval_seconds=$6,next_sync_at=CASE WHEN $6>0 THEN now() ELSE NULL END,sync_requested_at=now(),sync_started_at=NULL,sync_attempt_id=NULL,last_sync_status='never',last_sync_error='',last_synced_at=NULL,updated_at=now() WHERE id=$1 AND organization_id=$2`, id, organizationID, trustedPublicKey, requireSignature, credentialID, syncIntervalSeconds)
	} else if credentialChanged {
		_, err = tx.Exec(ctx, `UPDATE template_repositories SET trusted_public_key=$3,require_signature=$4,credential_id=$5,sync_interval_seconds=$6,next_sync_at=CASE WHEN $6>0 THEN now() ELSE NULL END,sync_requested_at=now(),sync_started_at=NULL,sync_attempt_id=NULL,last_sync_status=CASE WHEN last_sync_status='running' THEN 'failed' ELSE last_sync_status END,last_sync_error=CASE WHEN last_sync_status='running' THEN 'repository credential changed during synchronization' ELSE last_sync_error END,updated_at=now() WHERE id=$1 AND organization_id=$2`, id, organizationID, trustedPublicKey, requireSignature, credentialID, syncIntervalSeconds)
	} else {
		_, err = tx.Exec(ctx, `UPDATE template_repositories SET trusted_public_key=$3,require_signature=$4,credential_id=$5,sync_interval_seconds=$6,next_sync_at=CASE WHEN $6>0 THEN now() ELSE NULL END,updated_at=now() WHERE id=$1 AND organization_id=$2`, id, organizationID, trustedPublicKey, requireSignature, credentialID, syncIntervalSeconds)
	}
	if err != nil {
		return err
	}
	return nil
}

func equalOptionalUUID(left, right *uuid.UUID) bool {
	return left == nil && right == nil || left != nil && right != nil && *left == *right
}

func (s *Store) GetSourceCredential(ctx context.Context, organizationID, id uuid.UUID) (SourceCredential, error) {
	var item SourceCredential
	err := s.Pool.QueryRow(ctx, `SELECT id,organization_id,kind,name,server,username,encrypted_secret,created_at,updated_at FROM source_credentials WHERE id=$1 AND organization_id=$2`, id, organizationID).Scan(&item.ID, &item.OrganizationID, &item.Kind, &item.Name, &item.Server, &item.Username, &item.EncryptedSecret, &item.CreatedAt, &item.UpdatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return SourceCredential{}, ErrNotFound
	}
	return item, err
}

func (s *Store) DeleteTemplateRepository(ctx context.Context, organizationID, id uuid.UUID) error {
	tx, err := s.Pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	if err = deleteTemplateRepositoryTx(ctx, tx, organizationID, id); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

func (s *Store) DeleteTemplateRepositoryWithAudit(ctx context.Context, principal Principal, id uuid.UUID, remoteAddr string) error {
	tx, err := s.Pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	if err = deleteTemplateRepositoryTx(ctx, tx, principal.OrganizationID, id); err != nil {
		return err
	}
	if err = appendPrincipalAudit(ctx, tx, principal, "template_repository.delete", "template_repository", id.String(), remoteAddr, nil); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

func deleteTemplateRepositoryTx(ctx context.Context, tx pgx.Tx, organizationID, id uuid.UUID) error {
	if _, err := tx.Exec(ctx, `DELETE FROM templates WHERE repository_id=$1 AND organization_id=$2`, id, organizationID); err != nil {
		return err
	}
	tag, err := tx.Exec(ctx, `DELETE FROM template_repositories WHERE id=$1 AND organization_id=$2`, id, organizationID)
	if err == nil && tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	if err != nil {
		return err
	}
	return nil
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

// ReplaceRepositoryTemplatesForSync prevents a superseded scheduler attempt
// from publishing an older catalog snapshot after a stale-work takeover.
// Existing template instances retain their copied provenance when a removed
// catalog version is deleted because their template foreign key uses SET NULL.
func (s *Store) ReplaceRepositoryTemplatesForSync(ctx context.Context, repository TemplateRepository, items []Template) error {
	if repository.SyncAttemptID == nil {
		return ErrBusy
	}
	organizationID, repositoryID, attemptID := repository.OrganizationID, repository.ID, repository.SyncAttemptID
	if len(items) == 0 {
		return errors.New("repository catalog must contain at least one template")
	}
	tx, err := s.Pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	var currentAttemptID *uuid.UUID
	var syncStatus string
	if err = tx.QueryRow(ctx, `SELECT sync_attempt_id,last_sync_status FROM template_repositories WHERE id=$1 AND organization_id=$2 FOR UPDATE`, repositoryID, organizationID).Scan(&currentAttemptID, &syncStatus); errors.Is(err, pgx.ErrNoRows) {
		return ErrNotFound
	} else if err != nil {
		return err
	}
	if attemptID != nil && (currentAttemptID == nil || *currentAttemptID != *attemptID || syncStatus != "running") {
		return ErrBusy
	}
	if err = replaceRepositoryTemplatesTx(ctx, tx, repository, items); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

// PublishRepositoryTemplatesForSyncWithAudit commits a complete catalog
// snapshot, successful sync state, and system audit evidence atomically.
func (s *Store) PublishRepositoryTemplatesForSyncWithAudit(ctx context.Context, repository TemplateRepository, items []Template, remoteAddr string, metadata any) error {
	if repository.SyncAttemptID == nil {
		return ErrBusy
	}
	if len(items) == 0 {
		return errors.New("repository catalog must contain at least one template")
	}
	tx, err := s.Pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	var currentAttemptID *uuid.UUID
	var syncStatus string
	if err = tx.QueryRow(ctx, `SELECT sync_attempt_id,last_sync_status FROM template_repositories WHERE id=$1 AND organization_id=$2 FOR UPDATE`, repository.ID, repository.OrganizationID).Scan(&currentAttemptID, &syncStatus); errors.Is(err, pgx.ErrNoRows) {
		return ErrNotFound
	} else if err != nil {
		return err
	}
	if currentAttemptID == nil || *currentAttemptID != *repository.SyncAttemptID || syncStatus != "running" {
		return ErrBusy
	}
	if err = replaceRepositoryTemplatesTx(ctx, tx, repository, items); err != nil {
		return err
	}
	tag, err := tx.Exec(ctx, `UPDATE template_repositories SET last_sync_status='succeeded',last_sync_error='',last_synced_at=now(),sync_started_at=NULL,sync_attempt_id=NULL,next_sync_at=CASE WHEN sync_interval_seconds>0 THEN now()+(sync_interval_seconds * interval '1 second') ELSE NULL END,updated_at=now() WHERE id=$1 AND organization_id=$2 AND last_sync_status='running' AND sync_attempt_id=$3`, repository.ID, repository.OrganizationID, *repository.SyncAttemptID)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrBusy
	}
	if err = s.AuditOrganizationTx(ctx, tx, repository.OrganizationID, "template_repository.sync", "template_repository", repository.ID.String(), remoteAddr, metadata); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

func replaceRepositoryTemplatesTx(ctx context.Context, tx pgx.Tx, repository TemplateRepository, items []Template) error {
	organizationID, repositoryID := repository.OrganizationID, repository.ID
	ids := make([]uuid.UUID, 0, len(items))
	for _, item := range items {
		if item.RepositoryID == nil || item.OrganizationID == nil || *item.RepositoryID != repositoryID || *item.OrganizationID != organizationID {
			return errors.New("template repository scope mismatch")
		}
		item.ID = uuid.New()
		var id uuid.UUID
		if err := tx.QueryRow(ctx, `INSERT INTO templates(id,organization_id,repository_id,template_key,version,name,description,compose_yaml,config,source,source_path,checksum)
			VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)
			ON CONFLICT (organization_id,template_key,version) DO UPDATE SET repository_id=excluded.repository_id,name=excluded.name,description=excluded.description,compose_yaml=excluded.compose_yaml,config=excluded.config,source=excluded.source,source_path=excluded.source_path,checksum=excluded.checksum
			RETURNING id`, item.ID, organizationID, repositoryID, item.Key, item.Version, item.Name, item.Description, item.ComposeYAML, item.Config, item.Source, item.SourcePath, item.Checksum).Scan(&id); err != nil {
			return err
		}
		ids = append(ids, id)
	}
	if _, err := tx.Exec(ctx, `DELETE FROM templates WHERE repository_id=$1 AND organization_id=$2 AND NOT (id=ANY($3::uuid[]))`, repositoryID, organizationID, ids); err != nil {
		return err
	}
	return nil
}
