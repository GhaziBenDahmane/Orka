package store

import (
	"context"
	"errors"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

type SCIMToken struct {
	ID             uuid.UUID  `json:"id"`
	OrganizationID uuid.UUID  `json:"organizationId"`
	Name           string     `json:"name"`
	DefaultRole    string     `json:"defaultRole"`
	CreatedAt      time.Time  `json:"createdAt"`
	ExpiresAt      time.Time  `json:"expiresAt"`
	RevokedAt      *time.Time `json:"revokedAt,omitempty"`
}

func (s *Store) CreateSCIMToken(ctx context.Context, organizationID uuid.UUID, name, role string, hash []byte, expiresAt time.Time) (SCIMToken, error) {
	tx, err := s.Pool.Begin(ctx)
	if err != nil {
		return SCIMToken{}, err
	}
	defer tx.Rollback(ctx)
	item, err := createSCIMTokenTx(ctx, tx, organizationID, name, role, hash, expiresAt)
	if err != nil {
		return SCIMToken{}, err
	}
	return item, tx.Commit(ctx)
}

func (s *Store) CreateSCIMTokenWithAudit(ctx context.Context, principal Principal, name, role string, hash []byte, expiresAt time.Time, remoteAddr string) (SCIMToken, error) {
	tx, err := s.Pool.Begin(ctx)
	if err != nil {
		return SCIMToken{}, err
	}
	defer tx.Rollback(ctx)
	if _, err = lockOrganizationAndRequirePrincipalRole(ctx, tx, principal, "admin"); err != nil {
		return SCIMToken{}, err
	}
	item, err := createSCIMTokenTx(ctx, tx, principal.OrganizationID, name, role, hash, expiresAt)
	if err != nil {
		return SCIMToken{}, err
	}
	if err = appendPrincipalAudit(ctx, tx, principal, "scim.token.create", "scim_token", item.ID.String(), remoteAddr, map[string]any{"name": item.Name, "defaultRole": item.DefaultRole, "expiresAt": item.ExpiresAt}); err != nil {
		return SCIMToken{}, err
	}
	return item, tx.Commit(ctx)
}

func createSCIMTokenTx(ctx context.Context, tx pgx.Tx, organizationID uuid.UUID, name, role string, hash []byte, expiresAt time.Time) (SCIMToken, error) {
	item := SCIMToken{ID: uuid.New(), OrganizationID: organizationID, Name: name, DefaultRole: role, ExpiresAt: expiresAt}
	err := tx.QueryRow(ctx, `INSERT INTO scim_tokens(id,organization_id,name,token_hash,default_role,expires_at) SELECT $1,o.id,$3,$4,$5,$6 FROM organizations o WHERE o.id=$2 RETURNING created_at`, item.ID, organizationID, name, hash, role, expiresAt).Scan(&item.CreatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return SCIMToken{}, ErrNotFound
	}
	return item, err
}

func (s *Store) ListSCIMTokens(ctx context.Context, organizationID uuid.UUID) ([]SCIMToken, error) {
	rows, err := s.Pool.Query(ctx, `SELECT id,organization_id,name,default_role,created_at,expires_at,revoked_at FROM scim_tokens WHERE organization_id=$1 ORDER BY created_at DESC,id`, organizationID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	items := []SCIMToken{}
	for rows.Next() {
		var item SCIMToken
		if err = rows.Scan(&item.ID, &item.OrganizationID, &item.Name, &item.DefaultRole, &item.CreatedAt, &item.ExpiresAt, &item.RevokedAt); err != nil {
			return nil, err
		}
		items = append(items, item)
	}
	return items, rows.Err()
}

func (s *Store) RevokeSCIMToken(ctx context.Context, organizationID, tokenID uuid.UUID) error {
	tx, err := s.Pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	if err = revokeSCIMTokenTx(ctx, tx, organizationID, tokenID); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

func (s *Store) RevokeSCIMTokenWithAudit(ctx context.Context, principal Principal, tokenID uuid.UUID, remoteAddr string) error {
	tx, err := s.Pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	if _, err = lockOrganizationAndRequirePrincipalRole(ctx, tx, principal, "admin"); err != nil {
		return err
	}
	if err = revokeSCIMTokenTx(ctx, tx, principal.OrganizationID, tokenID); err != nil {
		return err
	}
	if err = appendPrincipalAudit(ctx, tx, principal, "scim.token.revoke", "scim_token", tokenID.String(), remoteAddr, nil); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

func revokeSCIMTokenTx(ctx context.Context, tx pgx.Tx, organizationID, tokenID uuid.UUID) error {
	tag, err := tx.Exec(ctx, `UPDATE scim_tokens SET revoked_at=now() WHERE id=$1 AND organization_id=$2 AND revoked_at IS NULL`, tokenID, organizationID)
	if err == nil && tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return err
}
