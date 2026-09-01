package store

import (
	"context"
	"errors"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

type OrganizationInvitation struct {
	ID             uuid.UUID  `json:"id"`
	OrganizationID uuid.UUID  `json:"organizationId"`
	Email          string     `json:"email"`
	Role           string     `json:"role"`
	ExpiresAt      time.Time  `json:"expiresAt"`
	AcceptedAt     *time.Time `json:"acceptedAt,omitempty"`
	RevokedAt      *time.Time `json:"revokedAt,omitempty"`
	CreatedAt      time.Time  `json:"createdAt"`
}

type InvitationAcceptance struct {
	InvitationID   uuid.UUID `json:"-"`
	UserID         uuid.UUID `json:"userId"`
	OrganizationID uuid.UUID `json:"organizationId"`
	Organization   string    `json:"organization"`
	Email          string    `json:"email"`
	Role           string    `json:"role"`
	RequireSSO     bool      `json:"requireSso"`
}

func (s *Store) CreateOrganizationInvitation(ctx context.Context, organizationID, creatorID uuid.UUID, email, role, actorRole string, tokenHash []byte, expiresAt time.Time) (OrganizationInvitation, error) {
	return s.createOrganizationInvitation(ctx, Principal{}, organizationID, &creatorID, email, role, actorRole, tokenHash, expiresAt, "", false)
}

func (s *Store) CreateOrganizationInvitationWithAudit(ctx context.Context, principal Principal, email, role string, tokenHash []byte, expiresAt time.Time, remoteAddr string) (OrganizationInvitation, error) {
	var creatorID *uuid.UUID
	if principal.ServiceAccountID == nil && principal.UserID != uuid.Nil {
		creatorID = &principal.UserID
	}
	return s.createOrganizationInvitation(ctx, principal, principal.OrganizationID, creatorID, email, role, principal.Role, tokenHash, expiresAt, remoteAddr, true)
}

func (s *Store) createOrganizationInvitation(ctx context.Context, principal Principal, organizationID uuid.UUID, creatorID *uuid.UUID, email, role, actorRole string, tokenHash []byte, expiresAt time.Time, remoteAddr string, audit bool) (OrganizationInvitation, error) {
	if !ValidOrganizationRole(role) {
		return OrganizationInvitation{}, errors.New("invalid organization role")
	}
	email = strings.ToLower(strings.TrimSpace(email))
	tx, err := s.Pool.Begin(ctx)
	if err != nil {
		return OrganizationInvitation{}, err
	}
	defer tx.Rollback(ctx)
	if audit {
		actorRole, err = lockOrganizationAndRequirePrincipalRole(ctx, tx, principal, "admin")
		if err != nil {
			return OrganizationInvitation{}, err
		}
	}
	if role == "owner" && actorRole != "owner" {
		return OrganizationInvitation{}, ErrOwnerRequired
	}
	item, err := createOrganizationInvitationTx(ctx, tx, organizationID, creatorID, email, role, tokenHash, expiresAt)
	if err != nil {
		return OrganizationInvitation{}, err
	}
	if audit {
		if err = appendPrincipalAudit(ctx, tx, principal, "invitation.create", "invitation", item.ID.String(), remoteAddr, map[string]any{"email": item.Email, "role": item.Role, "expiresAt": item.ExpiresAt}); err != nil {
			return OrganizationInvitation{}, err
		}
	}
	return item, tx.Commit(ctx)
}

func createOrganizationInvitationTx(ctx context.Context, tx pgx.Tx, organizationID uuid.UUID, creatorID *uuid.UUID, email, role string, tokenHash []byte, expiresAt time.Time) (OrganizationInvitation, error) {
	var lockedOrganizationID uuid.UUID
	if err := tx.QueryRow(ctx, `SELECT id FROM organizations WHERE id=$1 FOR UPDATE`, organizationID).Scan(&lockedOrganizationID); errors.Is(err, pgx.ErrNoRows) {
		return OrganizationInvitation{}, ErrNotFound
	} else if err != nil {
		return OrganizationInvitation{}, err
	}
	var member, scimManaged bool
	if err := tx.QueryRow(ctx, `SELECT
		EXISTS(SELECT 1 FROM memberships m JOIN users u ON u.id=m.user_id WHERE m.organization_id=$1 AND u.email=$2),
		EXISTS(SELECT 1 FROM scim_user_defaults d JOIN users u ON u.id=d.user_id WHERE d.organization_id=$1 AND u.email=$2)`, organizationID, email).Scan(&member, &scimManaged); err != nil {
		return OrganizationInvitation{}, err
	}
	if member {
		return OrganizationInvitation{}, ErrAlreadyMember
	}
	if scimManaged {
		return OrganizationInvitation{}, ErrSCIMManaged
	}
	if _, err := tx.Exec(ctx, `UPDATE organization_invitations SET revoked_at=now() WHERE organization_id=$1 AND email=$2 AND accepted_at IS NULL AND revoked_at IS NULL`, organizationID, email); err != nil {
		return OrganizationInvitation{}, err
	}
	item := OrganizationInvitation{ID: uuid.New(), OrganizationID: organizationID, Email: email, Role: role, ExpiresAt: expiresAt}
	err := tx.QueryRow(ctx, `INSERT INTO organization_invitations(id,organization_id,email,role,token_hash,created_by,expires_at) VALUES($1,$2,$3,$4,$5,$6,$7) RETURNING created_at`, item.ID, organizationID, email, role, tokenHash, creatorID, expiresAt).Scan(&item.CreatedAt)
	if err != nil {
		return OrganizationInvitation{}, err
	}
	return item, nil
}

func (s *Store) ListOrganizationInvitations(ctx context.Context, organizationID uuid.UUID) ([]OrganizationInvitation, error) {
	rows, err := s.Pool.Query(ctx, `SELECT id,organization_id,email,role,expires_at,accepted_at,revoked_at,created_at FROM organization_invitations WHERE organization_id=$1 ORDER BY created_at DESC LIMIT 200`, organizationID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	items := []OrganizationInvitation{}
	for rows.Next() {
		var item OrganizationInvitation
		if err = rows.Scan(&item.ID, &item.OrganizationID, &item.Email, &item.Role, &item.ExpiresAt, &item.AcceptedAt, &item.RevokedAt, &item.CreatedAt); err != nil {
			return nil, err
		}
		items = append(items, item)
	}
	return items, rows.Err()
}

func (s *Store) GetOrganizationInvitation(ctx context.Context, organizationID, invitationID uuid.UUID) (OrganizationInvitation, error) {
	var item OrganizationInvitation
	err := s.Pool.QueryRow(ctx, `SELECT id,organization_id,email,role,expires_at,accepted_at,revoked_at,created_at FROM organization_invitations WHERE id=$1 AND organization_id=$2`, invitationID, organizationID).Scan(
		&item.ID, &item.OrganizationID, &item.Email, &item.Role, &item.ExpiresAt, &item.AcceptedAt, &item.RevokedAt, &item.CreatedAt,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return OrganizationInvitation{}, ErrNotFound
	}
	return item, err
}

func (s *Store) RevokeOrganizationInvitation(ctx context.Context, organizationID, invitationID uuid.UUID) error {
	tx, err := s.Pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	if err = revokeOrganizationInvitationTx(ctx, tx, organizationID, invitationID); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

func (s *Store) RevokeOrganizationInvitationWithAudit(ctx context.Context, principal Principal, invitationID uuid.UUID, remoteAddr string) error {
	tx, err := s.Pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	if _, err = lockOrganizationAndRequirePrincipalRole(ctx, tx, principal, "admin"); err != nil {
		return err
	}
	if err = revokeOrganizationInvitationTx(ctx, tx, principal.OrganizationID, invitationID); err != nil {
		return err
	}
	if err = appendPrincipalAudit(ctx, tx, principal, "invitation.revoke", "invitation", invitationID.String(), remoteAddr, nil); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

func revokeOrganizationInvitationTx(ctx context.Context, tx pgx.Tx, organizationID, invitationID uuid.UUID) error {
	tag, err := tx.Exec(ctx, `UPDATE organization_invitations SET revoked_at=now() WHERE id=$1 AND organization_id=$2 AND accepted_at IS NULL AND revoked_at IS NULL`, invitationID, organizationID)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

func (s *Store) AcceptOrganizationInvitation(ctx context.Context, tokenHash []byte, displayName, passwordHash string) (InvitationAcceptance, error) {
	return s.acceptOrganizationInvitation(ctx, tokenHash, displayName, passwordHash, "", false)
}

func (s *Store) AcceptOrganizationInvitationWithAudit(ctx context.Context, tokenHash []byte, displayName, passwordHash, remoteAddr string) (InvitationAcceptance, error) {
	return s.acceptOrganizationInvitation(ctx, tokenHash, displayName, passwordHash, remoteAddr, true)
}

func (s *Store) acceptOrganizationInvitation(ctx context.Context, tokenHash []byte, displayName, passwordHash, remoteAddr string, audit bool) (InvitationAcceptance, error) {
	tx, err := s.Pool.Begin(ctx)
	if err != nil {
		return InvitationAcceptance{}, err
	}
	defer tx.Rollback(ctx)
	acceptance, err := acceptOrganizationInvitationTx(ctx, tx, tokenHash, displayName, passwordHash)
	if err != nil {
		return InvitationAcceptance{}, err
	}
	if audit {
		principal := Principal{UserID: acceptance.UserID, OrganizationID: acceptance.OrganizationID, Organization: acceptance.Organization, Email: acceptance.Email, Role: acceptance.Role}
		if err = appendPrincipalAudit(ctx, tx, principal, "invitation.accept", "invitation", acceptance.InvitationID.String(), remoteAddr, map[string]any{"email": acceptance.Email, "role": acceptance.Role}); err != nil {
			return InvitationAcceptance{}, err
		}
	}
	return acceptance, tx.Commit(ctx)
}

func acceptOrganizationInvitationTx(ctx context.Context, tx pgx.Tx, tokenHash []byte, displayName, passwordHash string) (InvitationAcceptance, error) {
	var invitationID uuid.UUID
	var acceptance InvitationAcceptance
	if err := tx.QueryRow(ctx, `SELECT organization_id FROM organization_invitations WHERE token_hash=$1 AND accepted_at IS NULL AND revoked_at IS NULL AND expires_at>now()`, tokenHash).Scan(&acceptance.OrganizationID); errors.Is(err, pgx.ErrNoRows) {
		return InvitationAcceptance{}, ErrNotFound
	} else if err != nil {
		return InvitationAcceptance{}, err
	}
	var lockedOrganizationID uuid.UUID
	if err := tx.QueryRow(ctx, `SELECT id FROM organizations WHERE id=$1 FOR UPDATE`, acceptance.OrganizationID).Scan(&lockedOrganizationID); errors.Is(err, pgx.ErrNoRows) {
		return InvitationAcceptance{}, ErrNotFound
	} else if err != nil {
		return InvitationAcceptance{}, err
	}
	err := tx.QueryRow(ctx, `SELECT i.id,i.organization_id,o.name,i.email,i.role,COALESCE(a.require_sso,false) FROM organization_invitations i JOIN organizations o ON o.id=i.organization_id LEFT JOIN organization_auth_settings a ON a.organization_id=i.organization_id WHERE i.token_hash=$1 AND i.organization_id=$2 AND i.accepted_at IS NULL AND i.revoked_at IS NULL AND i.expires_at>now() FOR UPDATE OF i`, tokenHash, acceptance.OrganizationID).Scan(&invitationID, &acceptance.OrganizationID, &acceptance.Organization, &acceptance.Email, &acceptance.Role, &acceptance.RequireSSO)
	if errors.Is(err, pgx.ErrNoRows) {
		return InvitationAcceptance{}, ErrNotFound
	}
	if err != nil {
		return InvitationAcceptance{}, err
	}
	if _, err = tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1,0))`, acceptance.Email); err != nil {
		return InvitationAcceptance{}, err
	}
	acceptance.InvitationID = invitationID
	var disabledAt *time.Time
	err = tx.QueryRow(ctx, `SELECT id,disabled_at FROM users WHERE email=$1 FOR UPDATE`, acceptance.Email).Scan(&acceptance.UserID, &disabledAt)
	if errors.Is(err, pgx.ErrNoRows) {
		if !acceptance.RequireSSO && passwordHash == "" {
			return InvitationAcceptance{}, ErrPasswordRequired
		}
		acceptance.UserID = uuid.New()
		if displayName = strings.TrimSpace(displayName); displayName == "" {
			displayName = strings.SplitN(acceptance.Email, "@", 2)[0]
		}
		if acceptance.RequireSSO {
			passwordHash = "!invite:" + uuid.NewString()
		}
		_, err = tx.Exec(ctx, `INSERT INTO users(id,email,password_hash,display_name) VALUES($1,$2,$3,$4)`, acceptance.UserID, acceptance.Email, passwordHash, displayName)
	} else if err == nil && disabledAt != nil {
		return InvitationAcceptance{}, ErrUserDisabled
	}
	if err != nil {
		return InvitationAcceptance{}, err
	}
	var scimManaged bool
	if err = tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM scim_user_defaults WHERE organization_id=$1 AND user_id=$2)`, acceptance.OrganizationID, acceptance.UserID).Scan(&scimManaged); err != nil {
		return InvitationAcceptance{}, err
	}
	if scimManaged {
		return InvitationAcceptance{}, ErrSCIMManaged
	}
	if _, err = tx.Exec(ctx, `INSERT INTO memberships(organization_id,user_id,role) VALUES($1,$2,$3) ON CONFLICT(organization_id,user_id) DO NOTHING`, acceptance.OrganizationID, acceptance.UserID, acceptance.Role); err != nil {
		return InvitationAcceptance{}, err
	}
	if _, err = tx.Exec(ctx, `UPDATE organization_invitations SET accepted_at=now(),accepted_user_id=$2 WHERE id=$1`, invitationID, acceptance.UserID); err != nil {
		return InvitationAcceptance{}, err
	}
	return acceptance, nil
}
