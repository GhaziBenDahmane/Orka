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
	if !ValidOrganizationRole(role) {
		return OrganizationInvitation{}, errors.New("invalid organization role")
	}
	if role == "owner" && actorRole != "owner" {
		return OrganizationInvitation{}, ErrOwnerRequired
	}
	email = strings.ToLower(strings.TrimSpace(email))
	tx, err := s.Pool.Begin(ctx)
	if err != nil {
		return OrganizationInvitation{}, err
	}
	defer tx.Rollback(ctx)
	var lockedOrganizationID uuid.UUID
	if err = tx.QueryRow(ctx, `SELECT id FROM organizations WHERE id=$1 FOR UPDATE`, organizationID).Scan(&lockedOrganizationID); errors.Is(err, pgx.ErrNoRows) {
		return OrganizationInvitation{}, ErrNotFound
	} else if err != nil {
		return OrganizationInvitation{}, err
	}
	var member bool
	if err = tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM memberships m JOIN users u ON u.id=m.user_id WHERE m.organization_id=$1 AND u.email=$2)`, organizationID, email).Scan(&member); err != nil {
		return OrganizationInvitation{}, err
	}
	if member {
		return OrganizationInvitation{}, ErrAlreadyMember
	}
	if _, err = tx.Exec(ctx, `UPDATE organization_invitations SET revoked_at=now() WHERE organization_id=$1 AND email=$2 AND accepted_at IS NULL AND revoked_at IS NULL`, organizationID, email); err != nil {
		return OrganizationInvitation{}, err
	}
	item := OrganizationInvitation{ID: uuid.New(), OrganizationID: organizationID, Email: email, Role: role, ExpiresAt: expiresAt}
	err = tx.QueryRow(ctx, `INSERT INTO organization_invitations(id,organization_id,email,role,token_hash,created_by,expires_at) VALUES($1,$2,$3,$4,$5,$6,$7) RETURNING created_at`, item.ID, organizationID, email, role, tokenHash, creatorID, expiresAt).Scan(&item.CreatedAt)
	if err != nil {
		return OrganizationInvitation{}, err
	}
	return item, tx.Commit(ctx)
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

func (s *Store) RevokeOrganizationInvitation(ctx context.Context, organizationID, invitationID uuid.UUID) error {
	tag, err := s.Pool.Exec(ctx, `UPDATE organization_invitations SET revoked_at=now() WHERE id=$1 AND organization_id=$2 AND accepted_at IS NULL AND revoked_at IS NULL`, invitationID, organizationID)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

func (s *Store) AcceptOrganizationInvitation(ctx context.Context, tokenHash []byte, displayName, passwordHash string) (InvitationAcceptance, error) {
	tx, err := s.Pool.Begin(ctx)
	if err != nil {
		return InvitationAcceptance{}, err
	}
	defer tx.Rollback(ctx)
	var invitationID uuid.UUID
	var acceptance InvitationAcceptance
	if err = tx.QueryRow(ctx, `SELECT organization_id FROM organization_invitations WHERE token_hash=$1 AND accepted_at IS NULL AND revoked_at IS NULL AND expires_at>now()`, tokenHash).Scan(&acceptance.OrganizationID); errors.Is(err, pgx.ErrNoRows) {
		return InvitationAcceptance{}, ErrNotFound
	} else if err != nil {
		return InvitationAcceptance{}, err
	}
	var lockedOrganizationID uuid.UUID
	if err = tx.QueryRow(ctx, `SELECT id FROM organizations WHERE id=$1 FOR UPDATE`, acceptance.OrganizationID).Scan(&lockedOrganizationID); errors.Is(err, pgx.ErrNoRows) {
		return InvitationAcceptance{}, ErrNotFound
	} else if err != nil {
		return InvitationAcceptance{}, err
	}
	err = tx.QueryRow(ctx, `SELECT i.id,i.organization_id,o.name,i.email,i.role,COALESCE(a.require_sso,false) FROM organization_invitations i JOIN organizations o ON o.id=i.organization_id LEFT JOIN organization_auth_settings a ON a.organization_id=i.organization_id WHERE i.token_hash=$1 AND i.organization_id=$2 AND i.accepted_at IS NULL AND i.revoked_at IS NULL AND i.expires_at>now() FOR UPDATE OF i`, tokenHash, acceptance.OrganizationID).Scan(&invitationID, &acceptance.OrganizationID, &acceptance.Organization, &acceptance.Email, &acceptance.Role, &acceptance.RequireSSO)
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
	err = tx.QueryRow(ctx, `SELECT id,disabled_at FROM users WHERE email=$1`, acceptance.Email).Scan(&acceptance.UserID, &disabledAt)
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
	if _, err = tx.Exec(ctx, `INSERT INTO memberships(organization_id,user_id,role) VALUES($1,$2,$3) ON CONFLICT(organization_id,user_id) DO NOTHING`, acceptance.OrganizationID, acceptance.UserID, acceptance.Role); err != nil {
		return InvitationAcceptance{}, err
	}
	if _, err = tx.Exec(ctx, `UPDATE organization_invitations SET accepted_at=now(),accepted_user_id=$2 WHERE id=$1`, invitationID, acceptance.UserID); err != nil {
		return InvitationAcceptance{}, err
	}
	return acceptance, tx.Commit(ctx)
}
