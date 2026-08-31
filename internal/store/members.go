package store

import (
	"context"
	"errors"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

type OrganizationMember struct {
	UserID        uuid.UUID `json:"userId"`
	Email         string    `json:"email"`
	DisplayName   string    `json:"displayName"`
	Role          string    `json:"role"`
	Active        bool      `json:"active"`
	ManagedBySCIM bool      `json:"managedByScim"`
	CreatedAt     time.Time `json:"createdAt"`
}

func ValidOrganizationRole(role string) bool {
	return role == "owner" || role == "admin" || role == "developer" || role == "viewer"
}

func (s *Store) ListOrganizationMembers(ctx context.Context, organizationID uuid.UUID) ([]OrganizationMember, error) {
	rows, err := s.Pool.Query(ctx, `SELECT m.user_id,u.email,u.display_name,m.role,u.disabled_at IS NULL,
		EXISTS(SELECT 1 FROM scim_user_defaults d WHERE d.organization_id=m.organization_id AND d.user_id=m.user_id),m.created_at
		FROM memberships m JOIN users u ON u.id=m.user_id
		WHERE m.organization_id=$1 ORDER BY lower(u.email),m.user_id`, organizationID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	items := []OrganizationMember{}
	for rows.Next() {
		var item OrganizationMember
		if err = rows.Scan(&item.UserID, &item.Email, &item.DisplayName, &item.Role, &item.Active, &item.ManagedBySCIM, &item.CreatedAt); err != nil {
			return nil, err
		}
		items = append(items, item)
	}
	return items, rows.Err()
}

func (s *Store) UpdateOrganizationMemberRole(ctx context.Context, organizationID, userID uuid.UUID, role, actorRole string) (OrganizationMember, error) {
	return s.updateOrganizationMemberRole(ctx, Principal{}, organizationID, userID, role, actorRole, "", false)
}

func (s *Store) UpdateOrganizationMemberRoleWithAudit(ctx context.Context, principal Principal, userID uuid.UUID, role, remoteAddr string) (OrganizationMember, error) {
	return s.updateOrganizationMemberRole(ctx, principal, principal.OrganizationID, userID, role, principal.Role, remoteAddr, true)
}

func (s *Store) updateOrganizationMemberRole(ctx context.Context, principal Principal, organizationID, userID uuid.UUID, role, actorRole, remoteAddr string, audit bool) (OrganizationMember, error) {
	if !ValidOrganizationRole(role) {
		return OrganizationMember{}, errors.New("invalid organization role")
	}
	tx, err := s.Pool.Begin(ctx)
	if err != nil {
		return OrganizationMember{}, err
	}
	defer tx.Rollback(ctx)
	item, err := updateOrganizationMemberRoleTx(ctx, tx, organizationID, userID, role, actorRole)
	if err != nil {
		return OrganizationMember{}, err
	}
	if audit {
		if err = appendPrincipalAudit(ctx, tx, principal, "membership.role.update", "user", userID.String(), remoteAddr, map[string]string{"role": item.Role}); err != nil {
			return OrganizationMember{}, err
		}
	}
	return item, tx.Commit(ctx)
}

func updateOrganizationMemberRoleTx(ctx context.Context, tx pgx.Tx, organizationID, userID uuid.UUID, role, actorRole string) (OrganizationMember, error) {
	var lockedOrganizationID uuid.UUID
	if err := tx.QueryRow(ctx, `SELECT id FROM organizations WHERE id=$1 FOR UPDATE`, organizationID).Scan(&lockedOrganizationID); errors.Is(err, pgx.ErrNoRows) {
		return OrganizationMember{}, ErrNotFound
	} else if err != nil {
		return OrganizationMember{}, err
	}
	item, err := organizationMemberForUpdate(ctx, tx, organizationID, userID)
	if err != nil {
		return OrganizationMember{}, err
	}
	if item.ManagedBySCIM {
		return OrganizationMember{}, ErrSCIMManaged
	}
	if actorRole != "owner" && (item.Role == "owner" || role == "owner") {
		return OrganizationMember{}, ErrOwnerRequired
	}
	if item.Role == "owner" && role != "owner" && item.Active {
		var owners int
		if err = tx.QueryRow(ctx, `SELECT count(*) FROM memberships m JOIN users u ON u.id=m.user_id WHERE m.organization_id=$1 AND m.role='owner' AND u.disabled_at IS NULL`, organizationID).Scan(&owners); err != nil {
			return OrganizationMember{}, err
		}
		if owners <= 1 {
			return OrganizationMember{}, ErrLastOwner
		}
	}
	if _, err = tx.Exec(ctx, `UPDATE memberships SET role=$3 WHERE organization_id=$1 AND user_id=$2`, organizationID, userID, role); err != nil {
		return OrganizationMember{}, err
	}
	item.Role = role
	return item, nil
}

func (s *Store) DeleteOrganizationMember(ctx context.Context, organizationID, userID uuid.UUID, actorRole string) error {
	return s.deleteOrganizationMember(ctx, Principal{}, organizationID, userID, actorRole, "", false)
}

func (s *Store) DeleteOrganizationMemberWithAudit(ctx context.Context, principal Principal, userID uuid.UUID, remoteAddr string) error {
	return s.deleteOrganizationMember(ctx, principal, principal.OrganizationID, userID, principal.Role, remoteAddr, true)
}

func (s *Store) deleteOrganizationMember(ctx context.Context, principal Principal, organizationID, userID uuid.UUID, actorRole, remoteAddr string, audit bool) error {
	tx, err := s.Pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	if err = deleteOrganizationMemberTx(ctx, tx, organizationID, userID, actorRole); err != nil {
		return err
	}
	if audit {
		if err = appendPrincipalAudit(ctx, tx, principal, "membership.remove", "user", userID.String(), remoteAddr, nil); err != nil {
			return err
		}
	}
	return tx.Commit(ctx)
}

func deleteOrganizationMemberTx(ctx context.Context, tx pgx.Tx, organizationID, userID uuid.UUID, actorRole string) error {
	var lockedOrganizationID uuid.UUID
	if err := tx.QueryRow(ctx, `SELECT id FROM organizations WHERE id=$1 FOR UPDATE`, organizationID).Scan(&lockedOrganizationID); errors.Is(err, pgx.ErrNoRows) {
		return ErrNotFound
	} else if err != nil {
		return err
	}
	item, err := organizationMemberForUpdate(ctx, tx, organizationID, userID)
	if err != nil {
		return err
	}
	if item.ManagedBySCIM {
		return ErrSCIMManaged
	}
	if actorRole != "owner" && item.Role == "owner" {
		return ErrOwnerRequired
	}
	if item.Role == "owner" && item.Active {
		var owners int
		if err = tx.QueryRow(ctx, `SELECT count(*) FROM memberships m JOIN users u ON u.id=m.user_id WHERE m.organization_id=$1 AND m.role='owner' AND u.disabled_at IS NULL`, organizationID).Scan(&owners); err != nil {
			return err
		}
		if owners <= 1 {
			return ErrLastOwner
		}
	}
	if _, err = tx.Exec(ctx, `DELETE FROM project_grants AS project_grant USING projects AS project WHERE project_grant.user_id=$1 AND project_grant.project_id=project.id AND project.organization_id=$2`, userID, organizationID); err != nil {
		return err
	}
	if _, err = tx.Exec(ctx, `DELETE FROM environment_grants AS environment_grant USING environments AS environment,projects AS project WHERE environment_grant.user_id=$1 AND environment_grant.environment_id=environment.id AND environment.project_id=project.id AND project.organization_id=$2`, userID, organizationID); err != nil {
		return err
	}
	if _, err = RevokeOrganizationMembershipSessionsTx(ctx, tx, organizationID, userID); err != nil {
		return err
	}
	if _, err = tx.Exec(ctx, `DELETE FROM memberships WHERE organization_id=$1 AND user_id=$2`, organizationID, userID); err != nil {
		return err
	}
	return nil
}

// RevokeOrganizationMembershipSessionsTx removes every session that could
// authorize the user in organizationID. Federated sessions are tenant-bound,
// while local sessions are deliberately unscoped so one login can enter any
// organization the user belongs to. The latter must also be revoked when a
// membership is removed; otherwise an old local token would regain access if
// the identity were later reprovisioned before that token expired.
func RevokeOrganizationMembershipSessionsTx(ctx context.Context, tx pgx.Tx, organizationID, userID uuid.UUID) (int64, error) {
	tag, err := tx.Exec(ctx, `DELETE FROM sessions WHERE user_id=$1 AND (organization_id=$2 OR organization_id IS NULL)`, userID, organizationID)
	if err != nil {
		return 0, err
	}
	return tag.RowsAffected(), nil
}

func organizationMemberForUpdate(ctx context.Context, tx pgx.Tx, organizationID, userID uuid.UUID) (OrganizationMember, error) {
	var item OrganizationMember
	err := tx.QueryRow(ctx, `SELECT m.user_id,u.email,u.display_name,m.role,u.disabled_at IS NULL,
		EXISTS(SELECT 1 FROM scim_user_defaults d WHERE d.organization_id=m.organization_id AND d.user_id=m.user_id),m.created_at
		FROM memberships m JOIN users u ON u.id=m.user_id
		WHERE m.organization_id=$1 AND m.user_id=$2 FOR UPDATE OF m`, organizationID, userID).Scan(&item.UserID, &item.Email, &item.DisplayName, &item.Role, &item.Active, &item.ManagedBySCIM, &item.CreatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return OrganizationMember{}, ErrNotFound
	}
	return item, err
}
