package store

import (
	"context"
	"errors"
	"sort"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// lockOrganizationAndRequirePrincipalRole closes the gap between HTTP
// authorization and a later administrative mutation. The organization row is
// the identity subsystem's first lock, so an in-flight demotion, removal, user
// disable, or service-account disable commits before this function re-reads
// the actor's current authority.
func lockOrganizationAndRequirePrincipalRole(ctx context.Context, tx pgx.Tx, principal Principal, minimum string) (string, error) {
	minimumRank := organizationRoleRank(minimum)
	if minimumRank == 0 {
		return "", errors.New("invalid minimum organization role")
	}
	var organizationID uuid.UUID
	if err := tx.QueryRow(ctx, `SELECT id FROM organizations WHERE id=$1 FOR UPDATE`, principal.OrganizationID).Scan(&organizationID); errors.Is(err, pgx.ErrNoRows) {
		return "", ErrNotFound
	} else if err != nil {
		return "", err
	}

	var role string
	if principal.ServiceAccountID != nil {
		if principal.UserID != uuid.Nil {
			return "", ErrInsufficientRole
		}
		err := tx.QueryRow(ctx, `SELECT role FROM service_accounts WHERE id=$1 AND organization_id=$2 AND enabled FOR UPDATE`, *principal.ServiceAccountID, principal.OrganizationID).Scan(&role)
		if errors.Is(err, pgx.ErrNoRows) {
			return "", ErrInsufficientRole
		}
		if err != nil {
			return "", err
		}
		if principal.ServiceAccountTokenID != nil {
			var tokenID uuid.UUID
			err = tx.QueryRow(ctx, `SELECT id FROM service_account_tokens WHERE id=$1 AND service_account_id=$2 AND revoked_at IS NULL AND expires_at>now() FOR UPDATE`, *principal.ServiceAccountTokenID, *principal.ServiceAccountID).Scan(&tokenID)
			if errors.Is(err, pgx.ErrNoRows) {
				return "", ErrInsufficientRole
			}
			if err != nil {
				return "", err
			}
		}
	} else {
		if principal.UserID == uuid.Nil {
			return "", ErrInsufficientRole
		}
		err := tx.QueryRow(ctx, `SELECT membership.role
			FROM memberships membership
			JOIN users actor ON actor.id=membership.user_id
			WHERE membership.organization_id=$1 AND membership.user_id=$2 AND actor.disabled_at IS NULL
			FOR UPDATE OF membership,actor`, principal.OrganizationID, principal.UserID).Scan(&role)
		if errors.Is(err, pgx.ErrNoRows) {
			return "", ErrInsufficientRole
		}
		if err != nil {
			return "", err
		}
		if principal.SessionID != uuid.Nil {
			var sessionID uuid.UUID
			err = tx.QueryRow(ctx, `SELECT id FROM sessions WHERE id=$1 AND user_id=$2 AND expires_at>now() AND (organization_id IS NULL OR organization_id=$3) FOR UPDATE`, principal.SessionID, principal.UserID, principal.OrganizationID).Scan(&sessionID)
			if errors.Is(err, pgx.ErrNoRows) {
				return "", ErrInsufficientRole
			}
			if err != nil {
				return "", err
			}
		}
	}
	if organizationRoleRank(role) < minimumRank {
		return "", ErrInsufficientRole
	}
	return role, nil
}

func organizationRoleRank(role string) int {
	switch role {
	case "viewer":
		return 1
	case "developer":
		return 2
	case "admin":
		return 3
	case "owner":
		return 4
	default:
		return 0
	}
}

// lockAuthenticatedPrincipalCredential revalidates the exact credential that
// entered an authenticated HTTP request. Callers without a credential binding
// are internal workflows (for example bootstrap and invitation acceptance)
// and retain the existing audit foreign-key validation.
func lockAuthenticatedPrincipalCredential(ctx context.Context, tx pgx.Tx, principal Principal) error {
	if principal.ServiceAccountTokenID != nil {
		if principal.ServiceAccountID == nil || principal.UserID != uuid.Nil {
			return ErrInsufficientRole
		}
		var role string
		err := tx.QueryRow(ctx, `SELECT account.role
			FROM service_accounts account
			WHERE account.id=$1 AND account.organization_id=$2 AND account.enabled
			FOR UPDATE`, *principal.ServiceAccountID, principal.OrganizationID).Scan(&role)
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrInsufficientRole
		}
		if err != nil {
			return err
		}
		if !currentRoleCoversAuthenticatedRole(role, principal.Role) {
			return ErrInsufficientRole
		}
		var tokenID uuid.UUID
		err = tx.QueryRow(ctx, `SELECT id FROM service_account_tokens WHERE id=$1 AND service_account_id=$2 AND revoked_at IS NULL AND expires_at>now() FOR UPDATE`, *principal.ServiceAccountTokenID, *principal.ServiceAccountID).Scan(&tokenID)
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrInsufficientRole
		}
		if err != nil {
			return err
		}
		return lockScopedAuthorizations(ctx, tx, principal, role)
	}
	if principal.SessionID != uuid.Nil {
		if principal.ServiceAccountID != nil || principal.UserID == uuid.Nil {
			return ErrInsufficientRole
		}
		var role string
		err := tx.QueryRow(ctx, `SELECT membership.role
			FROM memberships membership
			JOIN users actor ON actor.id=membership.user_id
			WHERE membership.organization_id=$1 AND membership.user_id=$2 AND actor.disabled_at IS NULL
			FOR UPDATE OF membership,actor`, principal.OrganizationID, principal.UserID).Scan(&role)
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrInsufficientRole
		}
		if err != nil {
			return err
		}
		if !currentRoleCoversAuthenticatedRole(role, principal.Role) {
			return ErrInsufficientRole
		}
		var sessionID uuid.UUID
		err = tx.QueryRow(ctx, `SELECT id FROM sessions WHERE id=$1 AND user_id=$2 AND expires_at>now() AND (organization_id IS NULL OR organization_id=$3) FOR UPDATE`, principal.SessionID, principal.UserID, principal.OrganizationID).Scan(&sessionID)
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrInsufficientRole
		}
		if err != nil {
			return err
		}
		return lockScopedAuthorizations(ctx, tx, principal, role)
	}
	if len(principal.ScopedAuthorizations) != 0 {
		return ErrInsufficientRole
	}
	return nil
}

func lockScopedAuthorizations(ctx context.Context, tx pgx.Tx, principal Principal, currentRole string) error {
	if len(principal.ScopedAuthorizations) == 0 {
		return nil
	}
	if principal.ServiceAccountID != nil || principal.UserID == uuid.Nil {
		return ErrInsufficientRole
	}
	claims := append([]ScopedAuthorization(nil), principal.ScopedAuthorizations...)
	sort.Slice(claims, func(i, j int) bool {
		left, right := claims[i].ProjectID.String()+claims[i].EnvironmentID.String(), claims[j].ProjectID.String()+claims[j].EnvironmentID.String()
		return left < right
	})
	for _, claim := range claims {
		if roleValue(claim.MinimumRole) == 0 || claim.ProjectID == uuid.Nil {
			return ErrInsufficientRole
		}
		effectiveRole := currentRole
		var projectRole string
		err := tx.QueryRow(ctx, `SELECT role FROM project_grants WHERE project_id=$1 AND user_id=$2 FOR UPDATE`, claim.ProjectID, principal.UserID).Scan(&projectRole)
		if err != nil && !errors.Is(err, pgx.ErrNoRows) {
			return err
		}
		if err == nil && roleValue(projectRole) > roleValue(effectiveRole) {
			effectiveRole = projectRole
		}
		if claim.EnvironmentID != uuid.Nil {
			var environmentRole string
			err = tx.QueryRow(ctx, `SELECT role FROM environment_grants WHERE environment_id=$1 AND user_id=$2 FOR UPDATE`, claim.EnvironmentID, principal.UserID).Scan(&environmentRole)
			if err != nil && !errors.Is(err, pgx.ErrNoRows) {
				return err
			}
			if err == nil && roleValue(environmentRole) > roleValue(effectiveRole) {
				effectiveRole = environmentRole
			}
		}
		if roleValue(effectiveRole) < roleValue(claim.MinimumRole) {
			return ErrInsufficientRole
		}
	}
	return nil
}

func currentRoleCoversAuthenticatedRole(current, authenticated string) bool {
	if authenticated == "" {
		return true
	}
	authenticatedRank := organizationRoleRank(authenticated)
	if authenticatedRank == 0 {
		return current == authenticated
	}
	return organizationRoleRank(current) >= authenticatedRank
}
