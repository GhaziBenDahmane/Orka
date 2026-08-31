package store

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// CreateSessionWithAudit makes authentication success and session issuance one
// durable transition. Unscoped local sessions are visible in every tenant the
// identity can enter, so their login event is appended to each membership's
// audit chain. Federated sessions and events remain bound to their IdP tenant.
func (s *Store) CreateSessionWithAudit(ctx context.Context, userID uuid.UUID, organizationID, providerID *uuid.UUID, providerRevision int64, tokenHash []byte, expires time.Time, authMethod, expectedPasswordHash, userAgent, ipAddress, remoteAddr string, metadata any) (uuid.UUID, error) {
	switch authMethod {
	case "local":
		if expectedPasswordHash == "" || organizationID != nil || providerID != nil || providerRevision != 0 {
			return uuid.Nil, ErrAuthenticationStateChanged
		}
	case "oidc", "saml":
		if expectedPasswordHash != "" || organizationID == nil || providerID == nil || providerRevision < 1 {
			return uuid.Nil, errors.New("federated session requires organization and provider binding")
		}
	default:
		return uuid.Nil, errors.New("unsupported audited authentication method")
	}
	auditMetadata, err := json.Marshal(metadata)
	if err != nil {
		return uuid.Nil, err
	}
	tx, err := s.Pool.Begin(ctx)
	if err != nil {
		return uuid.Nil, err
	}
	defer tx.Rollback(ctx)
	var currentPasswordHash string
	err = tx.QueryRow(ctx, `SELECT password_hash FROM users WHERE id=$1 AND disabled_at IS NULL FOR UPDATE`, userID).Scan(&currentPasswordHash)
	if errors.Is(err, pgx.ErrNoRows) {
		if authMethod == "local" {
			return uuid.Nil, ErrAuthenticationStateChanged
		}
		return uuid.Nil, ErrNotFound
	}
	if err != nil {
		return uuid.Nil, err
	}
	if authMethod == "local" && currentPasswordHash != expectedPasswordHash {
		return uuid.Nil, ErrAuthenticationStateChanged
	}
	var oidcProviderID, samlProviderID *uuid.UUID
	if authMethod == "oidc" {
		oidcProviderID = providerID
		var enabled bool
		var currentRevision int64
		if err = tx.QueryRow(ctx, `SELECT enabled,revision FROM oidc_providers WHERE id=$1 AND organization_id=$2 FOR KEY SHARE`, *providerID, *organizationID).Scan(&enabled, &currentRevision); errors.Is(err, pgx.ErrNoRows) || err == nil && !enabled {
			return uuid.Nil, ErrNotFound
		} else if err != nil {
			return uuid.Nil, err
		} else if currentRevision != providerRevision {
			return uuid.Nil, ErrAuthenticationStateChanged
		}
	} else if authMethod == "saml" {
		samlProviderID = providerID
		var enabled bool
		var currentRevision int64
		if err = tx.QueryRow(ctx, `SELECT enabled,revision FROM saml_providers WHERE id=$1 AND organization_id=$2 FOR KEY SHARE`, *providerID, *organizationID).Scan(&enabled, &currentRevision); errors.Is(err, pgx.ErrNoRows) || err == nil && !enabled {
			return uuid.Nil, ErrNotFound
		} else if err != nil {
			return uuid.Nil, err
		} else if currentRevision != providerRevision {
			return uuid.Nil, ErrAuthenticationStateChanged
		}
	}
	if err = lockSessionMemberships(ctx, tx, userID, organizationID); err != nil {
		return uuid.Nil, err
	}
	id := uuid.New()
	tag, err := tx.Exec(ctx, `INSERT INTO sessions(id,user_id,organization_id,oidc_provider_id,saml_provider_id,token_hash,expires_at,auth_method,user_agent,ip_address)
		VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)`, id, userID, organizationID, oidcProviderID, samlProviderID, tokenHash, expires, authMethod, userAgent, ipAddress)
	if err != nil {
		return uuid.Nil, err
	}
	if tag.RowsAffected() != 1 {
		if authMethod == "local" {
			return uuid.Nil, ErrAuthenticationStateChanged
		}
		return uuid.Nil, ErrNotFound
	}
	action := "auth." + authMethod + ".login"
	if organizationID != nil {
		tag, err = tx.Exec(ctx, `INSERT INTO audit_events(organization_id,actor_user_id,action,resource_type,resource_id,remote_addr,metadata)
			SELECT membership.organization_id,$2,$3,'user',$4,$5,$6
			FROM memberships membership
			WHERE membership.organization_id=$1 AND membership.user_id=$2`, *organizationID, userID, action, userID.String(), remoteAddr, auditMetadata)
	} else {
		tag, err = tx.Exec(ctx, `INSERT INTO audit_events(organization_id,actor_user_id,action,resource_type,resource_id,remote_addr,metadata)
			SELECT membership.organization_id,$1,$2,'user',$3,$4,$5
			FROM memberships membership
			WHERE membership.user_id=$1`, userID, action, userID.String(), remoteAddr, auditMetadata)
	}
	if err != nil {
		return uuid.Nil, err
	}
	if tag.RowsAffected() == 0 {
		return uuid.Nil, ErrNotFound
	}
	if err = tx.Commit(ctx); err != nil {
		return uuid.Nil, err
	}
	return id, nil
}

// lockSessionMemberships makes session issuance serialize with membership
// removal. It prevents a login transaction from committing a dormant token
// after removal has already revoked the user's prior sessions.
func lockSessionMemberships(ctx context.Context, tx pgx.Tx, userID uuid.UUID, organizationID *uuid.UUID) error {
	if organizationID != nil {
		var lockedOrganizationID uuid.UUID
		err := tx.QueryRow(ctx, `SELECT organization_id FROM memberships WHERE organization_id=$1 AND user_id=$2 FOR KEY SHARE`, *organizationID, userID).Scan(&lockedOrganizationID)
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrNotFound
		}
		return err
	}
	rows, err := tx.Query(ctx, `SELECT organization_id FROM memberships WHERE user_id=$1 ORDER BY organization_id FOR KEY SHARE`, userID)
	if err != nil {
		return err
	}
	defer rows.Close()
	found := false
	for rows.Next() {
		var lockedOrganizationID uuid.UUID
		if err = rows.Scan(&lockedOrganizationID); err != nil {
			return err
		}
		found = true
	}
	if err = rows.Err(); err != nil {
		return err
	}
	if !found {
		return ErrNotFound
	}
	return nil
}

func (s *Store) LogoutSessionWithAudit(ctx context.Context, principal Principal, remoteAddr string) error {
	return s.revokeSessionWithAudit(ctx, principal, principal.SessionID, "auth.logout", remoteAddr, nil)
}

func (s *Store) RevokeSessionWithAudit(ctx context.Context, principal Principal, sessionID uuid.UUID, remoteAddr string) error {
	return s.revokeSessionWithAudit(ctx, principal, sessionID, "session.revoke", remoteAddr, map[string]any{"current": sessionID == principal.SessionID})
}

func (s *Store) revokeSessionWithAudit(ctx context.Context, principal Principal, sessionID uuid.UUID, action, remoteAddr string, metadata any) error {
	if principal.ServiceAccountID != nil || principal.UserID == uuid.Nil || principal.SessionID == uuid.Nil {
		return ErrLocalSessionRequired
	}
	tx, err := s.Pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	if err = lockPrincipalSession(ctx, tx, principal); err != nil {
		return err
	}
	query := `DELETE FROM sessions WHERE id=$1 AND user_id=$2`
	args := []any{sessionID, principal.UserID}
	if principal.SessionOrganizationID != nil {
		query += ` AND organization_id=$3`
		args = append(args, *principal.SessionOrganizationID)
	}
	tag, err := tx.Exec(ctx, query, args...)
	if err != nil {
		return err
	}
	if tag.RowsAffected() != 1 {
		return ErrNotFound
	}
	if err = appendPrincipalAudit(ctx, tx, principal, action, "session", sessionID.String(), remoteAddr, metadata); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

func (s *Store) RevokeOtherSessionsWithAudit(ctx context.Context, principal Principal, remoteAddr string) (int64, error) {
	if principal.ServiceAccountID != nil || principal.UserID == uuid.Nil || principal.SessionID == uuid.Nil {
		return 0, ErrLocalSessionRequired
	}
	tx, err := s.Pool.Begin(ctx)
	if err != nil {
		return 0, err
	}
	defer tx.Rollback(ctx)
	if err = lockPrincipalSession(ctx, tx, principal); err != nil {
		return 0, err
	}
	query := `DELETE FROM sessions WHERE user_id=$1 AND id<>$2`
	args := []any{principal.UserID, principal.SessionID}
	if principal.SessionOrganizationID != nil {
		query += ` AND organization_id=$3`
		args = append(args, *principal.SessionOrganizationID)
	}
	tag, err := tx.Exec(ctx, query, args...)
	if err != nil {
		return 0, err
	}
	revoked := tag.RowsAffected()
	if err = appendPrincipalAudit(ctx, tx, principal, "session.revoke_others", "user", principal.UserID.String(), remoteAddr, map[string]int64{"revoked": revoked}); err != nil {
		return 0, err
	}
	if err = tx.Commit(ctx); err != nil {
		return 0, err
	}
	return revoked, nil
}

func lockPrincipalSession(ctx context.Context, tx pgx.Tx, principal Principal) error {
	var exists bool
	err := tx.QueryRow(ctx, `SELECT true
		FROM sessions session
		JOIN memberships membership ON membership.user_id=session.user_id AND membership.organization_id=$3
		WHERE session.id=$1 AND session.user_id=$2 AND session.expires_at>now()
		  AND (session.organization_id IS NULL OR session.organization_id=$3)
		FOR UPDATE OF session,membership`, principal.SessionID, principal.UserID, principal.OrganizationID).Scan(&exists)
	if errors.Is(err, pgx.ErrNoRows) {
		return ErrNotFound
	}
	return err
}

func appendPrincipalAudit(ctx context.Context, tx pgx.Tx, principal Principal, action, resourceType, resourceID, remoteAddr string, metadata any) error {
	auditMetadata, err := json.Marshal(metadata)
	if err != nil {
		return err
	}
	var serviceAccountID any
	if principal.ServiceAccountID != nil {
		serviceAccountID = *principal.ServiceAccountID
	}
	_, err = tx.Exec(ctx, `INSERT INTO audit_events(organization_id,actor_user_id,actor_service_account_id,action,resource_type,resource_id,remote_addr,metadata) VALUES($1,$2,$3,$4,$5,$6,$7,$8)`, principal.OrganizationID, nullableUUID(principal.UserID), serviceAccountID, action, resourceType, resourceID, remoteAddr, auditMetadata)
	return err
}
