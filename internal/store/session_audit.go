package store

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/google/uuid"
)

// CreateSessionWithAudit makes authentication success and session issuance one
// durable transition. Unscoped local sessions are visible in every tenant the
// identity can enter, so their login event is appended to each membership's
// audit chain. Federated sessions and events remain bound to their IdP tenant.
func (s *Store) CreateSessionWithAudit(ctx context.Context, userID uuid.UUID, organizationID *uuid.UUID, tokenHash []byte, expires time.Time, authMethod, expectedPasswordHash, userAgent, ipAddress, remoteAddr string, metadata any) (uuid.UUID, error) {
	switch authMethod {
	case "local":
		if expectedPasswordHash == "" {
			return uuid.Nil, ErrAuthenticationStateChanged
		}
	case "oidc", "saml":
		if expectedPasswordHash != "" {
			return uuid.Nil, errors.New("federated session cannot bind a password hash")
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
	id := uuid.New()
	tag, err := tx.Exec(ctx, `INSERT INTO sessions(id,user_id,organization_id,token_hash,expires_at,auth_method,user_agent,ip_address)
		SELECT $1,u.id,$3,$4,$5,$6,$7,$8 FROM users u
		WHERE u.id=$2 AND u.disabled_at IS NULL AND ($6<>'local' OR u.password_hash=$9)`, id, userID, organizationID, tokenHash, expires, authMethod, userAgent, ipAddress, expectedPasswordHash)
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
