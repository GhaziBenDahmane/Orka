package store

import (
	"context"
	"encoding/json"
	"errors"

	"github.com/GhaziBenDahmane/Orka/internal/auth"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// ChangeLocalPassword rotates a user's local credential, revokes every other
// interactive session for that identity, and records the event atomically.
// The authenticated local session used for the change remains valid so a
// successful response never strands the caller without a usable credential.
func (s *Store) ChangeLocalPassword(ctx context.Context, principal Principal, currentPassword, newPasswordHash, remoteAddr string) (int64, error) {
	if principal.ServiceAccountID != nil || principal.UserID == uuid.Nil || principal.SessionID == uuid.Nil {
		return 0, ErrLocalSessionRequired
	}
	tx, err := s.Pool.Begin(ctx)
	if err != nil {
		return 0, err
	}
	defer tx.Rollback(ctx)

	var currentHash string
	err = tx.QueryRow(ctx, `SELECT u.password_hash
		FROM users u JOIN sessions session ON session.user_id=u.id
		WHERE u.id=$1 AND u.disabled_at IS NULL AND session.id=$2
		  AND session.auth_method='local' AND session.expires_at>now()
		FOR UPDATE OF u,session`, principal.UserID, principal.SessionID).Scan(&currentHash)
	if errors.Is(err, pgx.ErrNoRows) {
		return 0, ErrLocalSessionRequired
	}
	if err != nil {
		return 0, err
	}
	if !auth.VerifyPassword(currentHash, currentPassword) {
		return 0, ErrInvalidCurrentPassword
	}
	if _, err = tx.Exec(ctx, `UPDATE users SET password_hash=$2 WHERE id=$1`, principal.UserID, newPasswordHash); err != nil {
		return 0, err
	}
	tag, err := tx.Exec(ctx, `DELETE FROM sessions WHERE user_id=$1 AND id<>$2`, principal.UserID, principal.SessionID)
	if err != nil {
		return 0, err
	}
	revoked := tag.RowsAffected()
	metadata, err := json.Marshal(map[string]int64{"revokedSessions": revoked})
	if err != nil {
		return 0, err
	}
	if _, err = tx.Exec(ctx, `INSERT INTO audit_events(organization_id,actor_user_id,action,resource_type,resource_id,remote_addr,metadata) VALUES($1,$2,'auth.password_change','user',$3,$4,$5)`, principal.OrganizationID, principal.UserID, principal.UserID.String(), remoteAddr, metadata); err != nil {
		return 0, err
	}
	if err = tx.Commit(ctx); err != nil {
		return 0, err
	}
	return revoked, nil
}
