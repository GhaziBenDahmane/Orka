package store

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/bendahma/dokploy-go/internal/auth"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

type LocalLoginCredential struct {
	UserID              uuid.UUID
	PasswordHash        string
	EncryptedTOTPSecret string
}

type MFAStatus struct {
	Enabled             bool `json:"enabled"`
	EnrollmentPending   bool `json:"enrollmentPending"`
	RecoveryCodesRemain int  `json:"recoveryCodesRemaining"`
}

// PasswordLoginCredential intentionally returns ciphertext, never plaintext.
// The caller decrypts it only after the password has been verified.
func (s *Store) PasswordLoginCredential(ctx context.Context, email string) (LocalLoginCredential, error) {
	var result LocalLoginCredential
	err := s.Pool.QueryRow(ctx, `SELECT id,password_hash,COALESCE(encrypted_totp_secret,'') FROM users WHERE email=$1 AND disabled_at IS NULL`, email).Scan(&result.UserID, &result.PasswordHash, &result.EncryptedTOTPSecret)
	if errors.Is(err, pgx.ErrNoRows) {
		return result, ErrNotFound
	}
	return result, err
}

func (s *Store) MFAStatus(ctx context.Context, principal Principal) (MFAStatus, error) {
	if principal.ServiceAccountID != nil || principal.UserID == uuid.Nil || principal.SessionID == uuid.Nil {
		return MFAStatus{}, ErrLocalSessionRequired
	}
	var status MFAStatus
	err := s.Pool.QueryRow(ctx, `SELECT u.encrypted_totp_secret IS NOT NULL,u.pending_encrypted_totp_secret IS NOT NULL,
		(SELECT count(*) FROM user_mfa_recovery_codes code WHERE code.user_id=u.id)
		FROM users u JOIN sessions session ON session.user_id=u.id
		WHERE u.id=$1 AND session.id=$2 AND session.expires_at>now()`, principal.UserID, principal.SessionID).Scan(&status.Enabled, &status.EnrollmentPending, &status.RecoveryCodesRemain)
	if errors.Is(err, pgx.ErrNoRows) {
		return MFAStatus{}, ErrLocalSessionRequired
	}
	return status, err
}

func (s *Store) BeginMFAEnrollment(ctx context.Context, principal Principal, currentPassword, encryptedSecret, remoteAddr string) error {
	if principal.ServiceAccountID != nil || principal.UserID == uuid.Nil || principal.SessionID == uuid.Nil {
		return ErrLocalSessionRequired
	}
	tx, err := s.Pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	var passwordHash string
	var enabled bool
	err = tx.QueryRow(ctx, `SELECT u.password_hash,u.encrypted_totp_secret IS NOT NULL FROM users u JOIN sessions session ON session.user_id=u.id
		WHERE u.id=$1 AND u.disabled_at IS NULL AND session.id=$2 AND session.auth_method='local' AND session.expires_at>now() FOR UPDATE OF u,session`, principal.UserID, principal.SessionID).Scan(&passwordHash, &enabled)
	if errors.Is(err, pgx.ErrNoRows) {
		return ErrLocalSessionRequired
	}
	if err != nil {
		return err
	}
	if !auth.VerifyPassword(passwordHash, currentPassword) {
		return ErrInvalidCurrentPassword
	}
	if enabled {
		return ErrMFAAlreadyEnabled
	}
	if _, err = tx.Exec(ctx, `UPDATE users SET pending_encrypted_totp_secret=$2 WHERE id=$1`, principal.UserID, encryptedSecret); err != nil {
		return err
	}
	if err = appendUserMFAAudit(ctx, tx, principal.UserID, "auth.mfa.enrollment_started", remoteAddr, nil); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

func (s *Store) PendingMFASecret(ctx context.Context, principal Principal) (string, error) {
	if principal.ServiceAccountID != nil || principal.UserID == uuid.Nil || principal.SessionID == uuid.Nil {
		return "", ErrLocalSessionRequired
	}
	var encrypted string
	err := s.Pool.QueryRow(ctx, `SELECT u.pending_encrypted_totp_secret FROM users u JOIN sessions session ON session.user_id=u.id
		WHERE u.id=$1 AND session.id=$2 AND session.auth_method='local' AND session.expires_at>now() AND u.pending_encrypted_totp_secret IS NOT NULL`, principal.UserID, principal.SessionID).Scan(&encrypted)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", ErrMFAEnrollmentMissing
	}
	return encrypted, err
}

func (s *Store) ConfirmMFAEnrollment(ctx context.Context, principal Principal, expectedPending string, acceptedCounter int64, recoveryDigests [][]byte, remoteAddr string) (int64, error) {
	if len(recoveryDigests) == 0 {
		return 0, errors.New("recovery codes are required")
	}
	tx, err := s.Pool.Begin(ctx)
	if err != nil {
		return 0, err
	}
	defer tx.Rollback(ctx)
	tag, err := tx.Exec(ctx, `UPDATE users u SET encrypted_totp_secret=$3,pending_encrypted_totp_secret=NULL,totp_last_counter=$4
		FROM sessions session WHERE u.id=$1 AND session.id=$2 AND session.user_id=u.id AND session.auth_method='local'
		AND session.expires_at>now() AND u.encrypted_totp_secret IS NULL AND u.pending_encrypted_totp_secret=$3`, principal.UserID, principal.SessionID, expectedPending, acceptedCounter)
	if err != nil {
		return 0, err
	}
	if tag.RowsAffected() != 1 {
		return 0, ErrAuthenticationStateChanged
	}
	if _, err = tx.Exec(ctx, `DELETE FROM user_mfa_recovery_codes WHERE user_id=$1`, principal.UserID); err != nil {
		return 0, err
	}
	for _, digest := range recoveryDigests {
		if _, err = tx.Exec(ctx, `INSERT INTO user_mfa_recovery_codes(user_id,code_hash) VALUES($1,$2)`, principal.UserID, digest); err != nil {
			return 0, err
		}
	}
	tag, err = tx.Exec(ctx, `DELETE FROM sessions WHERE user_id=$1 AND id<>$2`, principal.UserID, principal.SessionID)
	if err != nil {
		return 0, err
	}
	revoked := tag.RowsAffected()
	if err = appendUserMFAAudit(ctx, tx, principal.UserID, "auth.mfa.enabled", remoteAddr, map[string]any{"recoveryCodes": len(recoveryDigests), "revokedSessions": revoked}); err != nil {
		return 0, err
	}
	if err = tx.Commit(ctx); err != nil {
		return 0, err
	}
	return revoked, nil
}

// CreateMFASessionWithAudit consumes either a fresh TOTP counter or a recovery
// code in the same transaction that issues the session and appends its audit
// events. An exact ciphertext and password-hash match closes credential races.
func (s *Store) CreateMFASessionWithAudit(ctx context.Context, credential LocalLoginCredential, tokenHash []byte, expires time.Time, totpCounter *int64, recoveryDigest []byte, userAgent, ipAddress, remoteAddr string) (uuid.UUID, error) {
	if (totpCounter == nil) == (len(recoveryDigest) == 0) {
		return uuid.Nil, ErrInvalidMFAProof
	}
	tx, err := s.Pool.Begin(ctx)
	if err != nil {
		return uuid.Nil, err
	}
	defer tx.Rollback(ctx)
	var lastCounter *int64
	var activeSecret string
	err = tx.QueryRow(ctx, `SELECT totp_last_counter,COALESCE(encrypted_totp_secret,'') FROM users WHERE id=$1 AND disabled_at IS NULL AND password_hash=$2 FOR UPDATE`, credential.UserID, credential.PasswordHash).Scan(&lastCounter, &activeSecret)
	if errors.Is(err, pgx.ErrNoRows) || activeSecret != credential.EncryptedTOTPSecret || activeSecret == "" {
		return uuid.Nil, ErrAuthenticationStateChanged
	}
	if err != nil {
		return uuid.Nil, err
	}
	if err = lockSessionMemberships(ctx, tx, credential.UserID, nil); err != nil {
		return uuid.Nil, err
	}
	proof := "totp"
	if totpCounter != nil {
		if lastCounter != nil && *totpCounter <= *lastCounter {
			return uuid.Nil, ErrInvalidMFAProof
		}
		if _, err = tx.Exec(ctx, `UPDATE users SET totp_last_counter=$2 WHERE id=$1`, credential.UserID, *totpCounter); err != nil {
			return uuid.Nil, err
		}
	} else {
		proof = "recovery_code"
		tag, deleteErr := tx.Exec(ctx, `DELETE FROM user_mfa_recovery_codes WHERE user_id=$1 AND code_hash=$2`, credential.UserID, recoveryDigest)
		if deleteErr != nil {
			return uuid.Nil, deleteErr
		}
		if tag.RowsAffected() != 1 {
			return uuid.Nil, ErrInvalidMFAProof
		}
	}
	id := uuid.New()
	if _, err = tx.Exec(ctx, `INSERT INTO sessions(id,user_id,token_hash,expires_at,auth_method,user_agent,ip_address) VALUES($1,$2,$3,$4,'local',$5,$6)`, id, credential.UserID, tokenHash, expires, userAgent, ipAddress); err != nil {
		return uuid.Nil, err
	}
	metadata, _ := json.Marshal(map[string]string{"mfa": proof})
	tag, err := tx.Exec(ctx, `INSERT INTO audit_events(organization_id,actor_user_id,action,resource_type,resource_id,remote_addr,metadata)
		SELECT organization_id,$1,'auth.local.login','user',$2,$3,$4 FROM memberships WHERE user_id=$1`, credential.UserID, credential.UserID.String(), remoteAddr, metadata)
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

func (s *Store) ActiveMFASecret(ctx context.Context, principal Principal) (string, error) {
	if principal.ServiceAccountID != nil || principal.UserID == uuid.Nil || principal.SessionID == uuid.Nil {
		return "", ErrLocalSessionRequired
	}
	var encrypted string
	err := s.Pool.QueryRow(ctx, `SELECT u.encrypted_totp_secret FROM users u JOIN sessions session ON session.user_id=u.id WHERE u.id=$1 AND session.id=$2 AND session.auth_method='local' AND session.expires_at>now() AND u.encrypted_totp_secret IS NOT NULL`, principal.UserID, principal.SessionID).Scan(&encrypted)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", ErrMFANotEnabled
	}
	return encrypted, err
}

// ReplaceMFARecoveryCodes verifies password and consumes a proof atomically.
func (s *Store) ReplaceMFARecoveryCodes(ctx context.Context, principal Principal, currentPassword, expectedSecret string, totpCounter *int64, recoveryDigest []byte, newDigests [][]byte, remoteAddr string) (int64, error) {
	return s.updateMFA(ctx, principal, currentPassword, expectedSecret, totpCounter, recoveryDigest, newDigests, false, remoteAddr)
}

func (s *Store) DisableMFA(ctx context.Context, principal Principal, currentPassword, expectedSecret string, totpCounter *int64, recoveryDigest []byte, remoteAddr string) (int64, error) {
	return s.updateMFA(ctx, principal, currentPassword, expectedSecret, totpCounter, recoveryDigest, nil, true, remoteAddr)
}

func (s *Store) updateMFA(ctx context.Context, principal Principal, currentPassword, expectedSecret string, totpCounter *int64, recoveryDigest []byte, newDigests [][]byte, disable bool, remoteAddr string) (int64, error) {
	if principal.ServiceAccountID != nil || principal.UserID == uuid.Nil || principal.SessionID == uuid.Nil || (totpCounter == nil) == (len(recoveryDigest) == 0) {
		return 0, ErrInvalidMFAProof
	}
	tx, err := s.Pool.Begin(ctx)
	if err != nil {
		return 0, err
	}
	defer tx.Rollback(ctx)
	var passwordHash, activeSecret string
	var lastCounter *int64
	err = tx.QueryRow(ctx, `SELECT u.password_hash,COALESCE(u.encrypted_totp_secret,''),u.totp_last_counter FROM users u JOIN sessions session ON session.user_id=u.id WHERE u.id=$1 AND session.id=$2 AND session.auth_method='local' AND session.expires_at>now() FOR UPDATE OF u,session`, principal.UserID, principal.SessionID).Scan(&passwordHash, &activeSecret, &lastCounter)
	if errors.Is(err, pgx.ErrNoRows) {
		return 0, ErrLocalSessionRequired
	}
	if err != nil {
		return 0, err
	}
	if !auth.VerifyPassword(passwordHash, currentPassword) {
		return 0, ErrInvalidCurrentPassword
	}
	if activeSecret == "" {
		return 0, ErrMFANotEnabled
	}
	if activeSecret != expectedSecret {
		return 0, ErrAuthenticationStateChanged
	}
	proof := "totp"
	if totpCounter != nil {
		if lastCounter != nil && *totpCounter <= *lastCounter {
			return 0, ErrInvalidMFAProof
		}
		if _, err = tx.Exec(ctx, `UPDATE users SET totp_last_counter=$2 WHERE id=$1`, principal.UserID, *totpCounter); err != nil {
			return 0, err
		}
	} else {
		proof = "recovery_code"
		tag, consumeErr := tx.Exec(ctx, `DELETE FROM user_mfa_recovery_codes WHERE user_id=$1 AND code_hash=$2`, principal.UserID, recoveryDigest)
		if consumeErr != nil {
			return 0, consumeErr
		}
		if tag.RowsAffected() != 1 {
			return 0, ErrInvalidMFAProof
		}
	}
	action := "auth.mfa.recovery_codes_regenerated"
	if disable {
		action = "auth.mfa.disabled"
		if _, err = tx.Exec(ctx, `UPDATE users SET encrypted_totp_secret=NULL,pending_encrypted_totp_secret=NULL,totp_last_counter=NULL WHERE id=$1`, principal.UserID); err != nil {
			return 0, err
		}
	}
	if _, err = tx.Exec(ctx, `DELETE FROM user_mfa_recovery_codes WHERE user_id=$1`, principal.UserID); err != nil {
		return 0, err
	}
	for _, digest := range newDigests {
		if _, err = tx.Exec(ctx, `INSERT INTO user_mfa_recovery_codes(user_id,code_hash) VALUES($1,$2)`, principal.UserID, digest); err != nil {
			return 0, err
		}
	}
	tag, err := tx.Exec(ctx, `DELETE FROM sessions WHERE user_id=$1 AND id<>$2`, principal.UserID, principal.SessionID)
	if err != nil {
		return 0, err
	}
	revoked := tag.RowsAffected()
	if err = appendUserMFAAudit(ctx, tx, principal.UserID, action, remoteAddr, map[string]any{"mfa": proof, "recoveryCodes": len(newDigests), "revokedSessions": revoked}); err != nil {
		return 0, err
	}
	if err = tx.Commit(ctx); err != nil {
		return 0, err
	}
	return revoked, nil
}

func appendUserMFAAudit(ctx context.Context, tx pgx.Tx, userID uuid.UUID, action, remoteAddr string, metadata any) error {
	auditMetadata, err := json.Marshal(metadata)
	if err != nil {
		return err
	}
	tag, err := tx.Exec(ctx, `INSERT INTO audit_events(organization_id,actor_user_id,action,resource_type,resource_id,remote_addr,metadata)
		SELECT organization_id,$1,$2,'user',$3,$4,$5 FROM memberships WHERE user_id=$1`, userID, action, userID.String(), remoteAddr, auditMetadata)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}
