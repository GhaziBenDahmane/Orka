package store

import (
	"context"
	"errors"
	"os"
	"testing"
	"time"

	"github.com/google/uuid"
)

func TestConfirmMFAEnrollmentIsFencedBySessionRevocation(t *testing.T) {
	databaseURL := os.Getenv("DOCKYARD_TEST_DATABASE_URL")
	if databaseURL == "" {
		t.Skip("DOCKYARD_TEST_DATABASE_URL is not set")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	db, err := Open(ctx, databaseURL)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(db.Pool.Close)

	organizationID, userID, sessionID := uuid.New(), uuid.New(), uuid.New()
	pendingSecret := "encrypted-pending-" + uuid.NewString()
	for _, statement := range []struct {
		query string
		args  []any
	}{
		{`INSERT INTO organizations(id,name,slug) VALUES($1,'MFA authority',$2)`, []any{organizationID, "mfa-authority-" + organizationID.String()}},
		{`INSERT INTO users(id,email,password_hash,pending_encrypted_totp_secret) VALUES($1,$2,'!test',$3)`, []any{userID, userID.String() + "@example.test", pendingSecret}},
		{`INSERT INTO memberships(organization_id,user_id,role) VALUES($1,$2,'owner')`, []any{organizationID, userID}},
		{`INSERT INTO sessions(id,user_id,token_hash,expires_at,auth_method) VALUES($1,$2,$3,now()+interval '1 hour','local')`, []any{sessionID, userID, []byte("mfa-authority-session")}},
	} {
		if _, err = db.Pool.Exec(ctx, statement.query, statement.args...); err != nil {
			t.Fatal(err)
		}
	}
	t.Cleanup(func() {
		_, _ = db.Pool.Exec(context.Background(), `DELETE FROM organizations WHERE id=$1`, organizationID)
		_, _ = db.Pool.Exec(context.Background(), `DELETE FROM users WHERE id=$1`, userID)
	})

	revocation, err := db.Pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer revocation.Rollback(context.Background())
	if _, err = revocation.Exec(ctx, `DELETE FROM sessions WHERE id=$1`, sessionID); err != nil {
		t.Fatal(err)
	}

	result := make(chan error, 1)
	go func() {
		_, confirmErr := db.ConfirmMFAEnrollment(ctx, Principal{UserID: userID, SessionID: sessionID, OrganizationID: organizationID, Role: "owner"}, pendingSecret, 42, [][]byte{[]byte("recovery-code-digest")}, "127.0.0.1:1234")
		result <- confirmErr
	}()

	select {
	case confirmErr := <-result:
		t.Fatalf("MFA confirmation escaped uncommitted session revocation: %v", confirmErr)
	case <-time.After(150 * time.Millisecond):
	}
	if err = revocation.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	select {
	case confirmErr := <-result:
		if !errors.Is(confirmErr, ErrAuthenticationStateChanged) {
			t.Fatalf("confirmation error=%v, want authentication state changed", confirmErr)
		}
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}

	var active, pending bool
	var recoveryCodes, auditEvents int
	if err = db.Pool.QueryRow(ctx, `SELECT encrypted_totp_secret IS NOT NULL,pending_encrypted_totp_secret IS NOT NULL FROM users WHERE id=$1`, userID).Scan(&active, &pending); err != nil {
		t.Fatal(err)
	}
	if err = db.Pool.QueryRow(ctx, `SELECT count(*) FROM user_mfa_recovery_codes WHERE user_id=$1`, userID).Scan(&recoveryCodes); err != nil {
		t.Fatal(err)
	}
	if err = db.Pool.QueryRow(ctx, `SELECT count(*) FROM audit_events WHERE organization_id=$1 AND actor_user_id=$2 AND action='auth.mfa.enabled'`, organizationID, userID).Scan(&auditEvents); err != nil {
		t.Fatal(err)
	}
	if active || !pending || recoveryCodes != 0 || auditEvents != 0 {
		t.Fatalf("revoked confirmation changed state: active=%v pending=%v recovery_codes=%d audit_events=%d", active, pending, recoveryCodes, auditEvents)
	}
}
