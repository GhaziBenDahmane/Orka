package store

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"
)

func TestSCIMTokenLifecycleCommitsWithAudit(t *testing.T) {
	pool, ctx := migrationTestPool(t)
	if err := Migrate(ctx, pool); err != nil {
		t.Fatal(err)
	}
	db := &Store{Pool: pool}
	organizationID, userID := uuid.New(), uuid.New()
	if _, err := pool.Exec(ctx, `INSERT INTO organizations(id,name,slug) VALUES($1,'SCIM token audit',$2)`, organizationID, "scim-token-audit-"+organizationID.String()); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO users(id,email,password_hash) VALUES($1,$2,'!test')`, userID, userID.String()+"@example.test"); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `DELETE FROM organizations WHERE id=$1`, organizationID)
		_, _ = pool.Exec(context.Background(), `DELETE FROM users WHERE id=$1`, userID)
	})
	invalidPrincipal := Principal{OrganizationID: organizationID, UserID: uuid.New()}
	principal := Principal{OrganizationID: organizationID, UserID: userID}
	failedHash := []byte("failed-scim-token-hash")
	activeHash := []byte("active-scim-token-hash")
	expiresAt := time.Now().Add(30 * 24 * time.Hour)

	if _, err := db.CreateSCIMTokenWithAudit(ctx, invalidPrincipal, "identity provider", "developer", failedHash, expiresAt, "127.0.0.1:1234"); err == nil {
		t.Fatal("SCIM token creation succeeded without valid audit evidence")
	}
	if _, _, err := db.AuthenticateSCIM(ctx, failedHash); !errors.Is(err, ErrNotFound) {
		t.Fatalf("failed evidence retained SCIM credential: %v", err)
	}
	item, err := db.CreateSCIMTokenWithAudit(ctx, principal, "identity provider", "developer", activeHash, expiresAt, "127.0.0.1:1234")
	if err != nil {
		t.Fatal(err)
	}

	if err = db.RevokeSCIMTokenWithAudit(ctx, invalidPrincipal, item.ID, "127.0.0.1:1234"); err == nil {
		t.Fatal("SCIM token revocation succeeded without valid audit evidence")
	}
	if authenticatedOrganization, role, authenticateErr := db.AuthenticateSCIM(ctx, activeHash); authenticateErr != nil || authenticatedOrganization != organizationID || role != "developer" {
		t.Fatalf("failed evidence revoked SCIM credential: organization=%s role=%q err=%v", authenticatedOrganization, role, authenticateErr)
	}
	if err = db.RevokeSCIMTokenWithAudit(ctx, principal, item.ID, "127.0.0.1:1234"); err != nil {
		t.Fatal(err)
	}
	if _, _, err = db.AuthenticateSCIM(ctx, activeHash); !errors.Is(err, ErrNotFound) {
		t.Fatalf("revoked SCIM credential authentication error=%v, want not found", err)
	}

	var auditCount int
	if err = pool.QueryRow(ctx, `SELECT count(*) FROM audit_events WHERE organization_id=$1 AND actor_user_id=$2 AND resource_id=$3 AND action IN ('scim.token.create','scim.token.revoke')`, organizationID, userID, item.ID.String()).Scan(&auditCount); err != nil || auditCount != 2 {
		t.Fatalf("SCIM token audit count=%d err=%v", auditCount, err)
	}
}
