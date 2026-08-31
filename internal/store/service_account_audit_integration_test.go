package store

import (
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"
)

func TestServiceAccountLifecycleCommitsWithAudit(t *testing.T) {
	pool, ctx := migrationTestPool(t)
	if err := Migrate(ctx, pool); err != nil {
		t.Fatal(err)
	}
	db := &Store{Pool: pool}
	organizationID, userID := uuid.New(), uuid.New()
	if _, err := pool.Exec(ctx, `INSERT INTO organizations(id,name,slug) VALUES($1,'Service account audit',$2)`, organizationID, "service-account-audit-"+organizationID.String()); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO users(id,email,password_hash) VALUES($1,$2,'!test')`, userID, userID.String()+"@example.test"); err != nil {
		t.Fatal(err)
	}
	principal := Principal{OrganizationID: organizationID, UserID: userID, Role: "owner"}
	invalidPrincipal := principal
	invalidServiceAccountID := uuid.New()
	invalidPrincipal.ServiceAccountID = &invalidServiceAccountID
	expiresAt := time.Now().Add(30 * 24 * time.Hour)
	failedHash := []byte("failed-service-account-hash")
	originalHash := []byte("original-service-account-hash")
	failedRotationHash := []byte("failed-service-account-rotation-hash")
	rotatedHash := []byte("rotated-service-account-hash")

	if _, err := db.CreateServiceAccountWithAudit(ctx, invalidPrincipal, "failed-account", "developer", failedHash, expiresAt, "127.0.0.1:1234"); err == nil {
		t.Fatal("service account creation succeeded without valid audit evidence")
	}
	if _, err := db.Authenticate(ctx, failedHash, &organizationID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("failed evidence retained service-account credential: %v", err)
	}

	account, err := db.CreateServiceAccountWithAudit(ctx, principal, "automation", "developer", originalHash, expiresAt, "127.0.0.1:1234")
	if err != nil {
		t.Fatal(err)
	}
	if _, err = db.Authenticate(ctx, originalHash, &organizationID); err != nil {
		t.Fatalf("original service-account credential: %v", err)
	}

	if err = db.RotateServiceAccountTokenWithAudit(ctx, invalidPrincipal, account.ID, failedRotationHash, expiresAt, "127.0.0.1:1234"); err == nil {
		t.Fatal("service account rotation succeeded without valid audit evidence")
	}
	if _, err = db.Authenticate(ctx, originalHash, &organizationID); err != nil {
		t.Fatalf("failed evidence revoked original credential: %v", err)
	}
	if _, err = db.Authenticate(ctx, failedRotationHash, &organizationID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("failed evidence retained replacement credential: %v", err)
	}

	if err = db.RotateServiceAccountTokenWithAudit(ctx, principal, account.ID, rotatedHash, expiresAt, "127.0.0.1:1234"); err != nil {
		t.Fatal(err)
	}
	if _, err = db.Authenticate(ctx, originalHash, &organizationID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("rotated credential remained active: %v", err)
	}
	if _, err = db.Authenticate(ctx, rotatedHash, &organizationID); err != nil {
		t.Fatalf("replacement credential is inactive: %v", err)
	}

	if err = db.DisableServiceAccountWithAudit(ctx, invalidPrincipal, account.ID, "127.0.0.1:1234"); err == nil {
		t.Fatal("service account disablement succeeded without valid audit evidence")
	}
	if _, err = db.Authenticate(ctx, rotatedHash, &organizationID); err != nil {
		t.Fatalf("failed evidence disabled service account: %v", err)
	}
	if err = db.DisableServiceAccountWithAudit(ctx, principal, account.ID, "127.0.0.1:1234"); err != nil {
		t.Fatal(err)
	}
	if _, err = db.Authenticate(ctx, rotatedHash, &organizationID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("disabled service account still authenticates: %v", err)
	}

	var auditCount int
	if err = pool.QueryRow(ctx, `SELECT count(*) FROM audit_events WHERE organization_id=$1 AND actor_user_id=$2 AND actor_service_account_id IS NULL AND resource_id=$3 AND action IN ('service_account.create','service_account.rotate','service_account.disable')`, organizationID, userID, account.ID.String()).Scan(&auditCount); err != nil || auditCount != 3 {
		t.Fatalf("service-account audit count=%d err=%v", auditCount, err)
	}
}
