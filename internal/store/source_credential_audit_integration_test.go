package store

import (
	"errors"
	"testing"

	"github.com/google/uuid"
)

func TestSourceCredentialMutationCommitsWithAudit(t *testing.T) {
	pool, ctx := migrationTestPool(t)
	if err := Migrate(ctx, pool); err != nil {
		t.Fatal(err)
	}
	db := &Store{Pool: pool}
	organizationID, userID, credentialID := uuid.New(), uuid.New(), uuid.New()
	if _, err := pool.Exec(ctx, `INSERT INTO organizations(id,name,slug) VALUES($1,'Credential audit',$2)`, organizationID, "credential-audit-"+organizationID.String()); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO users(id,email,password_hash) VALUES($1,$2,'!test')`, userID, userID.String()+"@example.test"); err != nil {
		t.Fatal(err)
	}
	invalidPrincipal := Principal{OrganizationID: organizationID, UserID: uuid.New()}
	principal := Principal{OrganizationID: organizationID, UserID: userID}
	credential := SourceCredential{ID: credentialID, Kind: "registry", Name: "registry", Server: "registry.example.test", Username: "robot", EncryptedSecret: "original-ciphertext"}
	if _, err := db.CreateSourceCredentialWithAudit(ctx, invalidPrincipal, credential, "127.0.0.1:1234"); err == nil {
		t.Fatal("credential creation succeeded without a valid audit actor")
	}
	if _, err := db.GetSourceCredential(ctx, organizationID, credentialID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("failed audit did not roll back credential creation: %v", err)
	}
	if _, err := db.CreateSourceCredentialWithAudit(ctx, principal, credential, "127.0.0.1:1234"); err != nil {
		t.Fatal(err)
	}

	if _, err := db.RotateSourceCredentialWithAudit(ctx, invalidPrincipal, credentialID, "unaudited-ciphertext", "127.0.0.1:1234"); err == nil {
		t.Fatal("credential rotation succeeded without a valid audit actor")
	}
	stored, err := db.GetSourceCredential(ctx, organizationID, credentialID)
	if err != nil || stored.EncryptedSecret != "original-ciphertext" {
		t.Fatalf("failed audit did not roll back rotation: credential=%#v err=%v", stored, err)
	}

	rotated, err := db.RotateSourceCredentialWithAudit(ctx, principal, credentialID, "rotated-ciphertext", "127.0.0.1:1234")
	if err != nil || rotated.EncryptedSecret != "rotated-ciphertext" {
		t.Fatalf("audited rotation=%#v err=%v", rotated, err)
	}
	if err = db.DeleteSourceCredentialWithAudit(ctx, invalidPrincipal, credentialID, "127.0.0.1:1234"); err == nil {
		t.Fatal("credential deletion succeeded without a valid audit actor")
	}
	if _, err = db.GetSourceCredential(ctx, organizationID, credentialID); err != nil {
		t.Fatalf("failed audit did not roll back deletion: %v", err)
	}
	if err = db.DeleteSourceCredentialWithAudit(ctx, principal, credentialID, "127.0.0.1:1234"); err != nil {
		t.Fatal(err)
	}
	if _, err = db.GetSourceCredential(ctx, organizationID, credentialID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("deleted credential lookup error=%v, want not found", err)
	}
	var auditCount int
	if err = pool.QueryRow(ctx, `SELECT count(*) FROM audit_events WHERE organization_id=$1 AND actor_user_id=$2 AND resource_id=$3 AND action IN ('source_credential.create','source_credential.rotate','source_credential.delete')`, organizationID, userID, credentialID.String()).Scan(&auditCount); err != nil || auditCount != 3 {
		t.Fatalf("credential mutation audit count=%d err=%v", auditCount, err)
	}

	serviceAccountID, automationCredentialID := uuid.New(), uuid.New()
	if _, err = pool.Exec(ctx, `INSERT INTO service_accounts(id,organization_id,name,role) VALUES($1,$2,'credential-operator','admin')`, serviceAccountID, organizationID); err != nil {
		t.Fatal(err)
	}
	if _, err = db.CreateSourceCredential(ctx, SourceCredential{ID: automationCredentialID, OrganizationID: organizationID, Kind: "git", Name: "automation", Server: "github.com", Username: "token", EncryptedSecret: "original"}); err != nil {
		t.Fatal(err)
	}
	servicePrincipal := Principal{OrganizationID: organizationID, ServiceAccountID: &serviceAccountID, Role: "admin"}
	if _, err = db.RotateSourceCredentialWithAudit(ctx, servicePrincipal, automationCredentialID, "rotated", "127.0.0.1:1234"); err != nil {
		t.Fatal(err)
	}
	var serviceAuditCount int
	if err = pool.QueryRow(ctx, `SELECT count(*) FROM audit_events WHERE organization_id=$1 AND actor_user_id IS NULL AND actor_service_account_id=$2 AND resource_id=$3 AND action='source_credential.rotate'`, organizationID, serviceAccountID, automationCredentialID.String()).Scan(&serviceAuditCount); err != nil || serviceAuditCount != 1 {
		t.Fatalf("service-account credential audit count=%d err=%v", serviceAuditCount, err)
	}
}
