package store

import (
	"errors"
	"testing"

	"github.com/google/uuid"
)

func TestBackupDestinationMutationCommitsWithAudit(t *testing.T) {
	pool, ctx := migrationTestPool(t)
	if err := Migrate(ctx, pool); err != nil {
		t.Fatal(err)
	}
	db := &Store{Pool: pool}
	organizationID, userID := uuid.New(), uuid.New()
	if _, err := pool.Exec(ctx, `INSERT INTO organizations(id,name,slug) VALUES($1,'Backup audit',$2)`, organizationID, "backup-audit-"+organizationID.String()); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO users(id,email,password_hash) VALUES($1,$2,'!test')`, userID, userID.String()+"@example.test"); err != nil {
		t.Fatal(err)
	}
	invalidPrincipal := Principal{OrganizationID: organizationID, UserID: uuid.New()}
	principal := Principal{OrganizationID: organizationID, UserID: userID}
	destinationInput := BackupDestination{Name: "archive", Endpoint: "https://objects.example.test", Region: "eu-west-3", Bucket: "backups", Prefix: "original", UseTLS: true, EncryptedCredentials: "original-ciphertext"}
	destinationInput.ID = uuid.New()
	if _, err := db.CreateBackupDestinationWithAudit(ctx, invalidPrincipal, destinationInput, "127.0.0.1:1234"); err == nil {
		t.Fatal("backup destination creation succeeded without a valid audit actor")
	}
	if _, err := db.GetBackupDestination(ctx, organizationID, destinationInput.ID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("failed audit did not roll back destination creation: %v", err)
	}
	destination, err := db.CreateBackupDestinationWithAudit(ctx, principal, destinationInput, "127.0.0.1:1234")
	if err != nil {
		t.Fatal(err)
	}
	updated := destination
	updated.Name = "rotated"
	updated.Prefix = "current"
	updated.EncryptedCredentials = "rotated-ciphertext"

	if _, err = db.UpdateBackupDestinationWithAudit(ctx, invalidPrincipal, updated, "127.0.0.1:1234"); err == nil {
		t.Fatal("backup destination update succeeded without a valid audit actor")
	}
	stored, err := db.GetBackupDestination(ctx, organizationID, destination.ID)
	if err != nil || stored.Name != "archive" || stored.Prefix != "original" || stored.EncryptedCredentials != "original-ciphertext" {
		t.Fatalf("failed audit did not roll back destination update: destination=%#v err=%v", stored, err)
	}

	stored, err = db.UpdateBackupDestinationWithAudit(ctx, principal, updated, "127.0.0.1:1234")
	if err != nil || stored.Name != "rotated" || stored.Prefix != "current" || stored.EncryptedCredentials != "rotated-ciphertext" {
		t.Fatalf("audited destination update=%#v err=%v", stored, err)
	}
	if err = db.DeleteBackupDestinationWithAudit(ctx, invalidPrincipal, destination.ID, "127.0.0.1:1234"); err == nil {
		t.Fatal("backup destination deletion succeeded without a valid audit actor")
	}
	if _, err = db.GetBackupDestination(ctx, organizationID, destination.ID); err != nil {
		t.Fatalf("failed audit did not roll back destination deletion: %v", err)
	}
	if err = db.DeleteBackupDestinationWithAudit(ctx, principal, destination.ID, "127.0.0.1:1234"); err != nil {
		t.Fatal(err)
	}
	if _, err = db.GetBackupDestination(ctx, organizationID, destination.ID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("deleted destination lookup error=%v, want not found", err)
	}
	var auditCount int
	if err = pool.QueryRow(ctx, `SELECT count(*) FROM audit_events WHERE organization_id=$1 AND actor_user_id=$2 AND resource_id=$3 AND action IN ('backup_destination.create','backup_destination.update','backup_destination.delete')`, organizationID, userID, destination.ID.String()).Scan(&auditCount); err != nil || auditCount != 3 {
		t.Fatalf("backup destination mutation audit count=%d err=%v", auditCount, err)
	}
}
