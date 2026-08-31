package store

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"testing"
	"time"

	"github.com/google/uuid"
)

func TestBackupDestinationTenantIsolationAndReferences(t *testing.T) {
	databaseURL := os.Getenv("DOCKYARD_TEST_DATABASE_URL")
	if databaseURL == "" {
		t.Skip("DOCKYARD_TEST_DATABASE_URL is not set")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	db, err := Open(ctx, databaseURL)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(db.Pool.Close)

	orgID, otherOrgID, userID := uuid.New(), uuid.New(), uuid.New()
	projectID, environmentID, databaseID := uuid.New(), uuid.New(), uuid.New()
	tx, err := db.Pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(ctx)
	_, err = tx.Exec(ctx, `INSERT INTO organizations(id,name,slug) VALUES($1,'Backup Test',$2),($3,'Other Backup Test',$4)`, orgID, "backup-"+orgID.String(), otherOrgID, "other-backup-"+otherOrgID.String())
	if err == nil {
		_, err = tx.Exec(ctx, `INSERT INTO users(id,email,password_hash) VALUES($1,$2,'!test')`, userID, userID.String()+"@example.test")
	}
	if err == nil {
		_, err = tx.Exec(ctx, `INSERT INTO projects(id,organization_id,name,slug) VALUES($1,$2,'Project','project')`, projectID, orgID)
	}
	if err == nil {
		_, err = tx.Exec(ctx, `INSERT INTO environments(id,project_id,name,slug) VALUES($1,$2,'Production','production')`, environmentID, projectID)
	}
	if err == nil {
		_, err = tx.Exec(ctx, `INSERT INTO database_instances(id,environment_id,name,slug,engine,version,encrypted_credentials) VALUES($1,$2,'PostgreSQL','postgres','postgresql','17','test')`, databaseID, environmentID)
	}
	if err == nil {
		err = tx.Commit(ctx)
	}
	if err != nil {
		t.Fatal(err)
	}

	var backupID uuid.UUID
	t.Cleanup(func() {
		if backupID != uuid.Nil {
			_, _ = db.Pool.Exec(context.Background(), `DELETE FROM jobs WHERE payload->>'backupId'=$1`, backupID.String())
		}
		_, _ = db.Pool.Exec(context.Background(), `DELETE FROM organizations WHERE id=ANY($1)`, []uuid.UUID{orgID, otherOrgID})
		_, _ = db.Pool.Exec(context.Background(), `DELETE FROM users WHERE id=$1`, userID)
	})

	owned, err := db.CreateBackupDestination(ctx, BackupDestination{OrganizationID: orgID, Name: "owned", Endpoint: "http://minio:9000", Bucket: "backups", EncryptedCredentials: "ciphertext"})
	if err != nil {
		t.Fatal(err)
	}
	foreign, err := db.CreateBackupDestination(ctx, BackupDestination{OrganizationID: otherOrgID, Name: "foreign", Endpoint: "http://minio:9000", Bucket: "backups", EncryptedCredentials: "foreign-ciphertext"})
	if err != nil {
		t.Fatal(err)
	}
	updated, err := db.UpdateBackupDestination(ctx, orgID, BackupDestination{ID: owned.ID, Name: "rotated", Endpoint: "https://objects.example.test", Region: "eu-west-3", Bucket: "rotated-backups", Prefix: "tenant", UseTLS: true, EncryptedCredentials: "rotated-ciphertext"})
	if err != nil {
		t.Fatal(err)
	}
	if updated.OrganizationID != orgID || updated.Name != "rotated" || updated.Endpoint != "https://objects.example.test" || updated.Region != "eu-west-3" || updated.Bucket != "rotated-backups" || updated.Prefix != "tenant" || !updated.UseTLS || updated.EncryptedCredentials != "rotated-ciphertext" {
		t.Fatalf("updated destination=%#v", updated)
	}
	storedDestination, err := db.GetBackupDestination(ctx, orgID, owned.ID)
	if err != nil || storedDestination.EncryptedCredentials != "rotated-ciphertext" || storedDestination.Bucket != "rotated-backups" {
		t.Fatalf("stored updated destination=%#v err=%v", storedDestination, err)
	}
	if _, err = db.UpdateBackupDestination(ctx, otherOrgID, BackupDestination{ID: owned.ID, Name: "hijacked", Endpoint: "https://evil.example.test", Bucket: "stolen", UseTLS: true, EncryptedCredentials: "foreign"}); !errors.Is(err, ErrNotFound) {
		t.Fatalf("cross-tenant destination update error=%v, want not found", err)
	}

	if _, err = db.QueueDatabaseBackup(ctx, orgID, databaseID, userID, &foreign.ID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("cross-tenant backup destination error = %v, want not found", err)
	}
	if _, err = db.UpsertBackupPolicy(ctx, orgID, databaseID, 3600, 7, true, false, &foreign.ID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("cross-tenant policy destination error = %v, want not found", err)
	}

	policy, err := db.UpsertBackupPolicy(ctx, orgID, databaseID, 3600, 7, true, true, &owned.ID)
	if err != nil {
		t.Fatal(err)
	}
	if policy.DestinationID == nil || *policy.DestinationID != owned.ID || !policy.VerifyRestore {
		t.Fatalf("policy destination = %v, want %s", policy.DestinationID, owned.ID)
	}
	storedPolicy, err := db.GetBackupPolicy(ctx, orgID, databaseID)
	if err != nil || storedPolicy.DestinationID == nil || *storedPolicy.DestinationID != owned.ID || !storedPolicy.VerifyRestore {
		t.Fatalf("stored policy destination = %v, err = %v", storedPolicy.DestinationID, err)
	}

	backup, err := db.QueueDatabaseBackup(ctx, orgID, databaseID, userID, &owned.ID)
	if err != nil {
		t.Fatal(err)
	}
	backupID = backup.ID
	storedBackup, err := db.GetDatabaseBackup(ctx, orgID, backup.ID)
	if err != nil || storedBackup.DestinationID == nil || *storedBackup.DestinationID != owned.ID {
		t.Fatalf("stored backup destination = %v, err = %v", storedBackup.DestinationID, err)
	}
	updated.EncryptedCredentials = "second-rotation"
	if updated, err = db.UpdateBackupDestination(ctx, orgID, updated); err != nil || updated.EncryptedCredentials != "second-rotation" {
		t.Fatalf("credential-only rotation=%#v err=%v", updated, err)
	}
	if _, err = db.Pool.Exec(ctx, `UPDATE database_backups SET status='running',started_at=now() WHERE id=$1`, backup.ID); err != nil {
		t.Fatal(err)
	}
	updated.EncryptedCredentials = "blocked-rotation"
	if _, err = db.UpdateBackupDestination(ctx, orgID, updated); !errors.Is(err, ErrBusy) {
		t.Fatalf("credential rotation during active backup error=%v, want busy", err)
	}
	if _, err = db.Pool.Exec(ctx, `UPDATE database_backups SET status='failed',finished_at=now() WHERE id=$1`, backup.ID); err != nil {
		t.Fatal(err)
	}
	updated.EncryptedCredentials = "third-rotation"
	if updated, err = db.UpdateBackupDestination(ctx, orgID, updated); err != nil || updated.EncryptedCredentials != "third-rotation" {
		t.Fatalf("credential rotation after backup completion=%#v err=%v", updated, err)
	}
	operation, err := db.Pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = operation.Exec(ctx, `UPDATE database_backups SET status='running',started_at=now(),finished_at=NULL WHERE id=$1`, backup.ID); err != nil {
		_ = operation.Rollback(ctx)
		t.Fatal(err)
	}
	if err = LockBackupDestinationForOperation(ctx, operation, owned.ID); err != nil {
		_ = operation.Rollback(ctx)
		t.Fatal(err)
	}
	updated.EncryptedCredentials = "racing-rotation"
	rotationResult := make(chan error, 1)
	go func() {
		_, rotateErr := db.UpdateBackupDestination(ctx, orgID, updated)
		rotationResult <- rotateErr
	}()
	waitForBlockedStoreQuery(t, ctx, db, "pg_advisory_xact_lock")
	if err = operation.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	if err = <-rotationResult; !errors.Is(err, ErrBusy) {
		t.Fatalf("racing credential rotation error=%v, want busy", err)
	}
	if _, err = db.Pool.Exec(ctx, `UPDATE database_backups SET status='failed',finished_at=now() WHERE id=$1`, backup.ID); err != nil {
		t.Fatal(err)
	}
	changedLocation := updated
	changedLocation.Bucket = "different-bucket"
	if _, err = db.UpdateBackupDestination(ctx, orgID, changedLocation); !errors.Is(err, ErrBusy) {
		t.Fatalf("referenced destination location update error=%v, want busy", err)
	}

	db.RequireRemoteBackups = true
	if _, err = db.CreateBackupDestination(ctx, BackupDestination{OrganizationID: orgID, Name: "plaintext", Endpoint: "http://objects.example.test", Bucket: "backups", EncryptedCredentials: "ciphertext"}); !errors.Is(err, ErrRemoteBackupTLSRequired) {
		t.Fatalf("plaintext destination creation error=%v, want TLS required", err)
	}
	insecureUpdate := updated
	insecureUpdate.Endpoint = "http://objects.example.test"
	insecureUpdate.UseTLS = false
	if _, err = db.UpdateBackupDestination(ctx, orgID, insecureUpdate); !errors.Is(err, ErrRemoteBackupTLSRequired) {
		t.Fatalf("plaintext destination update error=%v, want TLS required", err)
	}
	if _, err = db.QueueDatabaseBackup(ctx, orgID, databaseID, userID, nil); !errors.Is(err, ErrRemoteBackupRequired) {
		t.Fatalf("local backup error = %v, want remote backup required", err)
	}
	if _, err = db.UpsertBackupPolicy(ctx, orgID, databaseID, 3600, 7, true, false, nil); !errors.Is(err, ErrRemoteBackupRequired) {
		t.Fatalf("local backup policy error = %v, want remote backup required", err)
	}
	legacyLocalBackupID := uuid.New()
	if _, err = db.Pool.Exec(ctx, `INSERT INTO database_backups(id,database_instance_id,status,format) VALUES($1,$2,'queued','native')`, legacyLocalBackupID, databaseID); err != nil {
		t.Fatal(err)
	}
	if err = db.ValidateBackupConfiguration(ctx); !errors.Is(err, ErrRemoteBackupRequired) {
		t.Fatalf("active local backup error=%v, want remote backup required", err)
	}
	if _, err = db.Pool.Exec(ctx, `DELETE FROM database_backups WHERE id=$1`, legacyLocalBackupID); err != nil {
		t.Fatal(err)
	}
	if err = db.ValidateBackupConfiguration(ctx); err != nil {
		t.Fatalf("valid remote backup configuration: %v", err)
	}
	if _, err = db.Pool.Exec(ctx, `UPDATE backup_destinations SET use_tls=false,endpoint='http://objects.example.test' WHERE id=$1`, owned.ID); err != nil {
		t.Fatal(err)
	}
	if _, err = db.QueueDatabaseBackup(ctx, orgID, databaseID, userID, &owned.ID); !errors.Is(err, ErrRemoteBackupTLSRequired) {
		t.Fatalf("plaintext manual backup error=%v, want TLS required", err)
	}
	if err = db.ValidateBackupConfiguration(ctx); !errors.Is(err, ErrRemoteBackupTLSRequired) {
		t.Fatalf("existing plaintext policy error=%v, want TLS required", err)
	}
	if _, err = db.Pool.Exec(ctx, `UPDATE backup_destinations SET use_tls=true,endpoint='https://objects.example.test' WHERE id=$1`, owned.ID); err != nil {
		t.Fatal(err)
	}
	if _, err = db.Pool.Exec(ctx, `UPDATE backup_policies SET destination_id=NULL WHERE database_instance_id=$1`, databaseID); err != nil {
		t.Fatal(err)
	}
	if err = db.ValidateBackupConfiguration(ctx); !errors.Is(err, ErrRemoteBackupRequired) {
		t.Fatalf("existing local backup policy error = %v, want remote backup required", err)
	}

	items, err := db.ListBackupDestinations(ctx, orgID)
	if err != nil || len(items) != 1 || items[0].ID != owned.ID {
		t.Fatalf("organization destinations = %#v, err = %v", items, err)
	}
	encoded, err := json.Marshal(items[0])
	if err != nil || string(encoded) == "" || containsJSONSecret(encoded, "ciphertext") {
		t.Fatalf("destination JSON leaked credentials: %s, err = %v", encoded, err)
	}

	err = db.DeleteBackupDestination(ctx, orgID, owned.ID)
	if !errors.Is(err, ErrBusy) {
		t.Fatalf("delete referenced destination error = %v, want busy", err)
	}
	if err = db.DeleteBackupDestination(ctx, orgID, foreign.ID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("cross-tenant destination deletion error = %v, want not found", err)
	}
	disposable, err := db.CreateBackupDestination(ctx, BackupDestination{OrganizationID: orgID, Name: "disposable", Endpoint: "https://objects.example.test", Bucket: "temporary", UseTLS: true, EncryptedCredentials: "ciphertext"})
	if err != nil {
		t.Fatal(err)
	}
	if err = db.DeleteBackupDestination(ctx, orgID, disposable.ID); err != nil {
		t.Fatalf("delete unreferenced destination: %v", err)
	}
	if _, err = db.GetBackupDestination(ctx, orgID, disposable.ID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("deleted destination lookup error = %v, want not found", err)
	}
}

func containsJSONSecret(encoded []byte, secret string) bool {
	var value map[string]any
	if json.Unmarshal(encoded, &value) != nil {
		return true
	}
	for _, item := range value {
		if text, ok := item.(string); ok && text == secret {
			return true
		}
	}
	return false
}
