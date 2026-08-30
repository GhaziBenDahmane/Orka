package store

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgconn"
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
	changedLocation := updated
	changedLocation.Bucket = "different-bucket"
	if _, err = db.UpdateBackupDestination(ctx, orgID, changedLocation); !errors.Is(err, ErrBusy) {
		t.Fatalf("referenced destination location update error=%v, want busy", err)
	}

	db.RequireRemoteBackups = true
	if _, err = db.QueueDatabaseBackup(ctx, orgID, databaseID, userID, nil); !errors.Is(err, ErrRemoteBackupRequired) {
		t.Fatalf("local backup error = %v, want remote backup required", err)
	}
	if _, err = db.UpsertBackupPolicy(ctx, orgID, databaseID, 3600, 7, true, false, nil); !errors.Is(err, ErrRemoteBackupRequired) {
		t.Fatalf("local backup policy error = %v, want remote backup required", err)
	}
	if err = db.ValidateBackupConfiguration(ctx); err != nil {
		t.Fatalf("valid remote backup configuration: %v", err)
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
	var pgErr *pgconn.PgError
	if !errors.As(err, &pgErr) || pgErr.Code != "23503" {
		t.Fatalf("delete referenced destination error = %v, want foreign-key violation", err)
	}
	if err = db.DeleteBackupDestination(ctx, orgID, foreign.ID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("cross-tenant destination deletion error = %v, want not found", err)
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
