package store

import (
	"context"
	"errors"
	"testing"

	"github.com/google/uuid"
)

func TestAuditComplianceMutationsCommitWithEvidence(t *testing.T) {
	pool, ctx := migrationTestPool(t)
	if err := Migrate(ctx, pool); err != nil {
		t.Fatal(err)
	}
	db := &Store{Pool: pool}
	organizationID, userID, backupDestinationID, archiveID := uuid.New(), uuid.New(), uuid.New(), uuid.New()
	if _, err := pool.Exec(ctx, `INSERT INTO organizations(id,name,slug) VALUES($1,'Audit compliance',$2)`, organizationID, "audit-compliance-"+organizationID.String()); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO users(id,email,password_hash) VALUES($1,$2,'!test')`, userID, userID.String()+"@example.test"); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO backup_destinations(id,organization_id,name,endpoint,bucket,use_tls,encrypted_credentials) VALUES($1,$2,'worm','https://objects.example.test','audit',true,'ciphertext')`, backupDestinationID, organizationID); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `DELETE FROM jobs WHERE kind='audit.archive' AND payload->>'batchId' IN (SELECT b.id::text FROM audit_archive_batches b JOIN audit_archive_destinations a ON a.id=b.destination_id WHERE a.organization_id=$1)`, organizationID)
		_, _ = pool.Exec(context.Background(), `DELETE FROM organizations WHERE id=$1`, organizationID)
		_, _ = pool.Exec(context.Background(), `DELETE FROM users WHERE id=$1`, userID)
	})
	invalidPrincipal := Principal{OrganizationID: organizationID, UserID: uuid.New()}
	principal := Principal{OrganizationID: organizationID, UserID: userID}

	if _, err := db.UpsertAuditRetentionPolicyWithAudit(ctx, invalidPrincipal, 30, "127.0.0.1:1234"); err == nil {
		t.Fatal("audit retention changed without valid audit evidence")
	}
	policy, err := db.GetAuditRetentionPolicy(ctx, organizationID)
	if err != nil || policy.RetentionDays != 365 {
		t.Fatalf("failed evidence did not roll back audit retention: policy=%#v err=%v", policy, err)
	}
	if policy, err = db.UpsertAuditRetentionPolicyWithAudit(ctx, principal, 30, "127.0.0.1:1234"); err != nil || policy.RetentionDays != 30 {
		t.Fatalf("audited retention update=%#v err=%v", policy, err)
	}

	archiveInput := AuditArchiveDestination{ID: archiveID, BackupDestinationID: backupDestinationID, Name: "compliance", ObjectPrefix: "audit", RetentionDays: 365}
	if _, err = db.CreateAuditArchiveDestinationWithAudit(ctx, invalidPrincipal, archiveInput, "127.0.0.1:1234"); err == nil {
		t.Fatal("audit archive created without valid audit evidence")
	}
	if _, err = db.GetAuditArchiveDestination(ctx, organizationID, archiveID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("failed evidence did not roll back audit archive creation: %v", err)
	}
	archive, err := db.CreateAuditArchiveDestinationWithAudit(ctx, principal, archiveInput, "127.0.0.1:1234")
	if err != nil {
		t.Fatal(err)
	}

	if _, err = db.QueueAuditArchiveWithAudit(ctx, invalidPrincipal, archive.ID, "127.0.0.1:1234"); err == nil {
		t.Fatal("audit archive batch queued without valid audit evidence")
	}
	var batchCount, jobCount int
	if err = pool.QueryRow(ctx, `SELECT count(*) FROM audit_archive_batches WHERE destination_id=$1`, archive.ID).Scan(&batchCount); err != nil || batchCount != 0 {
		t.Fatalf("failed evidence retained audit archive batch: count=%d err=%v", batchCount, err)
	}
	if err = pool.QueryRow(ctx, `SELECT count(*) FROM jobs WHERE kind='audit.archive' AND payload->>'batchId' IN (SELECT id::text FROM audit_archive_batches WHERE destination_id=$1)`, archive.ID).Scan(&jobCount); err != nil || jobCount != 0 {
		t.Fatalf("failed evidence retained audit archive job: count=%d err=%v", jobCount, err)
	}
	batch, err := db.QueueAuditArchiveWithAudit(ctx, principal, archive.ID, "127.0.0.1:1234")
	if err != nil {
		t.Fatal(err)
	}

	if err = db.DisableAuditArchiveDestinationWithAudit(ctx, invalidPrincipal, archive.ID, "127.0.0.1:1234"); err == nil {
		t.Fatal("audit archive disabled without valid audit evidence")
	}
	stored, err := db.GetAuditArchiveDestination(ctx, organizationID, archive.ID)
	if err != nil || !stored.Enabled {
		t.Fatalf("failed evidence did not roll back archive disable: archive=%#v err=%v", stored, err)
	}
	var batchStatus, jobStatus string
	if err = pool.QueryRow(ctx, `SELECT status FROM audit_archive_batches WHERE id=$1`, batch.ID).Scan(&batchStatus); err != nil || batchStatus != "pending" {
		t.Fatalf("failed evidence changed archive batch: status=%q err=%v", batchStatus, err)
	}
	if err = pool.QueryRow(ctx, `SELECT status FROM jobs WHERE kind='audit.archive' AND payload->>'batchId'=$1`, batch.ID.String()).Scan(&jobStatus); err != nil || jobStatus != "pending" {
		t.Fatalf("failed evidence changed archive job: status=%q err=%v", jobStatus, err)
	}
	if err = db.DisableAuditArchiveDestinationWithAudit(ctx, principal, archive.ID, "127.0.0.1:1234"); err != nil {
		t.Fatal(err)
	}
	stored, err = db.GetAuditArchiveDestination(ctx, organizationID, archive.ID)
	if err != nil || stored.Enabled {
		t.Fatalf("audited archive disable=%#v err=%v", stored, err)
	}
	if err = pool.QueryRow(ctx, `SELECT status FROM audit_archive_batches WHERE id=$1`, batch.ID).Scan(&batchStatus); err != nil || batchStatus != "failed" {
		t.Fatalf("archive disable batch status=%q err=%v", batchStatus, err)
	}
	if err = pool.QueryRow(ctx, `SELECT status FROM jobs WHERE kind='audit.archive' AND payload->>'batchId'=$1`, batch.ID.String()).Scan(&jobStatus); err != nil || jobStatus != "cancelled" {
		t.Fatalf("archive disable job status=%q err=%v", jobStatus, err)
	}

	var auditCount int
	if err = pool.QueryRow(ctx, `SELECT count(*) FROM audit_events WHERE organization_id=$1 AND actor_user_id=$2 AND action IN ('audit.retention.update','audit.archive.create','audit.archive.run','audit.archive.disable')`, organizationID, userID).Scan(&auditCount); err != nil || auditCount != 4 {
		t.Fatalf("audit compliance evidence count=%d err=%v", auditCount, err)
	}
}
