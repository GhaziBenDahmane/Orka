package store

import (
	"context"
	"errors"
	"os"
	"testing"
	"time"

	"github.com/google/uuid"
)

func TestAuditArchiveChainAndExplicitRetry(t *testing.T) {
	databaseURL := os.Getenv("DOCKYARD_TEST_DATABASE_URL")
	if databaseURL == "" {
		t.Skip("DOCKYARD_TEST_DATABASE_URL is not set")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	db, err := Open(ctx, databaseURL)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(db.Pool.Close)
	organizationID, backupDestinationID := uuid.New(), uuid.New()
	if _, err = db.Pool.Exec(ctx, `INSERT INTO organizations(id,name,slug) VALUES($1,'Archive',$2)`, organizationID, "archive-"+organizationID.String()); err == nil {
		_, err = db.Pool.Exec(ctx, `INSERT INTO backup_destinations(id,organization_id,name,endpoint,bucket,use_tls,encrypted_credentials) VALUES($1,$2,'worm','https://s3.example.test','audit',true,'encrypted')`, backupDestinationID, organizationID)
	}
	if err == nil {
		_, err = db.Pool.Exec(ctx, `INSERT INTO audit_events(organization_id,action,resource_type) VALUES($1,'one','test'),($1,'two','test')`, organizationID)
	}
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = db.Pool.Exec(context.Background(), `DELETE FROM jobs WHERE kind='audit.archive' AND payload->>'batchId' IN (SELECT b.id::text FROM audit_archive_batches b JOIN audit_archive_destinations a ON a.id=b.destination_id WHERE a.organization_id=$1)`, organizationID)
		_, _ = db.Pool.Exec(context.Background(), `DELETE FROM organizations WHERE id=$1`, organizationID)
	})
	destination, err := db.CreateAuditArchiveDestination(ctx, AuditArchiveDestination{OrganizationID: organizationID, BackupDestinationID: backupDestinationID, Name: "compliance", ObjectPrefix: "audit", RetentionDays: 365})
	if err != nil {
		t.Fatal(err)
	}
	first, err := db.QueueAuditArchive(ctx, organizationID, destination.ID)
	if err != nil || first.FirstEventID == 0 || first.LastEventID < first.FirstEventID || first.PreviousSHA256 != "" {
		t.Fatalf("first batch=%+v err=%v", first, err)
	}
	if _, err = db.QueueAuditArchive(ctx, organizationID, destination.ID); !errors.Is(err, ErrBusy) {
		t.Fatalf("second concurrent queue error=%v, want busy", err)
	}
	if err = db.FinishAuditArchiveBatch(ctx, first.ID, "", 0, errors.New("temporary storage failure")); err != nil {
		t.Fatal(err)
	}
	if _, err = db.Pool.Exec(ctx, `UPDATE jobs SET status='failed',finished_at=now() WHERE kind='audit.archive' AND payload->>'batchId'=$1`, first.ID.String()); err != nil {
		t.Fatal(err)
	}
	retried, err := db.QueueAuditArchive(ctx, organizationID, destination.ID)
	if err != nil || retried.ID != first.ID || retried.Status != "pending" {
		t.Fatalf("retried batch=%+v err=%v", retried, err)
	}
	if err = db.FinishAuditArchiveBatch(ctx, first.ID, "hash-one", 123, nil); err != nil {
		t.Fatal(err)
	}
	if _, err = db.Pool.Exec(ctx, `INSERT INTO audit_events(organization_id,action,resource_type) VALUES($1,'three','test')`, organizationID); err != nil {
		t.Fatal(err)
	}
	second, err := db.QueueAuditArchive(ctx, organizationID, destination.ID)
	if err != nil || second.PreviousSHA256 != "hash-one" || second.FirstEventID <= first.LastEventID {
		t.Fatalf("second batch=%+v err=%v", second, err)
	}
}
