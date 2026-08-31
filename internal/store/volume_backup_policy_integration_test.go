package store

import (
	"context"
	"errors"
	"os"
	"testing"
	"time"

	"github.com/google/uuid"
)

func TestVolumeBackupPolicyDeletionSerializesWithBackupAdmission(t *testing.T) {
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

	organizationID, userID := uuid.New(), uuid.New()
	projectID, environmentID, serviceID, destinationID := uuid.New(), uuid.New(), uuid.New(), uuid.New()
	statements := []struct {
		query string
		args  []any
	}{
		{`INSERT INTO organizations(id,name,slug) VALUES($1,'Volume Policy Race',$2)`, []any{organizationID, "volume-policy-race-" + organizationID.String()}},
		{`INSERT INTO users(id,email,password_hash) VALUES($1,$2,'!test')`, []any{userID, userID.String() + "@example.test"}},
		{`INSERT INTO projects(id,organization_id,name,slug) VALUES($1,$2,'Project','project')`, []any{projectID, organizationID}},
		{`INSERT INTO environments(id,project_id,name,slug) VALUES($1,$2,'Production','production')`, []any{environmentID, projectID}},
		{`INSERT INTO compose_services(id,environment_id,name,slug,stack_name,storage_node_id,compose_yaml) VALUES($1,$2,'App','app',$3,'nodeabc123',$4)`, []any{serviceID, environmentID, "volume-policy-race-" + serviceID.String(), "services:\n  app:\n    image: example/app:1\n    volumes:\n      - uploads:/data\nvolumes:\n  uploads: {}\n"}},
		{`INSERT INTO backup_destinations(id,organization_id,name,endpoint,bucket,use_tls,encrypted_credentials) VALUES($1,$2,'S3','https://s3.example.test','backups',true,'encrypted')`, []any{destinationID, organizationID}},
	}
	for _, statement := range statements {
		if _, err = db.Pool.Exec(ctx, statement.query, statement.args...); err != nil {
			t.Fatal(err)
		}
	}
	t.Cleanup(func() {
		_, _ = db.Pool.Exec(context.Background(), `DELETE FROM jobs WHERE resource_key=$1`, "service:"+serviceID.String())
		_, _ = db.Pool.Exec(context.Background(), `DELETE FROM organizations WHERE id=$1`, organizationID)
		_, _ = db.Pool.Exec(context.Background(), `DELETE FROM users WHERE id=$1`, userID)
	})

	db.RequireRemoteBackups = true
	if _, err = db.Pool.Exec(ctx, `UPDATE backup_destinations SET use_tls=false,endpoint='http://s3.example.test' WHERE id=$1`, destinationID); err != nil {
		t.Fatal(err)
	}
	if _, err = db.UpsertVolumeBackupPolicy(ctx, organizationID, serviceID, "uploads", "nodeabc123", destinationID, 3600, 7, true, true); !errors.Is(err, ErrRemoteBackupTLSRequired) {
		t.Fatalf("plaintext volume policy error=%v, want TLS required", err)
	}
	if _, err = db.Pool.Exec(ctx, `UPDATE backup_destinations SET use_tls=true,endpoint='https://s3.example.test' WHERE id=$1`, destinationID); err != nil {
		t.Fatal(err)
	}
	policy, err := db.UpsertVolumeBackupPolicy(ctx, organizationID, serviceID, "uploads", "nodeabc123", destinationID, 3600, 7, true, true)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = db.Pool.Exec(ctx, `UPDATE backup_destinations SET use_tls=false,endpoint='http://s3.example.test' WHERE id=$1`, destinationID); err != nil {
		t.Fatal(err)
	}
	if _, err = db.QueueVolumeBackup(ctx, organizationID, serviceID, "uploads", userID); !errors.Is(err, ErrRemoteBackupTLSRequired) {
		t.Fatalf("plaintext volume backup error=%v, want TLS required", err)
	}
	if _, err = db.Pool.Exec(ctx, `UPDATE backup_destinations SET use_tls=true,endpoint='https://s3.example.test' WHERE id=$1`, destinationID); err != nil {
		t.Fatal(err)
	}
	blocker, err := db.Pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer blocker.Rollback(context.Background())
	var lockedPolicyID uuid.UUID
	if err = blocker.QueryRow(ctx, `SELECT policy.id FROM volume_backup_policies policy JOIN compose_services service ON service.id=policy.compose_service_id WHERE policy.id=$1 FOR UPDATE OF service,policy`, policy.ID).Scan(&lockedPolicyID); err != nil {
		t.Fatal(err)
	}

	deleteResult := make(chan error, 1)
	go func() {
		deleteResult <- db.DeleteVolumeBackupPolicy(ctx, organizationID, serviceID, "uploads")
	}()
	waitForBlockedStoreQuery(t, ctx, db, "SELECT policy.id FROM volume_backup_policies policy JOIN compose_services service")

	type backupResult struct {
		backup VolumeBackup
		err    error
	}
	queueResult := make(chan backupResult, 1)
	go func() {
		backup, queueErr := db.QueueVolumeBackup(ctx, organizationID, serviceID, "uploads", userID)
		queueResult <- backupResult{backup: backup, err: queueErr}
	}()
	waitForBlockedStoreQuery(t, ctx, db, "SELECT policy.id,policy.destination_id,service.storage_node_id")
	if err = blocker.Commit(ctx); err != nil {
		t.Fatal(err)
	}

	deleteErr := <-deleteResult
	queued := <-queueResult
	switch {
	case deleteErr == nil:
		if !errors.Is(queued.err, ErrNotFound) {
			t.Fatalf("backup admitted after successful policy deletion: backup=%#v err=%v", queued.backup, queued.err)
		}
		var active int
		if err = db.Pool.QueryRow(ctx, `SELECT count(*) FROM volume_backups WHERE compose_service_id=$1 AND volume_name='uploads' AND status IN ('queued','running')`, serviceID).Scan(&active); err != nil || active != 0 {
			t.Fatalf("active backups after successful policy deletion=%d err=%v", active, err)
		}
	case queued.err == nil:
		if !errors.Is(deleteErr, ErrBusy) {
			t.Fatalf("policy deletion did not reject admitted backup: deleteErr=%v", deleteErr)
		}
		if err = db.CancelVolumeBackup(ctx, organizationID, queued.backup.ID); err != nil {
			t.Fatal(err)
		}
		if err = db.DeleteVolumeBackupPolicy(ctx, organizationID, serviceID, "uploads"); err != nil {
			t.Fatalf("delete policy after backup cancellation: %v", err)
		}
	default:
		t.Fatalf("race produced no valid winner: deleteErr=%v queueErr=%v", deleteErr, queued.err)
	}
}

func waitForBlockedStoreQuery(t *testing.T, ctx context.Context, db *Store, fragment string) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		var blocked bool
		err := db.Pool.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE datname=current_database() AND pid<>pg_backend_pid() AND wait_event_type='Lock' AND query LIKE $1)`, "%"+fragment+"%").Scan(&blocked)
		if err != nil {
			t.Fatal(err)
		}
		if blocked {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("query containing %q did not block on the policy lock", fragment)
}
