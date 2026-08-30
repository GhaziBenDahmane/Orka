package store

import (
	"context"
	"errors"
	"os"
	"testing"
	"time"

	"github.com/google/uuid"
)

func TestServiceDeletionFencesDataOperations(t *testing.T) {
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

	organizationID, userID, projectID, environmentID := uuid.New(), uuid.New(), uuid.New(), uuid.New()
	serviceID, databaseID, destinationID, databaseBackupID, volumeBackupID := uuid.New(), uuid.New(), uuid.New(), uuid.New(), uuid.New()
	statements := []struct {
		query string
		args  []any
	}{
		{`INSERT INTO organizations(id,name,slug) VALUES($1,'Deletion data fence',$2)`, []any{organizationID, "deletion-data-fence-" + organizationID.String()}},
		{`INSERT INTO users(id,email,password_hash) VALUES($1,$2,'!test')`, []any{userID, userID.String() + "@example.test"}},
		{`INSERT INTO projects(id,organization_id,name,slug) VALUES($1,$2,'Project','project')`, []any{projectID, organizationID}},
		{`INSERT INTO environments(id,project_id,name,slug) VALUES($1,$2,'Production','production')`, []any{environmentID, projectID}},
		{`INSERT INTO compose_services(id,environment_id,name,slug,stack_name,storage_node_id,compose_yaml) VALUES($1,$2,'Database','database',$3,'node1',$4)`, []any{serviceID, environmentID, "deletion-data-fence-" + serviceID.String(), "services:\n  database:\n    image: postgres:17\n    volumes:\n      - data:/data\nvolumes:\n  data: {}\n"}},
		{`INSERT INTO database_instances(id,environment_id,name,slug,engine,version,compose_service_id,encrypted_credentials,status) VALUES($1,$2,'Database','database','postgres','17',$3,'encrypted','running')`, []any{databaseID, environmentID, serviceID}},
		{`INSERT INTO backup_destinations(id,organization_id,name,endpoint,bucket,use_tls,encrypted_credentials) VALUES($1,$2,'S3','https://s3.example.test','backups',true,'encrypted')`, []any{destinationID, organizationID}},
		{`INSERT INTO volume_backup_policies(id,compose_service_id,volume_name,destination_id,interval_seconds,retention_count,quiesce,enabled,next_run_at) VALUES($1,$2,'data',$3,3600,7,true,true,now()+interval '1 hour')`, []any{uuid.New(), serviceID, destinationID}},
		{`INSERT INTO database_backups(id,database_instance_id,status,format,destination_id,finished_at) VALUES($1,$2,'succeeded','native',$3,now())`, []any{databaseBackupID, databaseID, destinationID}},
		{`INSERT INTO volume_backups(id,compose_service_id,volume_name,storage_node_id,destination_id,quiesce,status,finished_at) VALUES($1,$2,'data','node1',$3,true,'succeeded',now())`, []any{volumeBackupID, serviceID, destinationID}},
	}
	for _, statement := range statements {
		if _, err = db.Pool.Exec(ctx, statement.query, statement.args...); err != nil {
			t.Fatal(err)
		}
	}
	t.Cleanup(func() {
		_, _ = db.Pool.Exec(context.Background(), `DELETE FROM jobs WHERE resource_key IN ($1,$2) OR (kind='delete.compose' AND payload->>'serviceId'=$3)`, "service:"+serviceID.String(), "database:"+databaseID.String(), serviceID.String())
		_, _ = db.Pool.Exec(context.Background(), `DELETE FROM organizations WHERE id=$1`, organizationID)
		_, _ = db.Pool.Exec(context.Background(), `DELETE FROM users WHERE id=$1`, userID)
	})

	databaseBackup, err := db.QueueDatabaseBackup(ctx, organizationID, databaseID, userID, &destinationID)
	if err != nil {
		t.Fatal(err)
	}
	assertServiceDeletionBusy(t, ctx, db, organizationID, serviceID, "database backup")
	if err = db.CancelDatabaseBackup(ctx, organizationID, databaseBackup.ID); err != nil {
		t.Fatal(err)
	}

	volumeBackup, err := db.QueueVolumeBackup(ctx, organizationID, serviceID, "data", userID)
	if err != nil {
		t.Fatal(err)
	}
	assertServiceDeletionBusy(t, ctx, db, organizationID, serviceID, "volume backup")
	if err = db.CancelVolumeBackup(ctx, organizationID, volumeBackup.ID); err != nil {
		t.Fatal(err)
	}

	migration, err := db.QueueDatabaseMigration(ctx, organizationID, DatabaseMigration{DatabaseInstanceID: databaseID, SourceKind: "dokploy", SourceID: "source", SourceEngine: "postgres", SourceVersion: "16", SourceHost: "source.internal", EncryptedSourceConfig: "encrypted"})
	if err != nil {
		t.Fatal(err)
	}
	assertServiceDeletionBusy(t, ctx, db, organizationID, serviceID, "database migration")
	if err = db.CancelDatabaseMigration(ctx, organizationID, migration.ID); err != nil {
		t.Fatal(err)
	}

	databaseRestore, err := db.QueueDatabaseRestore(ctx, organizationID, databaseBackupID, userID, "database")
	if err != nil {
		t.Fatal(err)
	}
	assertServiceDeletionBusy(t, ctx, db, organizationID, serviceID, "database restore")
	if err = db.CancelDatabaseRestore(ctx, organizationID, databaseRestore.ID); err != nil {
		t.Fatal(err)
	}

	volumeRestore, err := db.QueueVolumeRestore(ctx, organizationID, volumeBackupID, userID, "database")
	if err != nil {
		t.Fatal(err)
	}
	assertServiceDeletionBusy(t, ctx, db, organizationID, serviceID, "volume restore")
	if err = db.CancelVolumeRestore(ctx, organizationID, volumeRestore.ID); err != nil {
		t.Fatal(err)
	}

	blocker, err := db.Pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer blocker.Rollback(context.Background())
	if err = blocker.QueryRow(ctx, `SELECT id FROM compose_services WHERE id=$1 FOR UPDATE`, serviceID).Scan(new(uuid.UUID)); err != nil {
		t.Fatal(err)
	}
	deleteResult := make(chan error, 1)
	go func() { deleteResult <- db.QueueServiceDeletion(ctx, organizationID, serviceID) }()
	waitForBlockedStoreQuery(t, ctx, db, "SELECT s.stack_name,s.deletion_requested_at IS NOT NULL FROM compose_services")
	type backupResult struct {
		backup DatabaseBackup
		err    error
	}
	backupResultChannel := make(chan backupResult, 1)
	go func() {
		backup, backupErr := db.QueueDatabaseBackup(ctx, organizationID, databaseID, userID, &destinationID)
		backupResultChannel <- backupResult{backup: backup, err: backupErr}
	}()
	waitForBlockedStoreQuery(t, ctx, db, "SELECT id FROM compose_services WHERE id=$1 AND deletion_requested_at IS NULL FOR UPDATE")
	if err = blocker.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	deleteErr := <-deleteResult
	concurrentBackup := <-backupResultChannel
	switch {
	case deleteErr == nil:
		if !errors.Is(concurrentBackup.err, ErrDeleting) {
			t.Fatalf("database backup admitted after successful deletion request: backup=%#v err=%v", concurrentBackup.backup, concurrentBackup.err)
		}
	case concurrentBackup.err == nil:
		if !errors.Is(deleteErr, ErrBusy) {
			t.Fatalf("service deletion did not reject concurrent backup: %v", deleteErr)
		}
		if err = db.CancelDatabaseBackup(ctx, organizationID, concurrentBackup.backup.ID); err != nil {
			t.Fatal(err)
		}
		if err = db.QueueServiceDeletion(ctx, organizationID, serviceID); err != nil {
			t.Fatalf("queue service deletion after concurrent backup cancellation: %v", err)
		}
	default:
		t.Fatalf("deletion race produced no valid winner: deletion=%v backup=%v", deleteErr, concurrentBackup.err)
	}
	if _, err = db.QueueDatabaseBackup(ctx, organizationID, databaseID, userID, &destinationID); !errors.Is(err, ErrDeleting) {
		t.Fatalf("database backup after deletion request error=%v, want ErrDeleting", err)
	}
	if _, err = db.QueueDatabaseRestore(ctx, organizationID, databaseBackupID, userID, "database"); !errors.Is(err, ErrDeleting) {
		t.Fatalf("database restore after deletion request error=%v, want ErrDeleting", err)
	}
	if _, err = db.QueueDatabaseMigration(ctx, organizationID, DatabaseMigration{DatabaseInstanceID: databaseID, SourceKind: "dokploy", SourceID: "late", SourceEngine: "postgres", SourceVersion: "16", SourceHost: "source.internal", EncryptedSourceConfig: "encrypted"}); !errors.Is(err, ErrDeleting) {
		t.Fatalf("database migration after deletion request error=%v, want ErrDeleting", err)
	}
	if _, err = db.QueueVolumeBackup(ctx, organizationID, serviceID, "data", userID); !errors.Is(err, ErrDeleting) {
		t.Fatalf("volume backup after deletion request error=%v, want ErrDeleting", err)
	}
	if _, err = db.QueueVolumeRestore(ctx, organizationID, volumeBackupID, userID, "database"); !errors.Is(err, ErrDeleting) {
		t.Fatalf("volume restore after deletion request error=%v, want ErrDeleting", err)
	}
}

func assertServiceDeletionBusy(t *testing.T, ctx context.Context, db *Store, organizationID, serviceID uuid.UUID, operation string) {
	t.Helper()
	if err := db.QueueServiceDeletion(ctx, organizationID, serviceID); !errors.Is(err, ErrBusy) {
		t.Fatalf("service deletion during %s error=%v, want ErrBusy", operation, err)
	}
}
