package deploy

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"os"
	"testing"
	"time"

	"github.com/bendahma/dokploy-go/internal/cryptox"
	"github.com/bendahma/dokploy-go/internal/store"
	"github.com/google/uuid"
)

func TestServiceDeletionDurablyQueuesRemoteBackupCleanup(t *testing.T) {
	databaseURL := os.Getenv("DOCKYARD_TEST_DATABASE_URL")
	if databaseURL == "" {
		t.Skip("DOCKYARD_TEST_DATABASE_URL is not set")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	db, err := store.Open(ctx, databaseURL)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(db.Pool.Close)
	box, err := cryptox.New([]byte("0123456789abcdef0123456789abcdef"))
	if err != nil {
		t.Fatal(err)
	}

	organizationID, projectID, environmentID := uuid.New(), uuid.New(), uuid.New()
	serviceID, databaseID, destinationID := uuid.New(), uuid.New(), uuid.New()
	databaseBackupID, volumeBackupID, volumeRestoreID := uuid.New(), uuid.New(), uuid.New()
	statements := []struct {
		query string
		args  []any
	}{
		{`INSERT INTO organizations(id,name,slug) VALUES($1,'Artifact cleanup',$2)`, []any{organizationID, "artifact-cleanup-" + organizationID.String()}},
		{`INSERT INTO projects(id,organization_id,name,slug) VALUES($1,$2,'Project','project')`, []any{projectID, organizationID}},
		{`INSERT INTO environments(id,project_id,name,slug) VALUES($1,$2,'Production','production')`, []any{environmentID, projectID}},
		{`INSERT INTO compose_services(id,environment_id,name,slug,stack_name,compose_yaml,storage_node_id,deletion_requested_at) VALUES($1,$2,'App','app',$3,'services: {}','node1',now())`, []any{serviceID, environmentID, "artifact-cleanup-" + serviceID.String()}},
		{`INSERT INTO database_instances(id,environment_id,name,slug,engine,version,compose_service_id,encrypted_credentials) VALUES($1,$2,'Database','database','postgres','17',$3,'ciphertext')`, []any{databaseID, environmentID, serviceID}},
		{`INSERT INTO backup_destinations(id,organization_id,name,endpoint,bucket,encrypted_credentials) VALUES($1,$2,'archive','https://objects.example.test','backups','invalid-ciphertext')`, []any{destinationID, organizationID}},
		{`INSERT INTO database_backups(id,database_instance_id,status,format,destination_id,object_key,encrypted,finished_at) VALUES($1,$2,'succeeded','native',$3,'databases/object.enc',true,now())`, []any{databaseBackupID, databaseID, destinationID}},
		{`INSERT INTO volume_backups(id,compose_service_id,volume_name,storage_node_id,destination_id,quiesce,status,object_key,finished_at) VALUES($1,$2,'data','node1',$3,true,'succeeded','volumes/object.enc',now())`, []any{volumeBackupID, serviceID, destinationID}},
		{`INSERT INTO volume_restores(id,volume_backup_id,status,finished_at) VALUES($1,$2,'succeeded',now())`, []any{volumeRestoreID, volumeBackupID}},
	}
	for _, statement := range statements {
		if _, err = db.Pool.Exec(ctx, statement.query, statement.args...); err != nil {
			t.Fatal(err)
		}
	}
	t.Cleanup(func() {
		_, _ = db.Pool.Exec(context.Background(), `DELETE FROM backup_artifact_deletions WHERE source_id=ANY($1)`, []uuid.UUID{databaseBackupID, volumeBackupID})
		_, _ = db.Pool.Exec(context.Background(), `DELETE FROM organizations WHERE id=$1`, organizationID)
	})

	payload, _ := json.Marshal(map[string]any{"serviceId": serviceID.String(), "stackName": "artifact-cleanup-" + serviceID.String(), "deleteVolumes": false})
	worker := &Worker{Store: db, Box: box, Swarm: &storagePlacementScheduler{}, BackupDirectory: t.TempDir(), Logger: slog.New(slog.NewTextHandler(io.Discard, nil))}
	if err = worker.deleteComposeService(ctx, job{Payload: payload}); err != nil {
		t.Fatal(err)
	}
	var remaining int
	if err = db.Pool.QueryRow(ctx, `SELECT (SELECT count(*) FROM compose_services WHERE id=$1)+(SELECT count(*) FROM database_instances WHERE id=$2)+(SELECT count(*) FROM database_backups WHERE id=$3)+(SELECT count(*) FROM volume_backups WHERE id=$4)+(SELECT count(*) FROM volume_restores WHERE id=$5)`, serviceID, databaseID, databaseBackupID, volumeBackupID, volumeRestoreID).Scan(&remaining); err != nil || remaining != 0 {
		t.Fatalf("remaining deleted resources=%d err=%v", remaining, err)
	}
	var queued, attempted int
	if err = db.Pool.QueryRow(ctx, `SELECT count(*),count(*) FILTER (WHERE attempts=1 AND last_error<>'') FROM backup_artifact_deletions WHERE source_id=ANY($1)`, []uuid.UUID{databaseBackupID, volumeBackupID}).Scan(&queued, &attempted); err != nil || queued != 2 || attempted != 2 {
		t.Fatalf("queued cleanup=%d attempted=%d err=%v", queued, attempted, err)
	}
}
