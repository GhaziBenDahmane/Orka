package deploy

import (
	"context"
	"errors"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/bendahma/dokploy-go/internal/store"
	"github.com/google/uuid"
)

func TestVolumeRestoreFailsCleanlyWhenArtifactSizeIsMissing(t *testing.T) {
	databaseURL := os.Getenv("DOCKYARD_TEST_DATABASE_URL")
	if databaseURL == "" {
		t.Skip("DOCKYARD_TEST_DATABASE_URL is not set")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	db, err := store.Open(ctx, databaseURL)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(db.Pool.Close)

	organizationID, projectID, environmentID := uuid.New(), uuid.New(), uuid.New()
	serviceID, destinationID, backupID, restoreID := uuid.New(), uuid.New(), uuid.New(), uuid.New()
	jobID, leaseID := uuid.New(), uuid.New()
	statements := []struct {
		query string
		args  []any
	}{
		{`INSERT INTO organizations(id,name,slug) VALUES($1,'Volume metadata',$2)`, []any{organizationID, "volume-metadata-" + organizationID.String()}},
		{`INSERT INTO projects(id,organization_id,name,slug) VALUES($1,$2,'Project','project')`, []any{projectID, organizationID}},
		{`INSERT INTO environments(id,project_id,name,slug) VALUES($1,$2,'Production','production')`, []any{environmentID, projectID}},
		{`INSERT INTO compose_services(id,environment_id,name,slug,stack_name,compose_yaml,storage_node_id,desired_state) VALUES($1,$2,'App','app',$3,'services: {}','node1','running')`, []any{serviceID, environmentID, "volume-metadata-" + serviceID.String()}},
		{`INSERT INTO backup_destinations(id,organization_id,name,endpoint,bucket,encrypted_credentials) VALUES($1,$2,'archive','https://objects.example.test','backups','ciphertext')`, []any{destinationID, organizationID}},
		{`INSERT INTO volume_backups(id,compose_service_id,volume_name,storage_node_id,destination_id,quiesce,status,object_key,size_bytes,sha256,plaintext_sha256,encrypted_data_key,finished_at) VALUES($1,$2,'data','node1',$3,true,'succeeded','volumes/object.enc',NULL,$4,$5,'wrapped',now())`, []any{backupID, serviceID, destinationID, strings.Repeat("a", 64), strings.Repeat("b", 64)}},
		{`INSERT INTO volume_restores(id,volume_backup_id,target_storage_node_id,status) VALUES($1,$2,'node1','queued')`, []any{restoreID, backupID}},
		{`INSERT INTO jobs(id,kind,payload,resource_key,status,max_attempts,locked_at,locked_by,lease_id) VALUES($1,'restore.volume',$2,$3,'running',1,now(),'test-worker',$4)`, []any{jobID, `{"restoreId":"` + restoreID.String() + `"}`, "service:" + serviceID.String(), leaseID}},
	}
	for _, statement := range statements {
		if _, err = db.Pool.Exec(ctx, statement.query, statement.args...); err != nil {
			t.Fatal(err)
		}
	}
	t.Cleanup(func() {
		_, _ = db.Pool.Exec(context.Background(), `DELETE FROM jobs WHERE id=$1`, jobID)
		_, _ = db.Pool.Exec(context.Background(), `DELETE FROM organizations WHERE id=$1`, organizationID)
	})

	worker := &Worker{Store: db}
	err = worker.restoreVolume(ctx, job{ID: jobID, LeaseID: leaseID, Attempts: 0, MaxAttempts: 1, Payload: []byte(`{"restoreId":"` + restoreID.String() + `"}`)})
	if err == nil || !strings.Contains(err.Error(), "verified artifact size") {
		t.Fatalf("restore error=%v", err)
	}
	var status, restoreError string
	if queryErr := db.Pool.QueryRow(ctx, `SELECT status,error FROM volume_restores WHERE id=$1`, restoreID).Scan(&status, &restoreError); queryErr != nil {
		t.Fatal(queryErr)
	}
	if status != "failed" || !strings.Contains(restoreError, "verified artifact size") {
		t.Fatalf("restore status=%q error=%q", status, restoreError)
	}
	if errors.Is(err, store.ErrLeaseLost) {
		t.Fatalf("restore lost its job lease: %v", err)
	}
}
