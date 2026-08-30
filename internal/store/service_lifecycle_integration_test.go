package store

import (
	"errors"
	"testing"

	"github.com/google/uuid"
)

func TestServiceStopStartIntentAndReconciliationFencing(t *testing.T) {
	pool, ctx := migrationTestPool(t)
	if err := Migrate(ctx, pool); err != nil {
		t.Fatal(err)
	}
	db := &Store{Pool: pool}
	organizationID, projectID, environmentID, serviceID := uuid.New(), uuid.New(), uuid.New(), uuid.New()
	databaseID, databaseBackupID := uuid.New(), uuid.New()
	destinationID, volumePolicyID, volumeBackupID := uuid.New(), uuid.New(), uuid.New()
	stackName := "lifecycle-" + serviceID.String()
	statements := []struct {
		query string
		args  []any
	}{
		{`INSERT INTO organizations(id,name,slug) VALUES($1,'Lifecycle intent',$2)`, []any{organizationID, "lifecycle-intent-" + organizationID.String()}},
		{`INSERT INTO projects(id,organization_id,name,slug) VALUES($1,$2,'Project','project')`, []any{projectID, organizationID}},
		{`INSERT INTO environments(id,project_id,name,slug) VALUES($1,$2,'Production','production')`, []any{environmentID, projectID}},
		{`INSERT INTO compose_services(id,environment_id,name,slug,stack_name,storage_node_id,compose_yaml) VALUES($1,$2,'API','api',$3,'node1','services: {api: {image: nginx, volumes: [data:/data]}}\nvolumes: {data: {}}')`, []any{serviceID, environmentID, stackName}},
		{`INSERT INTO deployments(id,compose_service_id,revision,compose_snapshot,effective_compose,status,trigger,finished_at) VALUES($1,$2,1,'services: {api: {image: nginx}}','services: {api: {image: nginx@sha256:test}}','succeeded','manual',now())`, []any{uuid.New(), serviceID}},
		{`INSERT INTO database_instances(id,environment_id,name,slug,engine,version,compose_service_id,encrypted_credentials,status) VALUES($1,$2,'Postgres','postgres','postgres','17',$3,'encrypted','running')`, []any{databaseID, environmentID, serviceID}},
		{`INSERT INTO database_backups(id,database_instance_id,status,format,finished_at) VALUES($1,$2,'succeeded','native',now())`, []any{databaseBackupID, databaseID}},
		{`INSERT INTO backup_destinations(id,organization_id,name,endpoint,bucket,encrypted_credentials) VALUES($1,$2,'S3','https://s3.example.test','backups','encrypted')`, []any{destinationID, organizationID}},
		{`INSERT INTO volume_backup_policies(id,compose_service_id,volume_name,destination_id,interval_seconds,retention_count,quiesce,enabled,next_run_at) VALUES($1,$2,'data',$3,900,7,true,true,now())`, []any{volumePolicyID, serviceID, destinationID}},
		{`INSERT INTO volume_backups(id,volume_backup_policy_id,compose_service_id,volume_name,storage_node_id,destination_id,quiesce,status,finished_at) VALUES($1,$2,$3,'data','node1',$4,true,'succeeded',now())`, []any{volumeBackupID, volumePolicyID, serviceID, destinationID}},
	}
	for _, statement := range statements {
		if _, err := pool.Exec(ctx, statement.query, statement.args...); err != nil {
			t.Fatal(err)
		}
	}
	blockingJobID := uuid.New()
	if _, err := pool.Exec(ctx, `INSERT INTO jobs(id,kind,payload,resource_key) VALUES($1,'backup.volume','{}',$2)`, blockingJobID, "service:"+serviceID.String()); err != nil {
		t.Fatal(err)
	}
	if _, _, err := db.QueueServiceStop(ctx, organizationID, serviceID); !errors.Is(err, ErrBusy) {
		t.Fatalf("stop during data operation error=%v", err)
	}
	if _, err := pool.Exec(ctx, `DELETE FROM jobs WHERE id=$1`, blockingJobID); err != nil {
		t.Fatal(err)
	}

	jobID, queued, err := db.QueueServiceStop(ctx, organizationID, serviceID)
	if err != nil || !queued || jobID == uuid.Nil {
		t.Fatalf("stop job=%s queued=%v err=%v", jobID, queued, err)
	}
	service, _, err := db.GetComposeService(ctx, organizationID, serviceID)
	if err != nil || service.DesiredState != "stopped" {
		t.Fatalf("service desired state=%q err=%v", service.DesiredState, err)
	}
	if _, err = db.QueueDatabaseBackup(ctx, organizationID, databaseID, uuid.Nil, nil); !errors.Is(err, ErrServiceStopped) {
		t.Fatalf("database backup on stopped service error=%v", err)
	}
	if _, err = db.QueueDatabaseRestore(ctx, organizationID, databaseBackupID, uuid.Nil, "postgres"); !errors.Is(err, ErrServiceStopped) {
		t.Fatalf("database restore on stopped service error=%v", err)
	}
	if _, err = db.QueueDatabaseMigration(ctx, organizationID, DatabaseMigration{DatabaseInstanceID: databaseID, SourceKind: "external", SourceID: "source", SourceEngine: "postgres", SourceVersion: "17", SourceHost: "source.internal"}); !errors.Is(err, ErrServiceStopped) {
		t.Fatalf("database migration on stopped service error=%v", err)
	}
	if _, err = db.QueueVolumeBackup(ctx, organizationID, serviceID, "data", uuid.Nil); !errors.Is(err, ErrServiceStopped) {
		t.Fatalf("volume backup on stopped service error=%v", err)
	}
	if _, err = db.QueueVolumeRestore(ctx, organizationID, volumeBackupID, uuid.Nil, "api"); !errors.Is(err, ErrServiceStopped) {
		t.Fatalf("volume restore on stopped service error=%v", err)
	}
	candidates, err := db.ListReconciliationCandidates(ctx, 10)
	if err != nil || len(candidates) != 0 {
		t.Fatalf("stopped reconciliation candidates=%#v err=%v", candidates, err)
	}
	if repair, err := db.RecordReconciliation(ctx, ReconciliationCandidate{ServiceID: serviceID, OrganizationID: organizationID, StackName: stackName}, "missing", "intentionally absent"); !errors.Is(err, ErrNotFound) || repair != nil {
		t.Fatalf("stale reconciliation repair=%#v err=%v", repair, err)
	}
	repeatedID, repeatedQueued, err := db.QueueServiceStop(ctx, organizationID, serviceID)
	if err != nil || repeatedQueued || repeatedID != jobID {
		t.Fatalf("repeated stop job=%s queued=%v err=%v", repeatedID, repeatedQueued, err)
	}

	started, err := db.QueueServiceStart(ctx, organizationID, serviceID, uuid.Nil)
	if err != nil || started.Trigger != "start" {
		t.Fatalf("start deployment=%#v err=%v", started, err)
	}
	if err = pool.QueryRow(ctx, `SELECT desired_state FROM compose_services WHERE id=$1`, serviceID).Scan(&service.DesiredState); err != nil || service.DesiredState != "running" {
		t.Fatalf("started desired state=%q err=%v", service.DesiredState, err)
	}
	var stopKey, startKey string
	if err = pool.QueryRow(ctx, `SELECT resource_key FROM jobs WHERE id=$1`, jobID).Scan(&stopKey); err != nil {
		t.Fatal(err)
	}
	if err = pool.QueryRow(ctx, `SELECT resource_key FROM jobs WHERE payload->>'deploymentId'=$1`, started.ID.String()).Scan(&startKey); err != nil {
		t.Fatal(err)
	}
	if stopKey != "service:"+serviceID.String() || startKey != stopKey {
		t.Fatalf("resource keys stop=%q start=%q", stopKey, startKey)
	}
	if _, err = db.QueueServiceStart(ctx, organizationID, serviceID, uuid.Nil); !errors.Is(err, ErrServiceAlreadyRunning) {
		t.Fatalf("second start error=%v", err)
	}
	if _, _, err = db.QueueServiceStop(ctx, organizationID, serviceID); !errors.Is(err, ErrDeploymentActive) {
		t.Fatalf("stop during deployment error=%v", err)
	}
}
