package store

import (
	"errors"
	"strings"
	"testing"

	"github.com/google/uuid"
)

func TestOfflineVolumeRestoreTargetsReboundNode(t *testing.T) {
	pool, ctx := migrationTestPool(t)
	if err := Migrate(ctx, pool); err != nil {
		t.Fatal(err)
	}
	db := &Store{Pool: pool}
	organizationID, userID := uuid.New(), uuid.New()
	projectID, environmentID, serviceID := uuid.New(), uuid.New(), uuid.New()
	destinationID, backupID := uuid.New(), uuid.New()
	for _, statement := range []struct {
		query string
		args  []any
	}{
		{`INSERT INTO organizations(id,name,slug) VALUES($1,'Offline restore',$2)`, []any{organizationID, "offline-restore-" + organizationID.String()}},
		{`INSERT INTO users(id,email,password_hash) VALUES($1,$2,'!test')`, []any{userID, userID.String() + "@example.test"}},
		{`INSERT INTO memberships(organization_id,user_id,role) VALUES($1,$2,'owner')`, []any{organizationID, userID}},
		{`INSERT INTO projects(id,organization_id,name,slug) VALUES($1,$2,'Project','project')`, []any{projectID, organizationID}},
		{`INSERT INTO environments(id,project_id,name,slug) VALUES($1,$2,'Production','production')`, []any{environmentID, projectID}},
		{`INSERT INTO compose_services(id,environment_id,name,slug,stack_name,storage_node_id,compose_yaml) VALUES($1,$2,'App','app',$3,'oldnode','services: {app: {image: nginx, volumes: [data:/data]}}\nvolumes: {data: {}}')`, []any{serviceID, environmentID, "offline-restore-" + serviceID.String()}},
		{`INSERT INTO deployments(id,compose_service_id,revision,compose_snapshot,effective_compose,status,trigger,finished_at) VALUES($1,$2,1,'services: {app: {image: nginx}}','services: {app: {image: nginx@sha256:test}}','succeeded','manual',now())`, []any{uuid.New(), serviceID}},
		{`INSERT INTO backup_destinations(id,organization_id,name,endpoint,bucket,encrypted_credentials) VALUES($1,$2,'S3','https://s3.example.test','backups','encrypted')`, []any{destinationID, organizationID}},
		{`INSERT INTO volume_backups(id,compose_service_id,volume_name,storage_node_id,destination_id,quiesce,status,object_key,size_bytes,sha256,plaintext_sha256,encrypted_data_key,finished_at) VALUES($1,$2,'data','oldnode',$3,true,'succeeded','backup.enc',42,$4,$5,'encrypted',now())`, []any{backupID, serviceID, destinationID, strings.Repeat("a", 64), strings.Repeat("b", 64)}},
	} {
		if _, err := pool.Exec(ctx, statement.query, statement.args...); err != nil {
			t.Fatal(err)
		}
	}
	principal := Principal{OrganizationID: organizationID, UserID: userID, Role: "owner"}
	if _, err := db.QueueOfflineVolumeRestoreWithAudit(ctx, principal, backupID, "app", "127.0.0.1"); !errors.Is(err, ErrOfflineRestoreRequiresStopped) {
		t.Fatalf("running offline restore error=%v", err)
	}
	if _, err := pool.Exec(ctx, `UPDATE compose_services SET desired_state='stopped',storage_node_id='newnode' WHERE id=$1`, serviceID); err != nil {
		t.Fatal(err)
	}
	if _, err := db.QueueOfflineVolumeRestoreWithAudit(ctx, principal, backupID, "app", "127.0.0.1"); !errors.Is(err, ErrOfflineRestoreRequiresStopped) {
		t.Fatalf("unconfirmed stop offline restore error=%v", err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO jobs(id,kind,payload,status,resource_key,finished_at) VALUES($1,'stop.compose','{}','succeeded',$2,now())`, uuid.New(), "service:"+serviceID.String()); err != nil {
		t.Fatal(err)
	}
	restore, err := db.QueueOfflineVolumeRestoreWithAudit(ctx, principal, backupID, "app", "127.0.0.1")
	if err != nil {
		t.Fatal(err)
	}
	if !restore.Offline || restore.TargetStorageNodeID != "newnode" || restore.Status != "queued" {
		t.Fatalf("offline restore=%#v", restore)
	}
	snapshot, err := db.BuildAIAuditSnapshot(ctx, organizationID)
	if err != nil {
		t.Fatal(err)
	}
	if len(snapshot.VolumeRestorePosture) != 1 {
		t.Fatalf("offline restore audit posture=%#v", snapshot.VolumeRestorePosture)
	}
	posture := snapshot.VolumeRestorePosture[0]
	if posture.ID != restore.ID || posture.ServiceID != serviceID || posture.ServiceName != "App" || posture.VolumeName != "data" || posture.StorageNodeID != "newnode" || posture.TargetStorageNodeID != "newnode" || posture.Status != "queued" || posture.CreatedAt.IsZero() {
		t.Fatalf("offline restore audit posture=%#v", posture)
	}
	loaded, err := db.GetVolumeRestore(ctx, organizationID, restore.ID)
	if err != nil || !loaded.Offline || loaded.TargetStorageNodeID != "newnode" {
		t.Fatalf("loaded offline restore=%#v err=%v", loaded, err)
	}
	var targetNodeID string
	var offline bool
	var jobs, audits int
	if err = pool.QueryRow(ctx, `SELECT target_storage_node_id,offline FROM volume_restores WHERE id=$1`, restore.ID).Scan(&targetNodeID, &offline); err != nil {
		t.Fatal(err)
	}
	if err = pool.QueryRow(ctx, `SELECT count(*) FROM jobs WHERE kind='restore.volume' AND payload->>'restoreId'=$1`, restore.ID.String()).Scan(&jobs); err != nil {
		t.Fatal(err)
	}
	if err = pool.QueryRow(ctx, `SELECT count(*) FROM audit_events WHERE action='volume_restore.create' AND resource_id=$1 AND metadata->>'targetStorageNodeId'='newnode' AND metadata->>'offline'='true'`, restore.ID.String()).Scan(&audits); err != nil {
		t.Fatal(err)
	}
	if targetNodeID != "newnode" || !offline || jobs != 1 || audits != 1 {
		t.Fatalf("persisted target=%q offline=%v jobs=%d audits=%d", targetNodeID, offline, jobs, audits)
	}
	if _, err = db.QueueServiceStart(ctx, organizationID, serviceID, userID); !errors.Is(err, ErrBusy) {
		t.Fatalf("start during offline restore error=%v", err)
	}
	if _, err = db.QueueDeployment(ctx, organizationID, serviceID, userID, "manual"); !errors.Is(err, ErrBusy) {
		t.Fatalf("deployment during offline restore error=%v", err)
	}
	if _, err = db.QueueRollback(ctx, organizationID, serviceID, userID); !errors.Is(err, ErrBusy) {
		t.Fatalf("rollback during offline restore error=%v", err)
	}
	var desiredState string
	if err = pool.QueryRow(ctx, `SELECT desired_state FROM compose_services WHERE id=$1`, serviceID).Scan(&desiredState); err != nil || desiredState != "stopped" {
		t.Fatalf("desired state after rejected start=%q err=%v", desiredState, err)
	}
}
