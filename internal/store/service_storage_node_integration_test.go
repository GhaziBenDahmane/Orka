package store

import (
	"context"
	"errors"
	"os"
	"testing"
	"time"

	"github.com/google/uuid"
)

func TestRebindComposeServiceStorageNodeIsStoppedAuditedAndAtomic(t *testing.T) {
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

	organizationID, projectID, environmentID := uuid.New(), uuid.New(), uuid.New()
	userID, serviceID, databaseID := uuid.New(), uuid.New(), uuid.New()
	for _, statement := range []struct {
		query string
		args  []any
	}{
		{`INSERT INTO organizations(id,name,slug) VALUES($1,'Storage relocation',$2)`, []any{organizationID, "storage-relocation-" + organizationID.String()}},
		{`INSERT INTO users(id,email,password_hash) VALUES($1,$2,'!test')`, []any{userID, userID.String() + "@example.test"}},
		{`INSERT INTO memberships(organization_id,user_id,role) VALUES($1,$2,'owner')`, []any{organizationID, userID}},
		{`INSERT INTO projects(id,organization_id,name,slug) VALUES($1,$2,'Project','project')`, []any{projectID, organizationID}},
		{`INSERT INTO environments(id,project_id,name,slug) VALUES($1,$2,'Environment','environment')`, []any{environmentID, projectID}},
		{`INSERT INTO compose_services(id,environment_id,name,slug,stack_name,storage_node_id,compose_yaml) VALUES($1,$2,'Database','database','database-stack','nodeold','services: {database: {image: postgres:17, volumes: [data:/data]}}\nvolumes: {data: {}}')`, []any{serviceID, environmentID}},
		{`INSERT INTO database_instances(id,environment_id,name,slug,engine,version,storage_node_id,compose_service_id,encrypted_credentials) VALUES($1,$2,'Database','database','postgres','17','nodeold',$3,'encrypted')`, []any{databaseID, environmentID, serviceID}},
	} {
		if _, err = db.Pool.Exec(ctx, statement.query, statement.args...); err != nil {
			t.Fatal(err)
		}
	}
	t.Cleanup(func() {
		_, _ = db.Pool.Exec(context.Background(), `DELETE FROM organizations WHERE id=$1`, organizationID)
		_, _ = db.Pool.Exec(context.Background(), `DELETE FROM users WHERE id=$1`, userID)
	})
	principal := Principal{OrganizationID: organizationID, UserID: userID}

	if _, err = db.RebindComposeServiceStorageNode(ctx, principal, serviceID, "nodenew", "database", "127.0.0.1"); !errors.Is(err, ErrStorageNodeRebindRequiresStopped) {
		t.Fatalf("running-service rebind error=%v", err)
	}
	if _, err = db.Pool.Exec(ctx, `UPDATE compose_services SET desired_state='stopped' WHERE id=$1`, serviceID); err != nil {
		t.Fatal(err)
	}
	if _, err = db.RebindComposeServiceStorageNode(ctx, principal, serviceID, "nodenew", "database", "127.0.0.1"); !errors.Is(err, ErrStorageNodeRebindRequiresStopped) {
		t.Fatalf("missing successful stop rebind error=%v", err)
	}
	if _, err = db.Pool.Exec(ctx, `INSERT INTO jobs(id,kind,payload,status,resource_key,finished_at) VALUES($1,'stop.compose','{}','succeeded',$2,now())`, uuid.New(), "service:"+serviceID.String()); err != nil {
		t.Fatal(err)
	}
	jobID := uuid.New()
	if _, err = db.Pool.Exec(ctx, `INSERT INTO jobs(id,kind,payload,status,resource_key) VALUES($1,'deploy.compose','{}','pending',$2)`, jobID, "service:"+serviceID.String()); err != nil {
		t.Fatal(err)
	}
	if _, err = db.RebindComposeServiceStorageNode(ctx, principal, serviceID, "nodenew", "database", "127.0.0.1"); !errors.Is(err, ErrBusy) {
		t.Fatalf("busy-service rebind error=%v", err)
	}
	if _, err = db.Pool.Exec(ctx, `DELETE FROM jobs WHERE id=$1`, jobID); err != nil {
		t.Fatal(err)
	}
	if _, err = db.RebindComposeServiceStorageNode(ctx, principal, serviceID, "../unsafe", "database", "127.0.0.1"); !errors.Is(err, ErrInvalidStorageNode) {
		t.Fatalf("invalid-node rebind error=%v", err)
	}
	if _, err = db.RebindComposeServiceStorageNode(ctx, principal, serviceID, "nodenew", "wrong", "127.0.0.1"); !errors.Is(err, ErrStorageNodeConfirmation) {
		t.Fatalf("confirmation error=%v", err)
	}
	missingServiceAccountID := uuid.New()
	if _, err = db.RebindComposeServiceStorageNode(ctx, Principal{OrganizationID: organizationID, ServiceAccountID: &missingServiceAccountID}, serviceID, "nodenew", "database", "127.0.0.1"); err == nil {
		t.Fatal("rebind without a valid audit actor succeeded")
	}
	var serviceNode, databaseNode string
	if err = db.Pool.QueryRow(ctx, `SELECT service.storage_node_id,database.storage_node_id FROM compose_services service JOIN database_instances database ON database.compose_service_id=service.id WHERE service.id=$1`, serviceID).Scan(&serviceNode, &databaseNode); err != nil || serviceNode != "nodeold" || databaseNode != "nodeold" {
		t.Fatalf("failed audit did not roll back nodes: service=%q database=%q err=%v", serviceNode, databaseNode, err)
	}

	item, err := db.RebindComposeServiceStorageNode(ctx, principal, serviceID, "nodenew", "database", "127.0.0.1")
	if err != nil || item.StorageNodeID != "nodenew" {
		t.Fatalf("rebind item=%#v err=%v", item, err)
	}
	if err = db.Pool.QueryRow(ctx, `SELECT service.storage_node_id,database.storage_node_id FROM compose_services service JOIN database_instances database ON database.compose_service_id=service.id WHERE service.id=$1`, serviceID).Scan(&serviceNode, &databaseNode); err != nil || serviceNode != "nodenew" || databaseNode != "nodenew" {
		t.Fatalf("rebound nodes: service=%q database=%q err=%v", serviceNode, databaseNode, err)
	}
	var auditCount int
	if err = db.Pool.QueryRow(ctx, `SELECT count(*) FROM audit_events WHERE organization_id=$1 AND action='service.storage_node_rebind' AND resource_id=$2 AND metadata->>'previousNodeId'='nodeold' AND metadata->>'nodeId'='nodenew'`, organizationID, serviceID.String()).Scan(&auditCount); err != nil || auditCount != 1 {
		t.Fatalf("rebind audit count=%d err=%v", auditCount, err)
	}
	if _, err = db.RebindComposeServiceStorageNode(ctx, principal, serviceID, "nodenew", "database", "127.0.0.1"); err != nil {
		t.Fatalf("idempotent rebind: %v", err)
	}
	if err = db.Pool.QueryRow(ctx, `SELECT count(*) FROM audit_events WHERE organization_id=$1 AND action='service.storage_node_rebind' AND resource_id=$2`, organizationID, serviceID.String()).Scan(&auditCount); err != nil || auditCount != 1 {
		t.Fatalf("idempotent rebind audit count=%d err=%v", auditCount, err)
	}
	if _, err = db.Pool.Exec(ctx, `UPDATE compose_services SET storage_node_id='' WHERE id=$1`, serviceID); err != nil {
		t.Fatal(err)
	}
	if _, err = db.RebindComposeServiceStorageNode(ctx, principal, serviceID, "nodeother", "database", "127.0.0.1"); !errors.Is(err, ErrStorageNodeUnassigned) {
		t.Fatalf("unassigned-service rebind error=%v", err)
	}
}
