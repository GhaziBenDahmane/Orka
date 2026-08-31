package store

import (
	"errors"
	"testing"

	"github.com/google/uuid"
)

func TestMoveComposeServicePreservesStateAndFailsClosed(t *testing.T) {
	pool, ctx := migrationTestPool(t)
	if err := Migrate(ctx, pool); err != nil {
		t.Fatal(err)
	}
	db := &Store{Pool: pool}
	organizationID, otherOrganizationID := uuid.New(), uuid.New()
	sourceProjectID, targetProjectID := uuid.New(), uuid.New()
	sourceEnvironmentID, targetEnvironmentID, remoteEnvironmentID, otherEnvironmentID := uuid.New(), uuid.New(), uuid.New(), uuid.New()
	clusterID := uuid.New()
	serviceID, databaseServiceID, linkedDatabaseID, busyServiceID, quotaServiceID := uuid.New(), uuid.New(), uuid.New(), uuid.New(), uuid.New()
	tagID, networkID := uuid.New(), uuid.New()
	for _, statement := range []struct {
		query string
		args  []any
	}{
		{`INSERT INTO organizations(id,name,slug) VALUES($1,'Move',$2),($3,'Other',$4)`, []any{organizationID, "move-" + organizationID.String(), otherOrganizationID, "move-" + otherOrganizationID.String()}},
		{`INSERT INTO clusters(id,organization_id,name,slug,state) VALUES($1,$2,'Remote','remote','active')`, []any{clusterID, organizationID}},
		{`INSERT INTO projects(id,organization_id,name,slug) VALUES($1,$2,'Source','source'),($3,$2,'Target','target'),($4,$5,'Other','other')`, []any{sourceProjectID, organizationID, targetProjectID, uuid.New(), otherOrganizationID}},
		{`INSERT INTO environments(id,project_id,name,slug) VALUES($1,$2,'Source','source'),($3,$4,'Target','target')`, []any{sourceEnvironmentID, sourceProjectID, targetEnvironmentID, targetProjectID}},
		{`INSERT INTO environments(id,project_id,cluster_id,name,slug) VALUES($1,$2,$3,'Remote','remote')`, []any{remoteEnvironmentID, targetProjectID, clusterID}},
		{`INSERT INTO environments(id,project_id,name,slug) SELECT $1,id,'Other','other' FROM projects WHERE organization_id=$2`, []any{otherEnvironmentID, otherOrganizationID}},
		{`INSERT INTO compose_services(id,environment_id,name,slug,stack_name,compose_yaml) VALUES
			($1,$2,'App','app',$3,'services: {web: {image: nginx}}'),
			($4,$2,'Database','database',$5,'services: {database: {image: postgres}}'),
			($6,$2,'Busy','busy',$7,'services: {web: {image: nginx}}'),
			($8,$2,'Quota','quota',$9,'services: {web: {image: nginx}}')`, []any{serviceID, sourceEnvironmentID, "move-" + serviceID.String(), databaseServiceID, "move-" + databaseServiceID.String(), busyServiceID, "move-" + busyServiceID.String(), quotaServiceID, "move-" + quotaServiceID.String()}},
		{`INSERT INTO tags(id,organization_id,name,color) VALUES($1,$2,'Frontend','#123456')`, []any{tagID, organizationID}},
		{`INSERT INTO compose_service_tags(compose_service_id,tag_id) VALUES($1,$2)`, []any{serviceID, tagID}},
		{`INSERT INTO routes(id,compose_service_id,service_name,host,target_port) VALUES($1,$2,'web',$3,80)`, []any{uuid.New(), serviceID, serviceID.String() + ".example.test"}},
		{`INSERT INTO managed_networks(id,organization_id,name,status,docker_id) VALUES($1,$2,'shared','ready','docker-network')`, []any{networkID, organizationID}},
		{`INSERT INTO compose_service_networks(compose_service_id,network_id) VALUES($1,$2)`, []any{serviceID, networkID}},
		{`INSERT INTO database_instances(id,environment_id,name,slug,engine,version,compose_service_id,encrypted_credentials) VALUES($1,$2,'Database','database','postgres','17',$3,'encrypted')`, []any{uuid.New(), sourceEnvironmentID, databaseServiceID}},
		{`INSERT INTO database_instances(id,environment_id,name,slug,engine,version,management_kind,connection_service_name,compose_service_id,encrypted_credentials) VALUES($1,$2,'Linked database','linked-database','postgres','17','compose','db',$3,'encrypted')`, []any{linkedDatabaseID, sourceEnvironmentID, serviceID}},
		{`INSERT INTO jobs(id,kind,payload,status,resource_key) VALUES($1,'stop.compose','{}','pending',$2)`, []any{uuid.New(), "service:" + busyServiceID.String()}},
	} {
		if _, err := pool.Exec(ctx, statement.query, statement.args...); err != nil {
			t.Fatal(err)
		}
	}

	moved, err := db.MoveComposeService(ctx, organizationID, serviceID, targetEnvironmentID)
	if err != nil {
		t.Fatal(err)
	}
	if moved.EnvironmentID != targetEnvironmentID || moved.Revision != 1 || len(moved.Tags) != 1 || moved.Tags[0].ID != tagID {
		t.Fatalf("moved service=%#v", moved)
	}
	var routes, networks int
	if err = pool.QueryRow(ctx, `SELECT (SELECT count(*) FROM routes WHERE compose_service_id=$1),(SELECT count(*) FROM compose_service_networks WHERE compose_service_id=$1)`, serviceID).Scan(&routes, &networks); err != nil || routes != 1 || networks != 1 {
		t.Fatalf("preserved routes=%d networks=%d err=%v", routes, networks, err)
	}
	var linkedEnvironmentID uuid.UUID
	if err = pool.QueryRow(ctx, `SELECT environment_id FROM database_instances WHERE id=$1`, linkedDatabaseID).Scan(&linkedEnvironmentID); err != nil || linkedEnvironmentID != targetEnvironmentID {
		t.Fatalf("linked database environment=%s err=%v", linkedEnvironmentID, err)
	}
	if _, err = db.MoveComposeService(ctx, organizationID, serviceID, targetEnvironmentID); err != nil {
		t.Fatalf("idempotent move: %v", err)
	}
	if _, err = db.MoveComposeService(ctx, organizationID, serviceID, remoteEnvironmentID); !errors.Is(err, ErrCrossClusterMove) {
		t.Fatalf("cross-cluster move error=%v", err)
	}
	if _, err = db.MoveComposeService(ctx, organizationID, serviceID, otherEnvironmentID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("cross-tenant move error=%v", err)
	}
	if _, err = db.MoveComposeService(ctx, organizationID, databaseServiceID, targetEnvironmentID); !errors.Is(err, ErrManagedDatabaseMove) {
		t.Fatalf("managed database move error=%v", err)
	}
	if _, err = db.MoveComposeService(ctx, organizationID, busyServiceID, targetEnvironmentID); !errors.Is(err, ErrBusy) {
		t.Fatalf("busy move error=%v", err)
	}
	if _, err = pool.Exec(ctx, `INSERT INTO resource_policies(organization_id,scope_type,scope_id,max_services) VALUES($1,'environment',$2,1)`, organizationID, targetEnvironmentID); err != nil {
		t.Fatal(err)
	}
	if _, err = db.MoveComposeService(ctx, organizationID, quotaServiceID, targetEnvironmentID); err == nil {
		t.Fatal("target environment quota was not enforced")
	} else {
		var quota *QuotaExceededError
		if !errors.As(err, &quota) || quota.Scope != "environment" {
			t.Fatalf("quota move error=%v", err)
		}
	}
}
