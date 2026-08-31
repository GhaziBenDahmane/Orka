package store

import (
	"context"
	"errors"
	"testing"

	"github.com/google/uuid"
)

func TestComposeLinkedDatabaseIdentityAndDeletionSafety(t *testing.T) {
	pool, ctx := migrationTestPool(t)
	if err := Migrate(ctx, pool); err != nil {
		t.Fatal(err)
	}
	db := &Store{Pool: pool}
	organizationID, userID := uuid.New(), uuid.New()
	projectID, environmentID, serviceID, databaseID := uuid.New(), uuid.New(), uuid.New(), uuid.New()
	for _, statement := range []struct {
		query string
		args  []any
	}{
		{`INSERT INTO organizations(id,name,slug) VALUES($1,'Linked database',$2)`, []any{organizationID, "linked-database-" + organizationID.String()}},
		{`INSERT INTO users(id,email,password_hash) VALUES($1,$2,'!test')`, []any{userID, userID.String() + "@example.test"}},
		{`INSERT INTO projects(id,organization_id,name,slug) VALUES($1,$2,'Project','project')`, []any{projectID, organizationID}},
		{`INSERT INTO environments(id,project_id,name,slug) VALUES($1,$2,'Production','production')`, []any{environmentID, projectID}},
		{`INSERT INTO compose_services(id,environment_id,name,slug,stack_name,compose_yaml) VALUES($1,$2,'Application','application',$3,'services: {db: {image: postgres:17}}')`, []any{serviceID, environmentID, "linked-" + serviceID.String()}},
		{`INSERT INTO database_instances(id,environment_id,name,slug,engine,version,driver_source,management_kind,connection_service_name,compose_service_id,encrypted_credentials,status) VALUES($1,$2,'Application database','application-db','postgres','17','built-in','compose','db',$3,'encrypted','running')`, []any{databaseID, environmentID, serviceID}},
	} {
		if _, err := pool.Exec(ctx, statement.query, statement.args...); err != nil {
			t.Fatal(err)
		}
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `DELETE FROM organizations WHERE id=$1`, organizationID)
	})

	item, err := db.GetDatabase(ctx, organizationID, databaseID)
	if err != nil || item.ManagementKind != "compose" || item.ConnectionServiceName != "db" || item.ComposeServiceID != serviceID {
		t.Fatalf("linked database=%#v err=%v", item, err)
	}
	items, err := db.ListDatabases(ctx, organizationID, environmentID)
	if err != nil || len(items) != 1 || items[0].ManagementKind != "compose" {
		t.Fatalf("linked database list=%#v err=%v", items, err)
	}
	principal := Principal{OrganizationID: organizationID, UserID: userID, Role: "owner"}
	if err = db.QueueDatabaseDeletionWithAudit(ctx, principal, databaseID, "127.0.0.1"); !errors.Is(err, ErrLinkedDatabaseDeletion) {
		t.Fatalf("linked database deletion error=%v", err)
	}
	var serviceExists, databaseExists bool
	if err = pool.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM compose_services WHERE id=$1),EXISTS(SELECT 1 FROM database_instances WHERE id=$2)`, serviceID, databaseID).Scan(&serviceExists, &databaseExists); err != nil || !serviceExists || !databaseExists {
		t.Fatalf("linked deletion mutated resources: service=%v database=%v err=%v", serviceExists, databaseExists, err)
	}
}
