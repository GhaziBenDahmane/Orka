package deploy

import (
	"context"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/bendahma/dokploy-go/internal/store"
	"github.com/google/uuid"
)

type storagePlacementScheduler struct {
	node  string
	calls int
}

func (*storagePlacementScheduler) Deploy(_ context.Context, _ string, compose string, _ map[string]string, _ *Credential) (DeploymentResult, error) {
	return DeploymentResult{ResolvedImages: map[string]string{}}, nil
}
func (*storagePlacementScheduler) Remove(context.Context, string) (string, error) { return "", nil }
func (*storagePlacementScheduler) RemoveVolumes(context.Context, string) (string, error) {
	return "", nil
}
func (*storagePlacementScheduler) Logs(context.Context, string, int) (string, error) { return "", nil }
func (*storagePlacementScheduler) Nodes(context.Context) ([]Node, error)             { return nil, nil }
func (*storagePlacementScheduler) RunContainerJob(context.Context, string, string, string, map[string]string, []string) (string, error) {
	return "", nil
}
func (s *storagePlacementScheduler) ResolveStorageNode(context.Context, string) (string, error) {
	s.calls++
	return s.node, nil
}

func TestManagedDatabaseStoragePlacementIsPersistedAndReused(t *testing.T) {
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
	organizationID, projectID, environmentID, serviceID, applicationID, databaseID := uuid.New(), uuid.New(), uuid.New(), uuid.New(), uuid.New(), uuid.New()
	for _, statement := range []struct {
		query string
		args  []any
	}{
		{`INSERT INTO organizations(id,name,slug) VALUES($1,'Storage placement',$2)`, []any{organizationID, "storage-worker-" + organizationID.String()}},
		{`INSERT INTO projects(id,organization_id,name,slug) VALUES($1,$2,'Project','project')`, []any{projectID, organizationID}},
		{`INSERT INTO environments(id,project_id,name,slug) VALUES($1,$2,'Environment','environment')`, []any{environmentID, projectID}},
		{`INSERT INTO compose_services(id,environment_id,name,slug,stack_name,compose_yaml) VALUES($1,$2,'Database','database','database-stack','services: {}')`, []any{serviceID, environmentID}},
		{`INSERT INTO compose_services(id,environment_id,name,slug,stack_name,compose_yaml) VALUES($1,$2,'Router','router','router-stack','services: {}')`, []any{applicationID, environmentID}},
		{`INSERT INTO database_instances(id,environment_id,name,slug,engine,version,compose_service_id,encrypted_credentials) VALUES($1,$2,'Database','database','postgres','17',$3,'encrypted')`, []any{databaseID, environmentID, serviceID}},
	} {
		if _, err = db.Pool.Exec(ctx, statement.query, statement.args...); err != nil {
			t.Fatal(err)
		}
	}
	t.Cleanup(func() {
		_, _ = db.Pool.Exec(context.Background(), `DELETE FROM organizations WHERE id=$1`, organizationID)
	})

	compose := "services:\n  database:\n    image: postgres:17\n    volumes: [data:/var/lib/postgresql/data]\nvolumes:\n  data: {}\n"
	first := &storagePlacementScheduler{node: "nodeabc123"}
	worker := Worker{Store: db, Swarm: first}
	pinned, err := worker.pinPersistentStorage(ctx, serviceID, "database-stack", compose, nil)
	if err != nil || !strings.Contains(pinned, "node.id == nodeabc123") || first.calls != 1 {
		t.Fatalf("first placement calls=%d err=%v compose=%s", first.calls, err, pinned)
	}
	var stored string
	if err = db.Pool.QueryRow(ctx, `SELECT storage_node_id FROM database_instances WHERE id=$1`, databaseID).Scan(&stored); err != nil || stored != "nodeabc123" {
		t.Fatalf("stored node=%q err=%v", stored, err)
	}

	second := &storagePlacementScheduler{node: "differentnode"}
	worker.Swarm = second
	pinned, err = worker.pinPersistentStorage(ctx, serviceID, "database-stack", compose, nil)
	if err != nil || !strings.Contains(pinned, "node.id == nodeabc123") || strings.Contains(pinned, "differentnode") || second.calls != 0 {
		t.Fatalf("reused placement calls=%d err=%v compose=%s", second.calls, err, pinned)
	}

	applicationCompose := "services:\n  router:\n    image: example/router:1\n    volumes: [data:/app/data]\nvolumes:\n  data: {}\n"
	applicationFirst := &storagePlacementScheduler{node: "nodeapp123"}
	worker.Swarm = applicationFirst
	pinned, err = worker.pinPersistentStorage(ctx, applicationID, "router-stack", applicationCompose, nil)
	if err != nil || !strings.Contains(pinned, "node.id == nodeapp123") || applicationFirst.calls != 1 {
		t.Fatalf("application first placement calls=%d err=%v compose=%s", applicationFirst.calls, err, pinned)
	}
	if err = db.Pool.QueryRow(ctx, `SELECT storage_node_id FROM compose_services WHERE id=$1`, applicationID).Scan(&stored); err != nil || stored != "nodeapp123" {
		t.Fatalf("application stored node=%q err=%v", stored, err)
	}
	applicationSecond := &storagePlacementScheduler{node: "differentnode"}
	worker.Swarm = applicationSecond
	pinned, err = worker.pinPersistentStorage(ctx, applicationID, "router-stack", applicationCompose, nil)
	if err != nil || !strings.Contains(pinned, "node.id == nodeapp123") || strings.Contains(pinned, "differentnode") || applicationSecond.calls != 0 {
		t.Fatalf("application reused placement calls=%d err=%v compose=%s", applicationSecond.calls, err, pinned)
	}
}
