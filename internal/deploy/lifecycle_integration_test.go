package deploy

import (
	"context"
	"encoding/json"
	"os"
	"testing"
	"time"

	"github.com/GhaziBenDahmane/Orka/internal/store"
	"github.com/google/uuid"
)

func TestParentAndClusterFinalizers(t *testing.T) {
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
	organizationID, projectID, environmentID, clusterID := uuid.New(), uuid.New(), uuid.New(), uuid.New()
	statements := []struct {
		query string
		args  []any
	}{
		{`INSERT INTO organizations(id,name,slug) VALUES($1,'Finalizers',$2)`, []any{organizationID, "finalizers-" + organizationID.String()}},
		{`INSERT INTO clusters(id,organization_id,name,slug,state,deletion_requested_at) VALUES($1,$2,'Cluster','cluster','disabled',now())`, []any{clusterID, organizationID}},
		{`INSERT INTO projects(id,organization_id,name,slug,deletion_requested_at) VALUES($1,$2,'Project','project',now())`, []any{projectID, organizationID}},
		{`INSERT INTO environments(id,project_id,name,slug,deletion_requested_at) VALUES($1,$2,'Environment','environment',now())`, []any{environmentID, projectID}},
	}
	for _, statement := range statements {
		if _, err = db.Pool.Exec(ctx, statement.query, statement.args...); err != nil {
			t.Fatal(err)
		}
	}
	t.Cleanup(func() {
		_, _ = db.Pool.Exec(context.Background(), `DELETE FROM organizations WHERE id=$1`, organizationID)
	})
	worker := Worker{Store: db}
	payload, _ := json.Marshal(map[string]string{"environmentId": environmentID.String()})
	if err = worker.deleteEnvironment(ctx, job{Payload: payload}); err != nil {
		t.Fatal(err)
	}
	payload, _ = json.Marshal(map[string]string{"projectId": projectID.String()})
	if err = worker.deleteProject(ctx, job{Payload: payload}); err != nil {
		t.Fatal(err)
	}
	payload, _ = json.Marshal(map[string]string{"clusterId": clusterID.String()})
	if err = worker.deleteCluster(ctx, job{Payload: payload}); err != nil {
		t.Fatal(err)
	}
	var remaining int
	if err = db.Pool.QueryRow(ctx, `SELECT (SELECT count(*) FROM projects WHERE id=$1)+(SELECT count(*) FROM environments WHERE id=$2)+(SELECT count(*) FROM clusters WHERE id=$3)`, projectID, environmentID, clusterID).Scan(&remaining); err != nil || remaining != 0 {
		t.Fatalf("remaining resources=%d err=%v", remaining, err)
	}
}
