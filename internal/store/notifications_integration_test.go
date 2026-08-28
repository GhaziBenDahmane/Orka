package store

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"testing"
	"time"

	"github.com/google/uuid"
)

func TestFailureNotificationsAreFilteredAndDeduplicated(t *testing.T) {
	databaseURL := os.Getenv("DOCKYARD_TEST_DATABASE_URL")
	if databaseURL == "" {
		t.Skip("DOCKYARD_TEST_DATABASE_URL is not set")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	db, err := Open(ctx, databaseURL)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(db.Pool.Close)
	orgID, projectID, environmentID, serviceID, deploymentID := uuid.New(), uuid.New(), uuid.New(), uuid.New(), uuid.New()
	endpointID, ignoredEndpointID := uuid.New(), uuid.New()
	statements := []struct {
		query string
		args  []any
	}{
		{`INSERT INTO organizations(id,name,slug) VALUES($1,'Notify',$2)`, []any{orgID, "notify-" + orgID.String()}},
		{`INSERT INTO projects(id,organization_id,name,slug) VALUES($1,$2,'Project','project')`, []any{projectID, orgID}},
		{`INSERT INTO environments(id,project_id,name,slug) VALUES($1,$2,'Production','production')`, []any{environmentID, projectID}},
		{`INSERT INTO compose_services(id,environment_id,name,slug,stack_name,compose_yaml) VALUES($1,$2,'App','app',$3,'services: {}')`, []any{serviceID, environmentID, "notify-" + serviceID.String()}},
		{`INSERT INTO deployments(id,compose_service_id,revision,compose_snapshot,status,trigger) VALUES($1,$2,1,'services: {}','failed','manual')`, []any{deploymentID, serviceID}},
		{`INSERT INTO notification_endpoints(id,organization_id,name,kind,encrypted_url,encrypted_secret,events) VALUES($1,$2,'receiver','webhook','url','secret',ARRAY['deployment.failed']),($3,$2,'ignored','webhook','url','secret',ARRAY['backup.failed'])`, []any{endpointID, orgID, ignoredEndpointID}},
	}
	for _, statement := range statements {
		if _, err = db.Pool.Exec(ctx, statement.query, statement.args...); err != nil {
			t.Fatal(err)
		}
	}
	t.Cleanup(func() { _, _ = db.Pool.Exec(context.Background(), `DELETE FROM organizations WHERE id=$1`, orgID) })
	payload, _ := json.Marshal(map[string]string{"deploymentId": deploymentID.String()})
	for range 2 {
		if err = db.QueueFailureNotifications(ctx, "deploy.compose", payload, errors.New("boom")); err != nil {
			t.Fatal(err)
		}
	}
	var deliveries, jobs int
	if err = db.Pool.QueryRow(ctx, `SELECT count(*) FROM notification_deliveries WHERE endpoint_id=$1`, endpointID).Scan(&deliveries); err != nil {
		t.Fatal(err)
	}
	if err = db.Pool.QueryRow(ctx, `SELECT count(*) FROM jobs WHERE kind='notify.webhook' AND payload->>'deliveryId' IN (SELECT id::text FROM notification_deliveries WHERE endpoint_id=$1)`, endpointID).Scan(&jobs); err != nil {
		t.Fatal(err)
	}
	if deliveries != 1 || jobs != 1 {
		t.Fatalf("deliveries=%d jobs=%d, want one deduplicated delivery", deliveries, jobs)
	}
}
