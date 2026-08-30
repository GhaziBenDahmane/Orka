package deploy

import (
	"context"
	"io"
	"log/slog"
	"os"
	"testing"
	"time"

	"github.com/bendahma/dokploy-go/internal/store"
	"github.com/google/uuid"
)

func TestReconciliationRepairsMissingLiveSwarmStack(t *testing.T) {
	if os.Getenv("DOCKYARD_TEST_SWARM") != "1" {
		t.Skip("DOCKYARD_TEST_SWARM is not set")
	}
	db, ctx := recoveryTestStore(t)
	organizationID, projectID, environmentID, serviceID := uuid.New(), uuid.New(), uuid.New(), uuid.New()
	stackName := "reconcile-live-" + serviceID.String()[:8]
	swarm := Swarm{DockerBin: "docker", Network: "dockyard-public", Timeout: time.Minute}
	t.Cleanup(func() {
		cleanupCtx, cancel := context.WithTimeout(context.Background(), time.Minute)
		defer cancel()
		_, _ = swarm.Remove(cleanupCtx, stackName)
	})
	effective, err := (Compiler{PublicNetwork: "dockyard-public"}).Compile("services:\n  sleeper:\n    image: node@sha256:e67514e5d0f6c46656005e1b693b2ec9d52e80b641307de684d4a015ba7a4eaf\n    command: [node, -e, 'setInterval(() => {}, 60000)']\n", nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, statement := range []struct {
		query string
		args  []any
	}{
		{`INSERT INTO organizations(id,name,slug) VALUES($1,'live reconcile',$2)`, []any{organizationID, "live-reconcile-" + organizationID.String()}},
		{`INSERT INTO projects(id,organization_id,name,slug) VALUES($1,$2,'project','project')`, []any{projectID, organizationID}},
		{`INSERT INTO environments(id,project_id,name,slug) VALUES($1,$2,'production','production')`, []any{environmentID, projectID}},
		{`INSERT INTO compose_services(id,environment_id,name,slug,stack_name,compose_yaml) VALUES($1,$2,'sleeper','sleeper',$3,$4)`, []any{serviceID, environmentID, stackName, effective}},
		{`INSERT INTO deployments(id,compose_service_id,revision,compose_snapshot,effective_compose,status,trigger,finished_at) VALUES($1,$2,1,$3,$3,'succeeded','seed',now())`, []any{uuid.New(), serviceID, effective}},
	} {
		if _, err = db.Pool.Exec(ctx, statement.query, statement.args...); err != nil {
			t.Fatal(err)
		}
	}
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	worker := &Worker{Store: db, ID: "live-reconciler", Logger: logger, Compiler: Compiler{PublicNetwork: "dockyard-public"}, Swarm: swarm}
	candidate := store.ReconciliationCandidate{ServiceID: serviceID, OrganizationID: organizationID, StackName: stackName}
	worker.reconcileStack(ctx, candidate)
	worker.reconcileStack(ctx, candidate)
	claimed, err := worker.claim(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if err = worker.execute(ctx, claimed); err != nil {
		t.Fatal(err)
	}
	if err = worker.finish(ctx, claimed, nil); err != nil {
		t.Fatal(err)
	}
	status, err := swarm.Status(ctx, stackName)
	if err != nil || !status.Exists || status.HealthyServices != status.Services {
		t.Fatalf("repaired stack status=%#v err=%v", status, err)
	}
}
