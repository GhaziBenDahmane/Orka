package deploy

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/bendahma/dokploy-go/internal/store"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

func recoveryTestStore(t *testing.T) (*store.Store, context.Context) {
	t.Helper()
	databaseURL := os.Getenv("DOCKYARD_TEST_DATABASE_URL")
	if databaseURL == "" {
		t.Skip("DOCKYARD_TEST_DATABASE_URL is not set")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	t.Cleanup(cancel)
	admin, err := pgxpool.New(ctx, databaseURL)
	if err != nil {
		t.Fatal(err)
	}
	schema := "worker_recovery_" + strings.ReplaceAll(uuid.NewString(), "-", "")
	if _, err := admin.Exec(ctx, fmt.Sprintf(`CREATE SCHEMA %s`, schema)); err != nil {
		admin.Close()
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = admin.Exec(context.Background(), fmt.Sprintf(`DROP SCHEMA %s CASCADE`, schema))
		admin.Close()
	})
	config, err := pgxpool.ParseConfig(databaseURL)
	if err != nil {
		t.Fatal(err)
	}
	config.ConnConfig.RuntimeParams["search_path"] = schema
	pool, err := pgxpool.NewWithConfig(ctx, config)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)
	if err := store.Migrate(ctx, pool); err != nil {
		t.Fatal(err)
	}
	return &store.Store{Pool: pool}, ctx
}

func TestRecoverStaleJobsFinalizesCancellationAndAllowsTakeover(t *testing.T) {
	db, ctx := recoveryTestStore(t)
	organizationID, projectID, environmentID, serviceID := uuid.New(), uuid.New(), uuid.New(), uuid.New()
	deploymentID, cancelledJobID, retryJobID := uuid.New(), uuid.New(), uuid.New()
	statements := []struct {
		query string
		args  []any
	}{
		{`INSERT INTO organizations(id,name,slug) VALUES($1,'recovery','recovery')`, []any{organizationID}},
		{`INSERT INTO projects(id,organization_id,name,slug) VALUES($1,$2,'recovery','recovery')`, []any{projectID, organizationID}},
		{`INSERT INTO environments(id,project_id,name,slug) VALUES($1,$2,'recovery','recovery')`, []any{environmentID, projectID}},
		{`INSERT INTO compose_services(id,environment_id,name,slug,stack_name,compose_yaml) VALUES($1,$2,'recovery','recovery',$3,'services: {}')`, []any{serviceID, environmentID, "recovery-" + serviceID.String()}},
		{`INSERT INTO deployments(id,compose_service_id,revision,compose_snapshot,status,trigger) VALUES($1,$2,1,'services: {}','running','manual')`, []any{deploymentID, serviceID}},
		{`INSERT INTO jobs(id,kind,payload,status,locked_at,locked_by,cancel_requested_at,created_at) VALUES($1,'deploy.compose',jsonb_build_object('deploymentId',$2::text),'running',now()-interval '2 minutes','dead-worker',now()-interval '90 seconds',now()-interval '2 minutes')`, []any{cancelledJobID, deploymentID}},
		{`INSERT INTO jobs(id,kind,payload,status,locked_at,locked_by,created_at) VALUES($1,'test.recovery','{}','running',now()-interval '2 minutes','dead-worker',now()-interval '1 minute')`, []any{retryJobID}},
	}
	for _, statement := range statements {
		if _, err := db.Pool.Exec(ctx, statement.query, statement.args...); err != nil {
			t.Fatal(err)
		}
	}
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	(&Worker{Store: db, ID: "worker-a", Logger: logger}).recoverStale(ctx)

	var deploymentStatus, cancelledJobStatus, retryJobStatus string
	if err := db.Pool.QueryRow(ctx, `SELECT status FROM deployments WHERE id=$1`, deploymentID).Scan(&deploymentStatus); err != nil {
		t.Fatal(err)
	}
	if err := db.Pool.QueryRow(ctx, `SELECT status FROM jobs WHERE id=$1`, cancelledJobID).Scan(&cancelledJobStatus); err != nil {
		t.Fatal(err)
	}
	if err := db.Pool.QueryRow(ctx, `SELECT status FROM jobs WHERE id=$1`, retryJobID).Scan(&retryJobStatus); err != nil {
		t.Fatal(err)
	}
	if deploymentStatus != "cancelled" || cancelledJobStatus != "cancelled" || retryJobStatus != "pending" {
		t.Fatalf("unexpected recovery states deployment=%s cancelled_job=%s retry_job=%s", deploymentStatus, cancelledJobStatus, retryJobStatus)
	}

	claimed, err := (&Worker{Store: db, ID: "worker-b", Logger: logger}).claim(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if claimed.ID != retryJobID || claimed.Attempts != 0 {
		t.Fatalf("claimed job id=%s attempts=%d, want id=%s attempts=0", claimed.ID, claimed.Attempts, retryJobID)
	}
	var status, lockedBy string
	var attempts int
	if err := db.Pool.QueryRow(ctx, `SELECT status,locked_by,attempts FROM jobs WHERE id=$1`, retryJobID).Scan(&status, &lockedBy, &attempts); err != nil {
		t.Fatal(err)
	}
	if status != "running" || lockedBy != "worker-b" || attempts != 1 {
		t.Fatalf("takeover status=%s locked_by=%s attempts=%d", status, lockedBy, attempts)
	}
}
