package deploy

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/bendahma/dokploy-go/internal/store"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
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

func TestJobLeaseFencesStaleWorkerAfterTakeover(t *testing.T) {
	db, ctx := recoveryTestStore(t)
	jobID := uuid.New()
	if _, err := db.Pool.Exec(ctx, `INSERT INTO jobs(id,kind,payload) VALUES($1,'test.fencing','{}')`, jobID); err != nil {
		t.Fatal(err)
	}
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	firstWorker := &Worker{Store: db, ID: "worker-a", Logger: logger}
	firstLease, err := firstWorker.claim(ctx)
	if err != nil || firstLease.ID != jobID || firstLease.LeaseID == uuid.Nil {
		t.Fatalf("first lease=%#v err=%v", firstLease, err)
	}
	if _, err = db.Pool.Exec(ctx, `UPDATE jobs SET locked_at=now()-interval '2 minutes' WHERE id=$1`, jobID); err != nil {
		t.Fatal(err)
	}
	// A restarted replica may reuse its configured worker name. The per-attempt
	// token, rather than locked_by, must still fence its predecessor.
	secondWorker := &Worker{Store: db, ID: "worker-a", Logger: logger}
	secondWorker.recoverStale(ctx)
	secondLease, err := secondWorker.claim(ctx)
	if err != nil || secondLease.ID != jobID || secondLease.LeaseID == uuid.Nil || secondLease.LeaseID == firstLease.LeaseID {
		t.Fatalf("second lease=%#v err=%v", secondLease, err)
	}
	if owned, err := firstWorker.renewJobLease(ctx, firstLease); err != nil || owned {
		t.Fatalf("stale heartbeat owned=%t err=%v", owned, err)
	}
	if _, err = db.Pool.Exec(ctx, `CREATE TABLE job_resource_probe(id uuid PRIMARY KEY,value text NOT NULL)`); err != nil {
		t.Fatal(err)
	}
	if _, err = db.Pool.Exec(ctx, `INSERT INTO job_resource_probe VALUES($1,'succeeded')`, jobID); err != nil {
		t.Fatal(err)
	}
	err = db.WithJobLease(ctx, firstLease.ID, firstLease.LeaseID, func(tx pgx.Tx) error {
		_, updateErr := tx.Exec(ctx, `UPDATE job_resource_probe SET value='running' WHERE id=$1`, jobID)
		return updateErr
	})
	if !errors.Is(err, store.ErrLeaseLost) {
		t.Fatalf("stale resource transition error=%v, want lease lost", err)
	}
	var resourceValue string
	if err = db.Pool.QueryRow(ctx, `SELECT value FROM job_resource_probe WHERE id=$1`, jobID).Scan(&resourceValue); err != nil || resourceValue != "succeeded" {
		t.Fatalf("resource changed by stale worker: value=%q err=%v", resourceValue, err)
	}
	if err = db.WithJobLease(ctx, secondLease.ID, secondLease.LeaseID, func(tx pgx.Tx) error {
		_, updateErr := tx.Exec(ctx, `UPDATE job_resource_probe SET value='current' WHERE id=$1`, jobID)
		return updateErr
	}); err != nil {
		t.Fatal(err)
	}
	if err = firstWorker.finish(ctx, firstLease, nil); !errors.Is(err, store.ErrLeaseLost) {
		t.Fatalf("stale finish error=%v, want lease lost", err)
	}
	var status, lockedBy string
	var leaseID uuid.UUID
	if err = db.Pool.QueryRow(ctx, `SELECT status,locked_by,lease_id FROM jobs WHERE id=$1`, jobID).Scan(&status, &lockedBy, &leaseID); err != nil {
		t.Fatal(err)
	}
	if status != "running" || lockedBy != "worker-a" || leaseID != secondLease.LeaseID {
		t.Fatalf("replacement lease changed: status=%s worker=%s lease=%s", status, lockedBy, leaseID)
	}
	if err = secondWorker.finish(ctx, secondLease, nil); err != nil {
		t.Fatal(err)
	}
	var leaseCleared bool
	if err = db.Pool.QueryRow(ctx, `SELECT status,lease_id IS NULL FROM jobs WHERE id=$1`, jobID).Scan(&status, &leaseCleared); err != nil {
		t.Fatal(err)
	}
	if status != "succeeded" || !leaseCleared {
		t.Fatalf("completed status=%s lease_cleared=%t", status, leaseCleared)
	}
	if err = db.Pool.QueryRow(ctx, `SELECT value FROM job_resource_probe WHERE id=$1`, jobID).Scan(&resourceValue); err != nil || resourceValue != "current" {
		t.Fatalf("resource transition was not preserved: value=%q err=%v", resourceValue, err)
	}
}

func TestRecoverySkipsActiveLeaseTransition(t *testing.T) {
	db, ctx := recoveryTestStore(t)
	jobID := uuid.New()
	if _, err := db.Pool.Exec(ctx, `INSERT INTO jobs(id,kind,payload,status,locked_at,locked_by,lease_id) VALUES($1,'test.fencing','{}','running',now()-interval '2 minutes','worker-a',$2)`, jobID, uuid.New()); err != nil {
		t.Fatal(err)
	}
	var leaseID uuid.UUID
	if err := db.Pool.QueryRow(ctx, `SELECT lease_id FROM jobs WHERE id=$1`, jobID).Scan(&leaseID); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Pool.Exec(ctx, `CREATE TABLE job_resource_probe(id uuid PRIMARY KEY,value text NOT NULL)`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Pool.Exec(ctx, `INSERT INTO job_resource_probe VALUES($1,'succeeded')`, jobID); err != nil {
		t.Fatal(err)
	}

	transitionStarted := make(chan struct{})
	releaseTransition := make(chan struct{})
	transitionDone := make(chan error, 1)
	go func() {
		transitionDone <- db.WithJobLease(ctx, jobID, leaseID, func(tx pgx.Tx) error {
			if _, err := tx.Exec(ctx, `UPDATE job_resource_probe SET value='running' WHERE id=$1`, jobID); err != nil {
				return err
			}
			close(transitionStarted)
			<-releaseTransition
			return nil
		})
	}()
	<-transitionStarted

	recoveryDone := make(chan struct{})
	go func() {
		(&Worker{Store: db, ID: "worker-b", Logger: slog.New(slog.NewTextHandler(io.Discard, nil))}).recoverStale(ctx)
		close(recoveryDone)
	}()
	select {
	case <-recoveryDone:
	case <-time.After(2 * time.Second):
		close(releaseTransition)
		t.Fatal("recovery did not skip the resource transition's locked job")
	}
	close(releaseTransition)
	if err := <-transitionDone; err != nil {
		t.Fatal(err)
	}
	<-recoveryDone

	var jobStatus, resourceStatus string
	if err := db.Pool.QueryRow(ctx, `SELECT status FROM jobs WHERE id=$1`, jobID).Scan(&jobStatus); err != nil {
		t.Fatal(err)
	}
	if err := db.Pool.QueryRow(ctx, `SELECT value FROM job_resource_probe WHERE id=$1`, jobID).Scan(&resourceStatus); err != nil {
		t.Fatal(err)
	}
	if jobStatus != "running" || resourceStatus != "running" {
		t.Fatalf("active attempt was recovered: job=%s resource=%s", jobStatus, resourceStatus)
	}
}

func TestFinishSerializesWithCancellation(t *testing.T) {
	db, ctx := recoveryTestStore(t)
	organizationID, projectID, environmentID, serviceID := uuid.New(), uuid.New(), uuid.New(), uuid.New()
	deploymentID, jobID, leaseID := uuid.New(), uuid.New(), uuid.New()
	statements := []struct {
		query string
		args  []any
	}{
		{`INSERT INTO organizations(id,name,slug) VALUES($1,'finish-race','finish-race')`, []any{organizationID}},
		{`INSERT INTO projects(id,organization_id,name,slug) VALUES($1,$2,'finish-race','finish-race')`, []any{projectID, organizationID}},
		{`INSERT INTO environments(id,project_id,name,slug) VALUES($1,$2,'finish-race','finish-race')`, []any{environmentID, projectID}},
		{`INSERT INTO compose_services(id,environment_id,name,slug,stack_name,compose_yaml) VALUES($1,$2,'finish-race','finish-race',$3,'services: {}')`, []any{serviceID, environmentID, "finish-race-" + serviceID.String()}},
		{`INSERT INTO deployments(id,compose_service_id,revision,compose_snapshot,status,trigger) VALUES($1,$2,1,'services: {}','running','manual')`, []any{deploymentID, serviceID}},
		{`INSERT INTO jobs(id,kind,payload,status,locked_at,locked_by,lease_id) VALUES($1,'deploy.compose',jsonb_build_object('deploymentId',$2::text),'running',now(),'worker-a',$3)`, []any{jobID, deploymentID, leaseID}},
	}
	for _, statement := range statements {
		if _, err := db.Pool.Exec(ctx, statement.query, statement.args...); err != nil {
			t.Fatal(err)
		}
	}

	cancelTx, err := db.Pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer cancelTx.Rollback(ctx)
	if _, err = cancelTx.Exec(ctx, `UPDATE jobs SET cancel_requested_at=now() WHERE id=$1`, jobID); err != nil {
		t.Fatal(err)
	}
	worker := &Worker{Store: db, ID: "worker-a", Logger: slog.New(slog.NewTextHandler(io.Discard, nil))}
	finishDone := make(chan error, 1)
	go func() {
		finishDone <- worker.finish(ctx, job{ID: jobID, LeaseID: leaseID, Kind: "deploy.compose", Payload: json.RawMessage(`{"deploymentId":"` + deploymentID.String() + `"}`)}, nil)
	}()
	select {
	case finishErr := <-finishDone:
		_ = cancelTx.Rollback(ctx)
		t.Fatalf("finish bypassed the cancellation row lock: %v", finishErr)
	case <-time.After(100 * time.Millisecond):
	}
	if err = cancelTx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	if err = <-finishDone; err != nil {
		t.Fatal(err)
	}

	var jobStatus, deploymentStatus string
	if err = db.Pool.QueryRow(ctx, `SELECT status FROM jobs WHERE id=$1`, jobID).Scan(&jobStatus); err != nil {
		t.Fatal(err)
	}
	if err = db.Pool.QueryRow(ctx, `SELECT status FROM deployments WHERE id=$1`, deploymentID).Scan(&deploymentStatus); err != nil {
		t.Fatal(err)
	}
	if jobStatus != "cancelled" || deploymentStatus != "cancelled" {
		t.Fatalf("cancellation lost to finish: job=%s deployment=%s", jobStatus, deploymentStatus)
	}
}
