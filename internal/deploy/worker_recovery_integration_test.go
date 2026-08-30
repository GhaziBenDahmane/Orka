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

	"github.com/bendahma/dokploy-go/internal/cryptox"
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

func TestClaimSerializesJobsWithTheSameResourceKey(t *testing.T) {
	db, ctx := recoveryTestStore(t)
	firstID, secondID, cancelledID := uuid.New(), uuid.New(), uuid.New()
	if _, err := db.Pool.Exec(ctx, `INSERT INTO jobs(id,kind,payload,resource_key,created_at) VALUES($1,'test.serial','{}','database:test',now()-interval '1 second'),($2,'test.serial','{}','database:test',now())`, firstID, secondID); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Pool.Exec(ctx, `INSERT INTO jobs(id,kind,payload,resource_key,cancel_requested_at,created_at) VALUES($1,'test.serial','{}','database:cancelled',now(),now()-interval '2 seconds')`, cancelledID); err != nil {
		t.Fatal(err)
	}
	first, err := (&Worker{Store: db}).claim(ctx)
	if err != nil || first.ID != firstID {
		t.Fatalf("first claim=%s err=%v", first.ID, err)
	}
	if _, err = (&Worker{Store: db}).claim(ctx); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("second same-resource claim error=%v, want ErrNotFound", err)
	}
	if _, err = db.Pool.Exec(ctx, `UPDATE jobs SET status='succeeded',finished_at=now(),locked_at=NULL,locked_by=NULL,lease_id=NULL WHERE id=$1`, firstID); err != nil {
		t.Fatal(err)
	}
	second, err := (&Worker{Store: db}).claim(ctx)
	if err != nil || second.ID != secondID {
		t.Fatalf("second claim=%s err=%v", second.ID, err)
	}
	if _, err = db.Pool.Exec(ctx, `UPDATE jobs SET status='succeeded',finished_at=now(),locked_at=NULL,locked_by=NULL,lease_id=NULL WHERE id=$1`, secondID); err != nil {
		t.Fatal(err)
	}
	if _, err = (&Worker{Store: db}).claim(ctx); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("cancel-requested pending job was claimable: %v", err)
	}
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

type takeoverScheduler struct {
	started    chan struct{}
	release    chan struct{}
	compose    chan string
	credential chan *Credential
	output     string
}

func (s takeoverScheduler) Deploy(ctx context.Context, _ string, compose string, _ map[string]string, credential *Credential) (DeploymentResult, error) {
	if s.compose != nil {
		s.compose <- compose
	}
	if s.credential != nil {
		s.credential <- credential
	}
	if s.started != nil {
		close(s.started)
	}
	if s.release != nil {
		select {
		case <-s.release:
		case <-ctx.Done():
			return DeploymentResult{}, ctx.Err()
		}
	}
	resolved := map[string]string{}
	if !strings.Contains(compose, "@sha256:") {
		resolved["web"] = "registry.example/app@sha256:" + strings.Repeat("b", 64)
	}
	return DeploymentResult{Output: s.output, ResolvedImages: resolved}, nil
}

func TestRollbackDeploymentReplaysImmutableSnapshotWithoutRebuild(t *testing.T) {
	db, ctx := recoveryTestStore(t)
	box, err := cryptox.New(make([]byte, 32))
	if err != nil {
		t.Fatal(err)
	}
	organizationID, projectID, environmentID, serviceID, credentialID := uuid.New(), uuid.New(), uuid.New(), uuid.New(), uuid.New()
	effective := "services:\n  web:\n    image: registry.example/private/app@sha256:" + strings.Repeat("a", 64) + "\n"
	encryptedCredential, err := box.Encrypt([]byte("registry-secret"), cryptox.ResourceContext("source-credential", credentialID.String()))
	if err != nil {
		t.Fatal(err)
	}
	statements := []struct {
		query string
		args  []any
	}{
		{`INSERT INTO organizations(id,name,slug) VALUES($1,'rollback-worker',$2)`, []any{organizationID, "rollback-worker-" + organizationID.String()}},
		{`INSERT INTO projects(id,organization_id,name,slug) VALUES($1,$2,'project','project')`, []any{projectID, organizationID}},
		{`INSERT INTO environments(id,project_id,name,slug) VALUES($1,$2,'production','production')`, []any{environmentID, projectID}},
		{`INSERT INTO compose_services(id,environment_id,name,slug,stack_name,compose_yaml) VALUES($1,$2,'app','app',$3,'services: {web: {image: moving-source}}')`, []any{serviceID, environmentID, "rollback-worker-" + serviceID.String()}},
		{`INSERT INTO source_credentials(id,organization_id,kind,name,server,username,encrypted_secret) VALUES($1,$2,'registry','private registry','registry.example','robot',$3)`, []any{credentialID, organizationID, encryptedCredential}},
		{`INSERT INTO application_sources(compose_service_id,repository_url,target_service,registry_image,registry_credential_id) VALUES($1,'https://invalid.example/repository','web','registry.example/private/app',$2)`, []any{serviceID, credentialID}},
		{`INSERT INTO deployments(id,compose_service_id,revision,compose_snapshot,effective_compose,env_snapshot,status,trigger,finished_at,registry_credential_id,registry_credential_server,registry_credential_username,encrypted_registry_credential) VALUES($1,$2,1,'services: {web: {image: moving-old-tag}}',$3,'','succeeded','manual',now(),$4,'registry.example','robot',$5)`, []any{uuid.New(), serviceID, effective, credentialID, encryptedCredential}},
	}
	for _, statement := range statements {
		if _, err = db.Pool.Exec(ctx, statement.query, statement.args...); err != nil {
			t.Fatal(err)
		}
	}
	rollback, err := db.QueueRollback(ctx, organizationID, serviceID, uuid.Nil)
	if err != nil {
		t.Fatal(err)
	}
	if err = db.DeleteSourceCredential(ctx, organizationID, credentialID); err != nil {
		t.Fatal(err)
	}
	worker := &Worker{Store: db, Box: box, ID: "rollback-test"}
	claimed, err := worker.claim(ctx)
	if err != nil {
		t.Fatal(err)
	}
	deployed, credential := make(chan string, 1), make(chan *Credential, 1)
	worker.Swarm = takeoverScheduler{compose: deployed, credential: credential}
	if err = worker.execute(ctx, claimed); err != nil {
		t.Fatal(err)
	}
	if got := <-deployed; got != effective {
		t.Fatalf("rollback rebuilt or recompiled immutable snapshot:\n%s\nwant:\n%s", got, effective)
	}
	if got := <-credential; got == nil || got.Server != "registry.example" || got.Username != "robot" || got.Secret != "registry-secret" {
		t.Fatalf("rollback registry credential=%#v", got)
	}
	var status, stored string
	if err = db.Pool.QueryRow(ctx, `SELECT status,effective_compose FROM deployments WHERE id=$1`, rollback.ID).Scan(&status, &stored); err != nil || status != "succeeded" || stored != effective {
		t.Fatalf("rollback status=%q effective=%q err=%v", status, stored, err)
	}
}

func TestReconciliationDeploymentUsesEffectiveSnapshotWithoutRebuild(t *testing.T) {
	db, ctx := recoveryTestStore(t)
	organizationID, projectID, environmentID, serviceID := uuid.New(), uuid.New(), uuid.New(), uuid.New()
	deploymentID := uuid.New()
	effective := "services:\n  web:\n    image: registry.example/app@sha256:" + strings.Repeat("a", 64) + "\n"
	statements := []struct {
		query string
		args  []any
	}{
		{`INSERT INTO organizations(id,name,slug) VALUES($1,'reconcile-worker',$2)`, []any{organizationID, "reconcile-worker-" + organizationID.String()}},
		{`INSERT INTO projects(id,organization_id,name,slug) VALUES($1,$2,'project','project')`, []any{projectID, organizationID}},
		{`INSERT INTO environments(id,project_id,name,slug) VALUES($1,$2,'production','production')`, []any{environmentID, projectID}},
		{`INSERT INTO compose_services(id,environment_id,name,slug,stack_name,compose_yaml) VALUES($1,$2,'app','app',$3,'services: {web: {image: moving-source}}')`, []any{serviceID, environmentID, "reconcile-worker-" + serviceID.String()}},
		{`INSERT INTO application_sources(compose_service_id,repository_url,target_service,registry_image) VALUES($1,'https://invalid.example/repository','web','registry.example/app')`, []any{serviceID}},
		{`INSERT INTO deployments(id,compose_service_id,revision,compose_snapshot,effective_compose,status,trigger) VALUES($1,$2,1,$3,$3,'queued','reconcile')`, []any{deploymentID, serviceID, effective}},
		{`INSERT INTO jobs(id,kind,payload,resource_key) VALUES($1,'deploy.compose',jsonb_build_object('deploymentId',$2::text),$3)`, []any{uuid.New(), deploymentID, "service:" + serviceID.String()}},
	}
	for _, statement := range statements {
		if _, err := db.Pool.Exec(ctx, statement.query, statement.args...); err != nil {
			t.Fatal(err)
		}
	}
	claimed, err := (&Worker{Store: db, ID: "reconcile-test"}).claim(ctx)
	if err != nil {
		t.Fatal(err)
	}
	deployed := make(chan string, 1)
	worker := &Worker{Store: db, ID: "reconcile-test", Logger: slog.New(slog.NewTextHandler(io.Discard, nil)), Compiler: Compiler{PublicNetwork: "public"}, Swarm: takeoverScheduler{compose: deployed}}
	if err = worker.execute(ctx, claimed); err != nil {
		t.Fatal(err)
	}
	if got := <-deployed; got != effective {
		t.Fatalf("deployed compose changed:\n%s\nwant:\n%s", got, effective)
	}
	if err = worker.finish(ctx, claimed, nil); err != nil {
		t.Fatal(err)
	}
	var status, stored string
	if err = db.Pool.QueryRow(ctx, `SELECT status,effective_compose FROM deployments WHERE id=$1`, deploymentID).Scan(&status, &stored); err != nil || status != "succeeded" || stored != effective {
		t.Fatalf("deployment status=%q effective=%q err=%v", status, stored, err)
	}
}

func (takeoverScheduler) Remove(context.Context, string) (string, error) {
	return "", nil
}

func (takeoverScheduler) RemoveVolumes(context.Context, string) (string, error) {
	return "", nil
}

func (takeoverScheduler) Logs(context.Context, string, int) (string, error) {
	return "", nil
}

func (takeoverScheduler) Nodes(context.Context) ([]Node, error) {
	return nil, nil
}

func (takeoverScheduler) RunContainerJob(context.Context, string, string, string, map[string]string, []string) (string, error) {
	return "", nil
}

func TestDeploymentTakeoverRejectsPausedWorkerCompletion(t *testing.T) {
	db, ctx := recoveryTestStore(t)
	organizationID, projectID, environmentID, serviceID := uuid.New(), uuid.New(), uuid.New(), uuid.New()
	statements := []struct {
		query string
		args  []any
	}{
		{`INSERT INTO organizations(id,name,slug) VALUES($1,'takeover','takeover')`, []any{organizationID}},
		{`INSERT INTO projects(id,organization_id,name,slug) VALUES($1,$2,'takeover','takeover')`, []any{projectID, organizationID}},
		{`INSERT INTO environments(id,project_id,name,slug) VALUES($1,$2,'takeover','takeover')`, []any{environmentID, projectID}},
		{`INSERT INTO compose_services(id,environment_id,name,slug,stack_name,compose_yaml) VALUES($1,$2,'takeover','takeover',$3,$4)`, []any{serviceID, environmentID, "takeover-" + serviceID.String(), "services:\n  web:\n    image: nginx:1.29-alpine\n"}},
	}
	for _, statement := range statements {
		if _, err := db.Pool.Exec(ctx, statement.query, statement.args...); err != nil {
			t.Fatal(err)
		}
	}
	deployment, err := db.QueueDeployment(ctx, organizationID, serviceID, uuid.Nil, "manual")
	if err != nil {
		t.Fatal(err)
	}
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	firstWorker := &Worker{Store: db, ID: "worker-a", Logger: logger, Compiler: Compiler{PublicNetwork: "dockyard-public"}}
	firstLease, err := firstWorker.claim(ctx)
	if err != nil {
		t.Fatal(err)
	}
	started, release := make(chan struct{}), make(chan struct{})
	firstWorker.Swarm = takeoverScheduler{started: started, release: release, output: "stale output"}
	firstExecution := make(chan error, 1)
	go func() { firstExecution <- firstWorker.execute(ctx, firstLease) }()
	select {
	case <-started:
	case executionErr := <-firstExecution:
		t.Fatalf("first deployment stopped before scheduler: %v", executionErr)
	case <-time.After(2 * time.Second):
		t.Fatal("first deployment did not reach scheduler")
	}

	if _, err = db.Pool.Exec(ctx, `UPDATE jobs SET locked_at=now()-interval '2 minutes' WHERE id=$1`, firstLease.ID); err != nil {
		t.Fatal(err)
	}
	secondWorker := &Worker{Store: db, ID: "worker-b", Logger: logger, Compiler: Compiler{PublicNetwork: "dockyard-public"}, Swarm: takeoverScheduler{output: "replacement output"}}
	secondWorker.recoverStale(ctx)
	secondLease, err := secondWorker.claim(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if secondLease.ID != firstLease.ID || secondLease.LeaseID == firstLease.LeaseID {
		t.Fatalf("replacement lease=%#v, first=%#v", secondLease, firstLease)
	}
	if err = secondWorker.execute(ctx, secondLease); err != nil {
		t.Fatal(err)
	}
	if err = secondWorker.finish(ctx, secondLease, nil); err != nil {
		t.Fatal(err)
	}

	close(release)
	if err = <-firstExecution; !errors.Is(err, store.ErrLeaseLost) {
		t.Fatalf("paused scheduler result=%v, want lease lost", err)
	}
	if err = firstWorker.finish(ctx, firstLease, nil); !errors.Is(err, store.ErrLeaseLost) {
		t.Fatalf("paused worker finish error=%v, want lease lost", err)
	}
	var deploymentStatus, output, jobStatus string
	if err = db.Pool.QueryRow(ctx, `SELECT status,output FROM deployments WHERE id=$1`, deployment.ID).Scan(&deploymentStatus, &output); err != nil {
		t.Fatal(err)
	}
	if err = db.Pool.QueryRow(ctx, `SELECT status FROM jobs WHERE id=$1`, firstLease.ID).Scan(&jobStatus); err != nil {
		t.Fatal(err)
	}
	if deploymentStatus != "succeeded" || output != "replacement output" || jobStatus != "succeeded" {
		t.Fatalf("stale completion changed takeover result: deployment=%s output=%q job=%s", deploymentStatus, output, jobStatus)
	}
}
