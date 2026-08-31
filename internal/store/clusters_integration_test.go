package store

import (
	"context"
	"errors"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/bendahma/dokploy-go/internal/clustercontract"
	"github.com/google/uuid"
)

func TestClusterEnrollmentTokenIsSingleUse(t *testing.T) {
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
	orgID := uuid.New()
	if _, err = db.Pool.Exec(ctx, `INSERT INTO organizations(id,name,slug) VALUES($1,'Cluster',$2)`, orgID, "cluster-"+orgID.String()); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = db.Pool.Exec(context.Background(), `DELETE FROM jobs WHERE kind='delete.cluster' AND payload->>'clusterId' IN (SELECT id::text FROM clusters WHERE organization_id=$1)`, orgID)
		_, _ = db.Pool.Exec(context.Background(), `DELETE FROM organizations WHERE id=$1`, orgID)
	})
	cluster, err := db.CreateCluster(ctx, Cluster{OrganizationID: orgID, Name: "Paris", Slug: "paris", Labels: map[string]any{"region": "eu-west"}})
	if err != nil {
		t.Fatal(err)
	}
	tokenHash := []byte("hashed-enrollment-token")
	csrHash := []byte("hashed-enrollment-csr")
	artifacts := ClusterEnrollmentArtifacts{
		Certificate:          "issued-certificate",
		CABundle:             "issued-ca-bundle",
		SigningCACertificate: "issued-signing-ca",
		SigningCAFingerprint: "sha256:" + strings.Repeat("a", 64),
	}
	if err = db.CreateClusterEnrollmentToken(ctx, orgID, cluster.ID, uuid.Nil, tokenHash, time.Now().Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	lookedUp, err := db.LookupClusterEnrollmentToken(ctx, tokenHash, csrHash)
	if err != nil || lookedUp.Cluster.ID != cluster.ID || lookedUp.Artifacts.Certificate != "" {
		t.Fatalf("cluster=%#v err=%v", lookedUp, err)
	}
	stored, created, err := db.CompleteClusterEnrollment(ctx, tokenHash, csrHash, artifacts, "012345", time.Now().Add(time.Hour))
	if err != nil || !created || stored.Certificate != artifacts.Certificate {
		t.Fatalf("complete enrollment artifacts=%#v created=%t err=%v", stored, created, err)
	}
	retried, err := db.LookupClusterEnrollmentToken(ctx, tokenHash, csrHash)
	if err != nil || retried.Cluster.ID != cluster.ID || retried.Artifacts != artifacts {
		t.Fatalf("retry lookup=%#v err=%v", retried, err)
	}
	winning, created, err := db.CompleteClusterEnrollment(ctx, tokenHash, csrHash, ClusterEnrollmentArtifacts{Certificate: "losing-race-certificate"}, "other", time.Now().Add(2*time.Hour))
	if err != nil || created || winning != artifacts {
		t.Fatalf("retry completion artifacts=%#v created=%t err=%v", winning, created, err)
	}
	if _, err = db.LookupClusterEnrollmentToken(ctx, tokenHash, []byte("different-csr")); !errors.Is(err, ErrNotFound) {
		t.Fatalf("different CSR lookup error = %v", err)
	}
	if _, _, err = db.CompleteClusterEnrollment(ctx, tokenHash, []byte("different-csr"), artifacts, "other", time.Now().Add(time.Hour)); !errors.Is(err, ErrNotFound) {
		t.Fatalf("different CSR completion error = %v", err)
	}
	if err = db.AuthenticateClusterCertificate(ctx, cluster.ID, "012345"); err != nil {
		t.Fatalf("authenticate current certificate: %v", err)
	}
	if err = db.AuthenticateClusterCertificate(ctx, cluster.ID, "superseded"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("superseded certificate error = %v", err)
	}
	if err = db.RotateClusterCertificate(ctx, cluster.ID, "012345", "6789ab", time.Now().Add(2*time.Hour), "sha256:"+strings.Repeat("b", 64)); err != nil {
		t.Fatal(err)
	}
	var currentSerial, pendingSerial string
	if err = db.Pool.QueryRow(ctx, `SELECT certificate_serial,pending_certificate_serial FROM clusters WHERE id=$1`, cluster.ID).Scan(&currentSerial, &pendingSerial); err != nil || currentSerial != "012345" || pendingSerial != "6789ab" {
		t.Fatalf("two-phase rotation state current=%q pending=%q err=%v", currentSerial, pendingSerial, err)
	}
	if err = db.AuthenticateClusterCertificate(ctx, cluster.ID, "012345"); err != nil {
		t.Fatalf("current certificate was revoked before replacement confirmation: %v", err)
	}
	if err = db.AuthenticateClusterCertificate(ctx, cluster.ID, "6789ab"); err != nil {
		t.Fatalf("authenticate rotated certificate: %v", err)
	}
	if err = db.AuthenticateClusterCertificate(ctx, cluster.ID, "012345"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("old certificate remained valid after replacement confirmation: %v", err)
	}
	if err = db.RotateClusterCertificate(ctx, cluster.ID, "6789ab", "abcdef", time.Now().Add(2*time.Hour), "sha256:"+strings.Repeat("c", 64)); err != nil {
		t.Fatal(err)
	}
	if err = db.RotateClusterCertificate(ctx, cluster.ID, "6789ab", "fedcba", time.Now().Add(2*time.Hour), "sha256:"+strings.Repeat("d", 64)); err != nil {
		t.Fatalf("retry rotation with still-current certificate: %v", err)
	}
	if err = db.AuthenticateClusterCertificate(ctx, cluster.ID, "abcdef"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("superseded pending certificate error = %v", err)
	}
	if err = db.AuthenticateClusterCertificate(ctx, cluster.ID, "6789ab"); err != nil {
		t.Fatalf("current certificate invalid during retried rotation: %v", err)
	}
	if err = db.AuthenticateClusterCertificate(ctx, cluster.ID, "fedcba"); err != nil {
		t.Fatalf("authenticate retried replacement certificate: %v", err)
	}
	if err = db.RecordClusterHeartbeat(ctx, cluster.ID, "1.2.3", "registry.example/dockyard@sha256:"+strings.Repeat("a", 64), "completed", "28.0.1", map[string]any{"nodes": 3}, clustercontract.Baseline()); err != nil {
		t.Fatal(err)
	}
	command, err := db.EnqueueClusterCommand(ctx, cluster.ID, uuid.New(), "swarm.nodes", "encrypted")
	if err != nil {
		t.Fatal(err)
	}
	claimed, err := db.ClaimClusterCommand(ctx, cluster.ID, time.Minute)
	if err != nil || claimed.ID != command.ID || claimed.LeaseID == nil {
		t.Fatalf("claimed=%#v err=%v", claimed, err)
	}
	if err = db.RenewClusterCommand(ctx, cluster.ID, command.ID, uuid.New(), time.Minute); !errors.Is(err, ErrLeaseLost) {
		t.Fatalf("wrong lease renewal error = %v", err)
	}
	if err = db.RenewClusterCommand(ctx, cluster.ID, command.ID, *claimed.LeaseID, time.Minute); err != nil {
		t.Fatal(err)
	}
	if err = db.CompleteClusterCommand(ctx, cluster.ID, command.ID, *claimed.LeaseID, "encrypted-result", false); err != nil {
		t.Fatal(err)
	}
	if _, err = db.ClaimClusterCommand(ctx, cluster.ID, time.Minute); !errors.Is(err, ErrNotFound) {
		t.Fatalf("empty queue error = %v", err)
	}
	partitioned, err := db.EnqueueClusterCommand(ctx, cluster.ID, uuid.New(), "swarm.nodes", "encrypted-after-partition")
	if err != nil {
		t.Fatal(err)
	}
	oldLease, err := db.ClaimClusterCommand(ctx, cluster.ID, 10*time.Second)
	if err != nil || oldLease.ID != partitioned.ID || oldLease.LeaseID == nil {
		t.Fatalf("old lease=%#v err=%v", oldLease, err)
	}
	if _, err = db.Pool.Exec(ctx, `UPDATE cluster_commands SET lease_expires_at=now()-interval '1 second' WHERE id=$1`, partitioned.ID); err != nil {
		t.Fatal(err)
	}
	if _, err = db.ClaimClusterCommand(ctx, cluster.ID, time.Minute); !errors.Is(err, ErrNotFound) {
		t.Fatalf("expired command backoff error = %v", err)
	}
	if _, err = db.Pool.Exec(ctx, `UPDATE cluster_commands SET run_after=now()-interval '1 second' WHERE id=$1`, partitioned.ID); err != nil {
		t.Fatal(err)
	}
	newLease, err := db.ClaimClusterCommand(ctx, cluster.ID, time.Minute)
	if err != nil || newLease.ID != partitioned.ID || newLease.LeaseID == nil || *newLease.LeaseID == *oldLease.LeaseID {
		t.Fatalf("replacement lease=%#v err=%v", newLease, err)
	}
	if err = db.CompleteClusterCommand(ctx, cluster.ID, partitioned.ID, *oldLease.LeaseID, "stale-result", false); !errors.Is(err, ErrLeaseLost) {
		t.Fatalf("partitioned agent completion error=%v, want lease lost", err)
	}
	if err = db.CompleteClusterCommand(ctx, cluster.ID, partitioned.ID, *newLease.LeaseID, "fresh-result", false); err != nil {
		t.Fatal(err)
	}
	completed, err := db.GetClusterCommand(ctx, cluster.ID, partitioned.ID)
	if err != nil || completed.Status != "succeeded" || completed.EncryptedResult != "fresh-result" || completed.Attempts != 2 {
		t.Fatalf("completed replacement command=%#v err=%v", completed, err)
	}
	if _, err = db.UpdateClusterState(ctx, orgID, cluster.ID, "draining"); err != nil {
		t.Fatal(err)
	}
	if _, err = db.EnqueueClusterCommand(ctx, cluster.ID, uuid.New(), "swarm.nodes", "encrypted"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("enqueue on draining cluster error = %v", err)
	}
	if _, err = db.UpdateClusterState(ctx, orgID, cluster.ID, "active"); err != nil {
		t.Fatal(err)
	}
	items, err := db.ListClusters(ctx, orgID)
	if err != nil || len(items) != 1 || items[0].State != "active" || items[0].CertificateNotAfter == nil || items[0].LastSeenAt == nil || items[0].AgentVersion != "1.2.3" || items[0].Capabilities.ProtocolVersion != clustercontract.ProtocolVersion {
		t.Fatalf("clusters=%#v err=%v", items, err)
	}
	if err = db.QueueClusterDeletion(ctx, orgID, cluster.ID); err != nil {
		t.Fatal(err)
	}
	if err = db.QueueClusterDeletion(ctx, orgID, cluster.ID); err != nil {
		t.Fatalf("idempotent cluster deletion: %v", err)
	}
	if err = db.AuthenticateClusterCertificate(ctx, cluster.ID, "6789ab"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("certificate remained active during deletion: %v", err)
	}
	var deletionJobs int
	if err = db.Pool.QueryRow(ctx, `SELECT count(*) FROM jobs WHERE kind='delete.cluster' AND payload->>'clusterId'=$1 AND status='pending'`, cluster.ID.String()).Scan(&deletionJobs); err != nil || deletionJobs != 1 {
		t.Fatalf("deletion jobs=%d err=%v", deletionJobs, err)
	}
	assignedCluster := uuid.New()
	projectID, environmentID := uuid.New(), uuid.New()
	if _, err = db.Pool.Exec(ctx, `INSERT INTO clusters(id,organization_id,name,slug,state) VALUES($1,$2,'Assigned','assigned','active')`, assignedCluster, orgID); err == nil {
		_, err = db.Pool.Exec(ctx, `INSERT INTO projects(id,organization_id,name,slug) VALUES($1,$2,'Assigned','assigned')`, projectID, orgID)
	}
	if err == nil {
		_, err = db.Pool.Exec(ctx, `INSERT INTO environments(id,project_id,cluster_id,name,slug) VALUES($1,$2,$3,'Assigned','assigned')`, environmentID, projectID, assignedCluster)
	}
	if err != nil {
		t.Fatal(err)
	}
	if err = db.QueueClusterDeletion(ctx, orgID, assignedCluster); !errors.Is(err, ErrBusy) {
		t.Fatalf("assigned cluster deletion error=%v, want busy", err)
	}
}

func TestClusterCommandsFollowOwningJobLease(t *testing.T) {
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
	organizationID, clusterID := uuid.New(), uuid.New()
	jobID, jobLeaseID := uuid.New(), uuid.New()
	if _, err = db.Pool.Exec(ctx, `INSERT INTO organizations(id,name,slug) VALUES($1,'Owned commands',$2)`, organizationID, "owned-commands-"+organizationID.String()); err == nil {
		_, err = db.Pool.Exec(ctx, `INSERT INTO clusters(id,organization_id,name,slug,state,last_seen_at) VALUES($1,$2,'Remote','remote','active',now())`, clusterID, organizationID)
	}
	if err == nil {
		_, err = db.Pool.Exec(ctx, `INSERT INTO jobs(id,kind,payload,status,locked_at,locked_by,lease_id) VALUES($1,'test.remote-owner','{}','running',now(),'worker-a',$2)`, jobID, jobLeaseID)
	}
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = db.Pool.Exec(context.Background(), `DELETE FROM organizations WHERE id=$1`, organizationID)
		_, _ = db.Pool.Exec(context.Background(), `DELETE FROM jobs WHERE id=$1`, jobID)
	})
	commandID := uuid.New()
	if _, err = db.EnqueueOwnedClusterCommand(ctx, clusterID, commandID, "swarm.nodes", "encrypted", jobID, jobLeaseID); err != nil {
		t.Fatal(err)
	}
	var storedJobID, storedLeaseID uuid.UUID
	if err = db.Pool.QueryRow(ctx, `SELECT owner_job_id,owner_job_lease_id FROM cluster_commands WHERE id=$1`, commandID).Scan(&storedJobID, &storedLeaseID); err != nil || storedJobID != jobID || storedLeaseID != jobLeaseID {
		t.Fatalf("command owner job=%s lease=%s err=%v", storedJobID, storedLeaseID, err)
	}
	claimed, err := db.ClaimClusterCommand(ctx, clusterID, time.Minute)
	if err != nil || claimed.ID != commandID || claimed.LeaseID == nil {
		t.Fatalf("claimed owned command=%#v err=%v", claimed, err)
	}
	if _, err = db.Pool.Exec(ctx, `UPDATE jobs SET status='pending',locked_at=NULL,locked_by=NULL,lease_id=NULL WHERE id=$1`, jobID); err != nil {
		t.Fatal(err)
	}
	if err = db.RenewClusterCommand(ctx, clusterID, commandID, *claimed.LeaseID, time.Minute); !errors.Is(err, ErrLeaseLost) {
		t.Fatalf("renew after parent lease loss error=%v, want lease lost", err)
	}
	if err = db.CompleteClusterCommand(ctx, clusterID, commandID, *claimed.LeaseID, "stale-result", false); !errors.Is(err, ErrLeaseLost) {
		t.Fatalf("complete after parent lease loss error=%v, want lease lost", err)
	}
	if _, err = db.ClaimClusterCommand(ctx, clusterID, time.Minute); !errors.Is(err, ErrNotFound) {
		t.Fatalf("orphan command claim error=%v, want not found", err)
	}
	var status, lastError string
	if err = db.Pool.QueryRow(ctx, `SELECT status,last_error FROM cluster_commands WHERE id=$1`, commandID).Scan(&status, &lastError); err != nil || status != "cancelled" || lastError != "originating worker lease lost" {
		t.Fatalf("orphan command status=%q error=%q queryErr=%v", status, lastError, err)
	}
	if _, err = db.EnqueueOwnedClusterCommand(ctx, clusterID, uuid.New(), "swarm.nodes", "encrypted", jobID, jobLeaseID); !errors.Is(err, ErrLeaseLost) {
		t.Fatalf("enqueue after parent lease loss error=%v, want lease lost", err)
	}
}

func TestAgentUpgradeRequiresReplacementHeartbeat(t *testing.T) {
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
	organizationID, clusterID := uuid.New(), uuid.New()
	if _, err = db.Pool.Exec(ctx, `INSERT INTO organizations(id,name,slug) VALUES($1,'Agent upgrade',$2)`, organizationID, "agent-upgrade-"+organizationID.String()); err == nil {
		_, err = db.Pool.Exec(ctx, `INSERT INTO clusters(id,organization_id,name,slug,state,last_seen_at) VALUES($1,$2,'Remote','remote','active',now())`, clusterID, organizationID)
	}
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = db.Pool.Exec(context.Background(), `DELETE FROM organizations WHERE id=$1`, organizationID)
	})

	target := "registry.example/dockyard@sha256:" + strings.Repeat("b", 64)
	upgrade, err := db.EnqueueAgentUpgrade(ctx, clusterID, uuid.New(), "encrypted-upgrade", target)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = db.EnqueueAgentUpgrade(ctx, clusterID, uuid.New(), "encrypted-duplicate", target); !errors.Is(err, ErrBusy) {
		t.Fatalf("concurrent upgrade error=%v, want ErrBusy", err)
	}
	claimed, err := db.ClaimClusterCommand(ctx, clusterID, time.Minute)
	if err != nil || claimed.ID != upgrade.ID || claimed.LeaseID == nil || claimed.TargetImage != target {
		t.Fatalf("claimed upgrade=%#v err=%v", claimed, err)
	}
	if err = db.CompleteClusterCommand(ctx, clusterID, upgrade.ID, *claimed.LeaseID, "encrypted-submission", false); err != nil {
		t.Fatal(err)
	}
	verifying, err := db.GetClusterCommand(ctx, clusterID, upgrade.ID)
	if err != nil || verifying.Status != "verifying" || verifying.TargetImage != target {
		t.Fatalf("submitted upgrade=%#v err=%v", verifying, err)
	}
	oldImage := "registry.example/dockyard@sha256:" + strings.Repeat("a", 64)
	if err = db.RecordClusterHeartbeat(ctx, clusterID, "1.0.0", oldImage, "updating", "29.0.0", map[string]any{"nodes": 3}, clustercontract.Baseline()); err != nil {
		t.Fatal(err)
	}
	verifying, err = db.GetClusterCommand(ctx, clusterID, upgrade.ID)
	if err != nil || verifying.Status != "verifying" {
		t.Fatalf("upgrade completed before replacement heartbeat=%#v err=%v", verifying, err)
	}
	if err = db.RecordClusterHeartbeat(ctx, clusterID, "2.0.0", target, "completed", "29.0.0", map[string]any{"nodes": 3}, clustercontract.Baseline()); err != nil {
		t.Fatal(err)
	}
	succeeded, err := db.GetClusterCommand(ctx, clusterID, upgrade.ID)
	if err != nil || succeeded.Status != "succeeded" {
		t.Fatalf("converged upgrade=%#v err=%v", succeeded, err)
	}
	cluster, err := db.GetCluster(ctx, organizationID, clusterID)
	if err != nil || cluster.AgentImage != target || cluster.AgentUpdateState != "completed" || cluster.AgentVersion != "2.0.0" {
		t.Fatalf("cluster release state=%#v err=%v", cluster, err)
	}

	rollbackTarget := "registry.example/dockyard@sha256:" + strings.Repeat("c", 64)
	rollback, err := db.EnqueueAgentUpgrade(ctx, clusterID, uuid.New(), "encrypted-rollback", rollbackTarget)
	if err != nil {
		t.Fatal(err)
	}
	claimed, err = db.ClaimClusterCommand(ctx, clusterID, time.Minute)
	if err != nil || claimed.ID != rollback.ID || claimed.LeaseID == nil {
		t.Fatalf("claimed rollback=%#v err=%v", claimed, err)
	}
	if err = db.CompleteClusterCommand(ctx, clusterID, rollback.ID, *claimed.LeaseID, "encrypted-submission", false); err != nil {
		t.Fatal(err)
	}
	if err = db.RecordClusterHeartbeat(ctx, clusterID, "2.0.0", target, "rollback_completed", "29.0.0", map[string]any{"nodes": 3}, clustercontract.Baseline()); err != nil {
		t.Fatal(err)
	}
	failed, err := db.GetClusterCommand(ctx, clusterID, rollback.ID)
	if err != nil || failed.Status != "failed" || !strings.Contains(failed.LastError, "rollback_completed") {
		t.Fatalf("rolled-back upgrade=%#v err=%v", failed, err)
	}

	timedOut, err := db.EnqueueAgentUpgrade(ctx, clusterID, uuid.New(), "encrypted-timeout", rollbackTarget)
	if err != nil {
		t.Fatal(err)
	}
	claimed, err = db.ClaimClusterCommand(ctx, clusterID, time.Minute)
	if err != nil || claimed.ID != timedOut.ID || claimed.LeaseID == nil {
		t.Fatalf("claimed timeout=%#v err=%v", claimed, err)
	}
	if err = db.CompleteClusterCommand(ctx, clusterID, timedOut.ID, *claimed.LeaseID, "encrypted-submission", false); err != nil {
		t.Fatal(err)
	}
	if _, err = db.Pool.Exec(ctx, `UPDATE cluster_commands SET run_after=now()-interval '1 second' WHERE id=$1`, timedOut.ID); err != nil {
		t.Fatal(err)
	}
	if err = db.RecordClusterHeartbeat(ctx, clusterID, "3.0.0", rollbackTarget, "completed", "29.0.0", map[string]any{"nodes": 3}, clustercontract.Baseline()); err != nil {
		t.Fatal(err)
	}
	timedOut, err = db.GetClusterCommand(ctx, clusterID, timedOut.ID)
	if err != nil || timedOut.Status != "failed" || !strings.Contains(timedOut.LastError, "verification deadline") {
		t.Fatalf("timed-out upgrade=%#v err=%v", timedOut, err)
	}
	if _, err = db.EnqueueAgentUpgrade(ctx, clusterID, uuid.New(), "encrypted-after-timeout", rollbackTarget); err != nil {
		t.Fatalf("replacement upgrade after timeout: %v", err)
	}
}

func TestEnvironmentPlacementUsesLabelsCapacityAndFreshHeartbeat(t *testing.T) {
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
	orgID, projectID, smallID, largeID, staleID := uuid.New(), uuid.New(), uuid.New(), uuid.New(), uuid.New()
	if _, err = db.Pool.Exec(ctx, `INSERT INTO organizations(id,name,slug) VALUES($1,'Placement',$2)`, orgID, "placement-"+orgID.String()); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _ = db.Pool.Exec(context.Background(), `DELETE FROM organizations WHERE id=$1`, orgID) })
	if _, err = db.Pool.Exec(ctx, `INSERT INTO projects(id,organization_id,name,slug) VALUES($1,$2,'Project','project')`, projectID, orgID); err != nil {
		t.Fatal(err)
	}
	for _, cluster := range []struct {
		id       uuid.UUID
		nodes    int
		lastSeen string
	}{
		{smallID, 2, "now()"}, {largeID, 5, "now()"}, {staleID, 20, "now()-interval '10 minutes'"},
	} {
		query := `INSERT INTO clusters(id,organization_id,name,slug,state,labels,capacity,last_seen_at,certificate_not_after) VALUES($1,$2,$3,$4,'active','{"region":"eu"}',jsonb_build_object('nodes',$5::integer,'nanoCpus',$5::bigint*2000000000,'memoryBytes',$5::bigint*4294967296),` + cluster.lastSeen + `,now()+interval '1 day')`
		if _, err = db.Pool.Exec(ctx, query, cluster.id, orgID, cluster.id.String(), "c-"+cluster.id.String(), cluster.nodes); err != nil {
			t.Fatal(err)
		}
	}
	if _, err = db.CreateEnvironmentOnCluster(ctx, orgID, projectID, "Explicit stale", "explicit-stale", &staleID); !errors.Is(err, ErrNoCapacity) {
		t.Fatalf("explicit stale placement error=%v, want ErrNoCapacity", err)
	}
	environment, err := db.CreateEnvironmentWithPlacement(ctx, orgID, projectID, "Production", "production", nil, map[string]string{"region": "eu"}, 3, 8_000_000_000, 16_000_000_000)
	if err != nil {
		t.Fatal(err)
	}
	if environment.ClusterID == nil || *environment.ClusterID != largeID || environment.MinimumNodes != 3 || environment.MinimumNanoCPUs != 8_000_000_000 || environment.PlacementSelector["region"] != "eu" {
		t.Fatalf("unexpected placement: %#v", environment)
	}
	serviceID := uuid.New()
	if _, err = db.Pool.Exec(ctx, `INSERT INTO compose_services(id,environment_id,name,slug,stack_name,compose_yaml) VALUES($1,$2,'Web','web',$3,'services: {}')`, serviceID, environment.ID, "placement-"+serviceID.String()); err != nil {
		t.Fatal(err)
	}
	if _, err = db.Pool.Exec(ctx, `UPDATE clusters SET last_seen_at=now()-interval '10 minutes' WHERE id=$1`, largeID); err != nil {
		t.Fatal(err)
	}
	if _, err = db.QueueDeployment(ctx, orgID, serviceID, uuid.Nil, "manual"); !errors.Is(err, ErrClusterUnavailable) {
		t.Fatalf("deployment during agent partition error=%v, want ErrClusterUnavailable", err)
	}
	if _, err = db.EnqueueClusterCommand(ctx, largeID, uuid.New(), "swarm.deploy", "encrypted"); !errors.Is(err, ErrClusterUnavailable) {
		t.Fatalf("command during agent partition error=%v, want ErrClusterUnavailable", err)
	}
	if _, err = db.Pool.Exec(ctx, `UPDATE clusters SET last_seen_at=now(),capacity=jsonb_set(capacity,'{nodes}','1') WHERE id=$1`, largeID); err != nil {
		t.Fatal(err)
	}
	if _, err = db.QueueDeployment(ctx, orgID, serviceID, uuid.Nil, "manual"); !errors.Is(err, ErrNoCapacity) {
		t.Fatalf("deployment after capacity loss error=%v, want ErrNoCapacity", err)
	}
	if _, err = db.Pool.Exec(ctx, `UPDATE clusters SET capacity=jsonb_set(capacity,'{nodes}','5') WHERE id=$1`, largeID); err != nil {
		t.Fatal(err)
	}
	maintenanceStart, maintenanceEnd := time.Now().Add(-time.Minute), time.Now().Add(time.Hour)
	configured, err := db.UpdateClusterConfiguration(ctx, orgID, largeID, "active", &maintenanceStart, &maintenanceEnd)
	if err != nil || configured.MaintenanceEndsAt == nil {
		t.Fatal(err)
	}
	if _, err = db.QueueDeployment(ctx, orgID, serviceID, uuid.Nil, "manual"); !errors.Is(err, ErrMaintenance) {
		t.Fatalf("deployment during maintenance error=%v", err)
	}
	if _, err = db.EnqueueClusterCommand(ctx, largeID, uuid.New(), "swarm.deploy", "encrypted"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("command during maintenance error=%v", err)
	}
	for _, kind := range []string{"swarm.volume-artifact", "image.resolve", "database.transfer"} {
		if _, err = db.EnqueueClusterCommand(ctx, largeID, uuid.New(), kind, "encrypted"); !errors.Is(err, ErrNotFound) {
			t.Fatalf("%s command during maintenance error=%v", kind, err)
		}
	}
	if _, err = db.UpdateClusterConfiguration(ctx, orgID, largeID, "active", nil, nil); err != nil {
		t.Fatal(err)
	}
	if _, err = db.UpdateClusterState(ctx, orgID, largeID, "draining"); err != nil {
		t.Fatal(err)
	}
	if _, err = db.CreateEnvironmentWithPlacement(ctx, orgID, projectID, "Unavailable", "unavailable", nil, map[string]string{"region": "eu"}, 3, 0, 0); !errors.Is(err, ErrNoCapacity) {
		t.Fatalf("placement error=%v, want ErrNoCapacity", err)
	}
}
