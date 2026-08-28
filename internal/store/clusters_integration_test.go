package store

import (
	"context"
	"errors"
	"os"
	"testing"
	"time"

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
	if err = db.CreateClusterEnrollmentToken(ctx, orgID, cluster.ID, uuid.Nil, tokenHash, time.Now().Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	lookedUp, err := db.LookupClusterEnrollmentToken(ctx, tokenHash)
	if err != nil || lookedUp.ID != cluster.ID {
		t.Fatalf("cluster=%#v err=%v", lookedUp, err)
	}
	if err = db.ConsumeClusterEnrollmentToken(ctx, tokenHash, "012345", time.Now().Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	if err = db.AuthenticateClusterCertificate(ctx, cluster.ID, "012345"); err != nil {
		t.Fatalf("authenticate current certificate: %v", err)
	}
	if err = db.AuthenticateClusterCertificate(ctx, cluster.ID, "superseded"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("superseded certificate error = %v", err)
	}
	if err = db.RotateClusterCertificate(ctx, cluster.ID, "012345", "6789ab", time.Now().Add(2*time.Hour)); err != nil {
		t.Fatal(err)
	}
	if err = db.AuthenticateClusterCertificate(ctx, cluster.ID, "012345"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("old certificate after rotation error = %v", err)
	}
	if err = db.AuthenticateClusterCertificate(ctx, cluster.ID, "6789ab"); err != nil {
		t.Fatalf("authenticate rotated certificate: %v", err)
	}
	if err = db.RecordClusterHeartbeat(ctx, cluster.ID, "1.2.3", "28.0.1", map[string]any{"nodes": 3}); err != nil {
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
	if _, err = db.UpdateClusterState(ctx, orgID, cluster.ID, "draining"); err != nil {
		t.Fatal(err)
	}
	if _, err = db.EnqueueClusterCommand(ctx, cluster.ID, uuid.New(), "swarm.nodes", "encrypted"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("enqueue on draining cluster error = %v", err)
	}
	if _, err = db.UpdateClusterState(ctx, orgID, cluster.ID, "active"); err != nil {
		t.Fatal(err)
	}
	if err = db.ConsumeClusterEnrollmentToken(ctx, tokenHash, "other", time.Now().Add(time.Hour)); !errors.Is(err, ErrNotFound) {
		t.Fatalf("replay error = %v", err)
	}
	items, err := db.ListClusters(ctx, orgID)
	if err != nil || len(items) != 1 || items[0].State != "active" || items[0].CertificateNotAfter == nil || items[0].LastSeenAt == nil || items[0].AgentVersion != "1.2.3" {
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
		query := `INSERT INTO clusters(id,organization_id,name,slug,state,labels,capacity,last_seen_at,certificate_not_after) VALUES($1,$2,$3,$4,'active','{"region":"eu"}',jsonb_build_object('nodes',$5::integer),` + cluster.lastSeen + `,now()+interval '1 day')`
		if _, err = db.Pool.Exec(ctx, query, cluster.id, orgID, cluster.id.String(), "c-"+cluster.id.String(), cluster.nodes); err != nil {
			t.Fatal(err)
		}
	}
	environment, err := db.CreateEnvironmentWithPlacement(ctx, orgID, projectID, "Production", "production", nil, map[string]string{"region": "eu"}, 3)
	if err != nil {
		t.Fatal(err)
	}
	if environment.ClusterID == nil || *environment.ClusterID != largeID || environment.MinimumNodes != 3 || environment.PlacementSelector["region"] != "eu" {
		t.Fatalf("unexpected placement: %#v", environment)
	}
	serviceID := uuid.New()
	if _, err = db.Pool.Exec(ctx, `INSERT INTO compose_services(id,environment_id,name,slug,stack_name,compose_yaml) VALUES($1,$2,'Web','web',$3,'services: {}')`, serviceID, environment.ID, "placement-"+serviceID.String()); err != nil {
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
	if _, err = db.EnqueueClusterCommand(ctx, largeID, uuid.New(), "swarm.nodes", "encrypted"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("command during maintenance error=%v", err)
	}
	if _, err = db.UpdateClusterConfiguration(ctx, orgID, largeID, "active", nil, nil); err != nil {
		t.Fatal(err)
	}
	if _, err = db.UpdateClusterState(ctx, orgID, largeID, "draining"); err != nil {
		t.Fatal(err)
	}
	if _, err = db.CreateEnvironmentWithPlacement(ctx, orgID, projectID, "Unavailable", "unavailable", nil, map[string]string{"region": "eu"}, 3); !errors.Is(err, ErrNoCapacity) {
		t.Fatalf("placement error=%v, want ErrNoCapacity", err)
	}
}
