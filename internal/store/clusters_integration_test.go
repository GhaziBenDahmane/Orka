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
	t.Cleanup(func() { _, _ = db.Pool.Exec(context.Background(), `DELETE FROM organizations WHERE id=$1`, orgID) })
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
	if err = db.ConsumeClusterEnrollmentToken(ctx, tokenHash, "other", time.Now().Add(time.Hour)); !errors.Is(err, ErrNotFound) {
		t.Fatalf("replay error = %v", err)
	}
	items, err := db.ListClusters(ctx, orgID)
	if err != nil || len(items) != 1 || items[0].State != "active" || items[0].CertificateNotAfter == nil || items[0].LastSeenAt == nil || items[0].AgentVersion != "1.2.3" {
		t.Fatalf("clusters=%#v err=%v", items, err)
	}
}
