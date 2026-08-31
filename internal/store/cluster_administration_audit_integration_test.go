package store

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"
)

func TestClusterAdministrationCommitsWithAudit(t *testing.T) {
	pool, ctx := migrationTestPool(t)
	if err := Migrate(ctx, pool); err != nil {
		t.Fatal(err)
	}
	db := &Store{Pool: pool}
	organizationID, userID := uuid.New(), uuid.New()
	if _, err := pool.Exec(ctx, `INSERT INTO organizations(id,name,slug) VALUES($1,'Cluster audit',$2)`, organizationID, "cluster-audit-"+organizationID.String()); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO users(id,email,password_hash) VALUES($1,$2,'!test')`, userID, userID.String()+"@example.test"); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `DELETE FROM jobs WHERE kind='delete.cluster' AND payload->>'clusterId' IN (SELECT id::text FROM clusters WHERE organization_id=$1)`, organizationID)
		_, _ = pool.Exec(context.Background(), `DELETE FROM organizations WHERE id=$1`, organizationID)
		_, _ = pool.Exec(context.Background(), `DELETE FROM users WHERE id=$1`, userID)
	})
	principal := Principal{OrganizationID: organizationID, UserID: userID}
	missingServiceAccountID := uuid.New()
	invalidAuditPrincipal := principal
	invalidAuditPrincipal.ServiceAccountID = &missingServiceAccountID

	if _, err := db.CreateClusterWithAudit(ctx, invalidAuditPrincipal, Cluster{Name: "Discarded", Slug: "discarded"}, "127.0.0.1:1234"); err == nil {
		t.Fatal("cluster creation succeeded without valid audit evidence")
	}
	var count int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM clusters WHERE organization_id=$1 AND slug='discarded'`, organizationID).Scan(&count); err != nil || count != 0 {
		t.Fatalf("failed evidence retained cluster: count=%d err=%v", count, err)
	}
	cluster, err := db.CreateClusterWithAudit(ctx, principal, Cluster{Name: "Paris", Slug: "paris", Labels: map[string]any{"region": "eu-west"}}, "127.0.0.1:1234")
	if err != nil {
		t.Fatal(err)
	}

	if _, err = db.UpdateClusterConfigurationWithAudit(ctx, invalidAuditPrincipal, cluster.ID, "draining", nil, nil, "127.0.0.1:1234"); err == nil {
		t.Fatal("cluster state changed without valid audit evidence")
	}
	stored, err := db.GetCluster(ctx, organizationID, cluster.ID)
	if err != nil || stored.State != "pending" {
		t.Fatalf("failed evidence changed cluster state: cluster=%#v err=%v", stored, err)
	}
	if _, err = db.UpdateClusterConfigurationWithAudit(ctx, principal, cluster.ID, "draining", nil, nil, "127.0.0.1:1234"); err != nil {
		t.Fatal(err)
	}

	if err = db.CreateClusterEnrollmentTokenWithAudit(ctx, invalidAuditPrincipal, cluster.ID, []byte("failed-enrollment-token"), time.Now().Add(15*time.Minute), "127.0.0.1:1234"); err == nil {
		t.Fatal("cluster enrollment token created without valid audit evidence")
	}
	if err = pool.QueryRow(ctx, `SELECT count(*) FROM cluster_enrollment_tokens WHERE cluster_id=$1`, cluster.ID).Scan(&count); err != nil || count != 0 {
		t.Fatalf("failed evidence retained enrollment token: count=%d err=%v", count, err)
	}
	if err = db.CreateClusterEnrollmentTokenWithAudit(ctx, principal, cluster.ID, []byte("active-enrollment-token"), time.Now().Add(15*time.Minute), "127.0.0.1:1234"); err != nil {
		t.Fatal(err)
	}

	commandID := uuid.New()
	if _, err = pool.Exec(ctx, `INSERT INTO cluster_commands(id,cluster_id,kind,encrypted_payload) VALUES($1,$2,'swarm.nodes','encrypted')`, commandID, cluster.ID); err != nil {
		t.Fatal(err)
	}
	if err = db.QueueClusterDeletionWithAudit(ctx, invalidAuditPrincipal, cluster.ID, "127.0.0.1:1234"); err == nil {
		t.Fatal("cluster deletion queued without valid audit evidence")
	}
	stored, err = db.GetCluster(ctx, organizationID, cluster.ID)
	if err != nil || stored.State != "draining" {
		t.Fatalf("failed evidence changed cluster deletion state: cluster=%#v err=%v", stored, err)
	}
	var commandStatus string
	if err = pool.QueryRow(ctx, `SELECT status FROM cluster_commands WHERE id=$1`, commandID).Scan(&commandStatus); err != nil || commandStatus != "pending" {
		t.Fatalf("failed evidence cancelled cluster command: status=%q err=%v", commandStatus, err)
	}
	if err = pool.QueryRow(ctx, `SELECT count(*) FROM jobs WHERE kind='delete.cluster' AND payload->>'clusterId'=$1`, cluster.ID.String()).Scan(&count); err != nil || count != 0 {
		t.Fatalf("failed evidence retained cluster deletion job: count=%d err=%v", count, err)
	}
	if err = db.QueueClusterDeletionWithAudit(ctx, principal, cluster.ID, "127.0.0.1:1234"); err != nil {
		t.Fatal(err)
	}
	stored, err = db.GetCluster(ctx, organizationID, cluster.ID)
	if err != nil || stored.State != "disabled" {
		t.Fatalf("audited cluster deletion state=%#v err=%v", stored, err)
	}
	if err = pool.QueryRow(ctx, `SELECT status FROM cluster_commands WHERE id=$1`, commandID).Scan(&commandStatus); err != nil || commandStatus != "cancelled" {
		t.Fatalf("cluster deletion command status=%q err=%v", commandStatus, err)
	}
	if err = pool.QueryRow(ctx, `SELECT count(*) FROM jobs WHERE kind='delete.cluster' AND payload->>'clusterId'=$1 AND status='pending'`, cluster.ID.String()).Scan(&count); err != nil || count != 1 {
		t.Fatalf("cluster deletion job count=%d err=%v", count, err)
	}

	var auditCount int
	if err = pool.QueryRow(ctx, `SELECT count(*) FROM audit_events WHERE organization_id=$1 AND actor_user_id=$2 AND resource_id=$3 AND action IN ('cluster.create','cluster.state.update','cluster.enrollment_token.create','cluster.delete')`, organizationID, userID, cluster.ID.String()).Scan(&auditCount); err != nil || auditCount != 4 {
		t.Fatalf("cluster administration audit count=%d err=%v", auditCount, err)
	}
}
