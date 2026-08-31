package store

import (
	"context"
	"testing"

	"github.com/google/uuid"
)

func TestAgentUpgradeLifecycleCommitsWithAudit(t *testing.T) {
	pool, ctx := migrationTestPool(t)
	if err := Migrate(ctx, pool); err != nil {
		t.Fatal(err)
	}
	db := &Store{Pool: pool}
	organizationID, userID, clusterID := uuid.New(), uuid.New(), uuid.New()
	if _, err := pool.Exec(ctx, `INSERT INTO organizations(id,name,slug) VALUES($1,'Agent upgrade audit',$2)`, organizationID, "agent-upgrade-audit-"+organizationID.String()); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO users(id,email,password_hash) VALUES($1,$2,'!test')`, userID, userID.String()+"@example.test"); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO clusters(id,organization_id,name,slug,state,last_seen_at) VALUES($1,$2,'Paris','paris','active',now())`, clusterID, organizationID); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `DELETE FROM organizations WHERE id=$1`, organizationID)
		_, _ = pool.Exec(context.Background(), `DELETE FROM users WHERE id=$1`, userID)
	})
	principal := Principal{OrganizationID: organizationID, UserID: userID}
	missingServiceAccountID := uuid.New()
	invalidAuditPrincipal := principal
	invalidAuditPrincipal.ServiceAccountID = &missingServiceAccountID
	targetImage := "registry.example.test/dockyard-agent@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	failedCommandID := uuid.New()

	if _, err := db.EnqueueAgentUpgradeWithAudit(ctx, invalidAuditPrincipal, clusterID, failedCommandID, "failed-encrypted-payload", targetImage, "127.0.0.1:1234"); err == nil {
		t.Fatal("agent upgrade queued without valid audit evidence")
	}
	var count int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM cluster_commands WHERE id=$1`, failedCommandID).Scan(&count); err != nil || count != 0 {
		t.Fatalf("failed evidence retained agent upgrade: count=%d err=%v", count, err)
	}

	commandID := uuid.New()
	command, err := db.EnqueueAgentUpgradeWithAudit(ctx, principal, clusterID, commandID, "encrypted-payload", targetImage, "127.0.0.1:1234")
	if err != nil || command.ID != commandID || command.Status != "pending" {
		t.Fatalf("audited agent upgrade=%#v err=%v", command, err)
	}
	if err = db.CancelPendingAgentUpgradeWithAudit(ctx, invalidAuditPrincipal, clusterID, commandID, "127.0.0.1:1234"); err == nil {
		t.Fatal("agent upgrade cancelled without valid audit evidence")
	}
	stored, err := db.GetClusterCommand(ctx, clusterID, commandID)
	if err != nil || stored.Status != "pending" {
		t.Fatalf("failed evidence changed agent upgrade: command=%#v err=%v", stored, err)
	}
	if err = db.CancelPendingAgentUpgradeWithAudit(ctx, principal, clusterID, commandID, "127.0.0.1:1234"); err != nil {
		t.Fatal(err)
	}
	stored, err = db.GetClusterCommand(ctx, clusterID, commandID)
	if err != nil || stored.Status != "cancelled" {
		t.Fatalf("audited agent upgrade cancellation=%#v err=%v", stored, err)
	}

	var queueAudits, cancelAudits int
	if err = pool.QueryRow(ctx, `SELECT count(*) FROM audit_events WHERE organization_id=$1 AND actor_user_id=$2 AND action='cluster.agent.upgrade' AND resource_id=$3`, organizationID, userID, clusterID.String()).Scan(&queueAudits); err != nil || queueAudits != 1 {
		t.Fatalf("agent upgrade queue audit count=%d err=%v", queueAudits, err)
	}
	if err = pool.QueryRow(ctx, `SELECT count(*) FROM audit_events WHERE organization_id=$1 AND actor_user_id=$2 AND action='cluster.agent.upgrade.cancel' AND resource_id=$3`, organizationID, userID, commandID.String()).Scan(&cancelAudits); err != nil || cancelAudits != 1 {
		t.Fatalf("agent upgrade cancellation audit count=%d err=%v", cancelAudits, err)
	}
}
