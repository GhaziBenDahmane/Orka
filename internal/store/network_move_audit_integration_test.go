package store

import (
	"context"
	"testing"

	"github.com/google/uuid"
)

func TestManagedNetworkMutationsCommitWithAudit(t *testing.T) {
	pool, ctx := migrationTestPool(t)
	if err := Migrate(ctx, pool); err != nil {
		t.Fatal(err)
	}
	db := &Store{Pool: pool}
	organizationID, userID := uuid.New(), uuid.New()
	projectID, environmentID, serviceID := uuid.New(), uuid.New(), uuid.New()
	for _, statement := range []struct {
		query string
		args  []any
	}{
		{`INSERT INTO organizations(id,name,slug) VALUES($1,'Network audit',$2)`, []any{organizationID, "network-audit-" + organizationID.String()}},
		{`INSERT INTO users(id,email,password_hash) VALUES($1,$2,'!test')`, []any{userID, userID.String() + "@example.test"}},
		{`INSERT INTO projects(id,organization_id,name,slug) VALUES($1,$2,'Project','project')`, []any{projectID, organizationID}},
		{`INSERT INTO environments(id,project_id,name,slug) VALUES($1,$2,'Production','production')`, []any{environmentID, projectID}},
		{`INSERT INTO compose_services(id,environment_id,name,slug,stack_name,compose_yaml) VALUES($1,$2,'App','app',$3,'services: {web: {image: nginx}}')`, []any{serviceID, environmentID, "network-audit-" + serviceID.String()}},
	} {
		if _, err := pool.Exec(ctx, statement.query, statement.args...); err != nil {
			t.Fatal(err)
		}
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `DELETE FROM organizations WHERE id=$1`, organizationID)
		_, _ = pool.Exec(context.Background(), `DELETE FROM users WHERE id=$1`, userID)
	})
	principal := Principal{OrganizationID: organizationID, UserID: userID}
	missingServiceAccountID := uuid.New()
	invalidPrincipal := principal
	invalidPrincipal.ServiceAccountID = &missingServiceAccountID

	if _, err := db.CreateManagedNetworkWithAudit(ctx, invalidPrincipal, ManagedNetwork{Name: "discarded", Driver: "overlay", Attachable: true, EnableIPv4: true}, "127.0.0.1:1234"); err == nil {
		t.Fatal("network created without valid audit evidence")
	}
	var count int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM managed_networks WHERE organization_id=$1`, organizationID).Scan(&count); err != nil || count != 0 {
		t.Fatalf("failed evidence retained network: count=%d err=%v", count, err)
	}
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM jobs WHERE kind='network.create' AND payload->>'networkId' IN (SELECT id::text FROM managed_networks WHERE organization_id=$1)`, organizationID).Scan(&count); err != nil || count != 0 {
		t.Fatalf("failed evidence retained network job: count=%d err=%v", count, err)
	}

	network, err := db.CreateManagedNetworkWithAudit(ctx, principal, ManagedNetwork{Name: "backend", Driver: "overlay", Attachable: true, EnableIPv4: true}, "127.0.0.1:1234")
	if err != nil {
		t.Fatal(err)
	}
	if _, err = pool.Exec(ctx, `UPDATE managed_networks SET status='error',last_error='failed' WHERE id=$1`, network.ID); err != nil {
		t.Fatal(err)
	}
	if _, err = pool.Exec(ctx, `UPDATE jobs SET status='failed',attempts=max_attempts,finished_at=now() WHERE kind='network.create' AND payload->>'networkId'=$1`, network.ID.String()); err != nil {
		t.Fatal(err)
	}
	if _, err = db.RetryManagedNetworkProvisioningWithAudit(ctx, invalidPrincipal, network.ID, "127.0.0.1:1234"); err == nil {
		t.Fatal("network retried without valid audit evidence")
	}
	stored, err := db.GetManagedNetwork(ctx, organizationID, network.ID)
	if err != nil || stored.Status != "error" || stored.LastError != "failed" {
		t.Fatalf("failed evidence changed network retry state: network=%#v err=%v", stored, err)
	}
	if _, err = db.RetryManagedNetworkProvisioningWithAudit(ctx, principal, network.ID, "127.0.0.1:1234"); err != nil {
		t.Fatal(err)
	}
	if _, err = pool.Exec(ctx, `UPDATE managed_networks SET status='ready',docker_id='network-id' WHERE id=$1`, network.ID); err != nil {
		t.Fatal(err)
	}
	if _, err = db.ReplaceServiceNetworksWithAudit(ctx, principal, serviceID, []uuid.UUID{network.ID}, "127.0.0.1:1234"); err != nil {
		t.Fatal(err)
	}
	if _, err = db.ReplaceServiceNetworksWithAudit(ctx, invalidPrincipal, serviceID, nil, "127.0.0.1:1234"); err == nil {
		t.Fatal("network assignments replaced without valid audit evidence")
	}
	attachments, err := db.ListServiceNetworks(ctx, organizationID, serviceID)
	if err != nil || len(attachments) != 1 || attachments[0].ID != network.ID {
		t.Fatalf("failed evidence changed network assignments: items=%#v err=%v", attachments, err)
	}
	var revision int64
	if err = pool.QueryRow(ctx, `SELECT revision FROM compose_services WHERE id=$1`, serviceID).Scan(&revision); err != nil || revision != 2 {
		t.Fatalf("failed evidence changed service revision: revision=%d err=%v", revision, err)
	}
	if _, err = db.ReplaceServiceNetworksWithAudit(ctx, principal, serviceID, nil, "127.0.0.1:1234"); err != nil {
		t.Fatal(err)
	}
	if err = db.QueueManagedNetworkDeletionWithAudit(ctx, invalidPrincipal, network.ID, "127.0.0.1:1234"); err == nil {
		t.Fatal("network deletion queued without valid audit evidence")
	}
	stored, err = db.GetManagedNetwork(ctx, organizationID, network.ID)
	if err != nil || stored.Status != "ready" || stored.DeletionRequestedAt != nil {
		t.Fatalf("failed evidence changed deletion state: network=%#v err=%v", stored, err)
	}
	if err = db.QueueManagedNetworkDeletionWithAudit(ctx, principal, network.ID, "127.0.0.1:1234"); err != nil {
		t.Fatal(err)
	}
	if err = pool.QueryRow(ctx, `SELECT count(*) FROM audit_events WHERE organization_id=$1 AND actor_user_id=$2 AND action IN ('network.create.queued','network.create.retried','network.delete.queued','service.networks.replace')`, organizationID, userID).Scan(&count); err != nil || count != 5 {
		t.Fatalf("network audit count=%d err=%v", count, err)
	}
}

func TestMoveComposeServiceCommitsWithAudit(t *testing.T) {
	pool, ctx := migrationTestPool(t)
	if err := Migrate(ctx, pool); err != nil {
		t.Fatal(err)
	}
	db := &Store{Pool: pool}
	organizationID, userID, projectID := uuid.New(), uuid.New(), uuid.New()
	sourceEnvironmentID, targetEnvironmentID, serviceID := uuid.New(), uuid.New(), uuid.New()
	for _, statement := range []struct {
		query string
		args  []any
	}{
		{`INSERT INTO organizations(id,name,slug) VALUES($1,'Move audit',$2)`, []any{organizationID, "move-audit-" + organizationID.String()}},
		{`INSERT INTO users(id,email,password_hash) VALUES($1,$2,'!test')`, []any{userID, userID.String() + "@example.test"}},
		{`INSERT INTO projects(id,organization_id,name,slug) VALUES($1,$2,'Project','project')`, []any{projectID, organizationID}},
		{`INSERT INTO environments(id,project_id,name,slug) VALUES($1,$2,'Source','source'),($3,$2,'Target','target')`, []any{sourceEnvironmentID, projectID, targetEnvironmentID}},
		{`INSERT INTO compose_services(id,environment_id,name,slug,stack_name,compose_yaml) VALUES($1,$2,'App','app',$3,'services: {web: {image: nginx}}')`, []any{serviceID, sourceEnvironmentID, "move-audit-" + serviceID.String()}},
	} {
		if _, err := pool.Exec(ctx, statement.query, statement.args...); err != nil {
			t.Fatal(err)
		}
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `DELETE FROM organizations WHERE id=$1`, organizationID)
		_, _ = pool.Exec(context.Background(), `DELETE FROM users WHERE id=$1`, userID)
	})
	principal := Principal{OrganizationID: organizationID, UserID: userID}
	missingServiceAccountID := uuid.New()
	invalidPrincipal := principal
	invalidPrincipal.ServiceAccountID = &missingServiceAccountID

	if _, err := db.MoveComposeServiceWithAudit(ctx, invalidPrincipal, serviceID, targetEnvironmentID, "127.0.0.1:1234"); err == nil {
		t.Fatal("service moved without valid audit evidence")
	}
	var environmentID uuid.UUID
	if err := pool.QueryRow(ctx, `SELECT environment_id FROM compose_services WHERE id=$1`, serviceID).Scan(&environmentID); err != nil || environmentID != sourceEnvironmentID {
		t.Fatalf("failed evidence moved service to %s err=%v", environmentID, err)
	}
	item, err := db.MoveComposeServiceWithAudit(ctx, principal, serviceID, targetEnvironmentID, "127.0.0.1:1234")
	if err != nil || item.EnvironmentID != targetEnvironmentID {
		t.Fatalf("audited service move=%#v err=%v", item, err)
	}
	var count int
	if err = pool.QueryRow(ctx, `SELECT count(*) FROM audit_events WHERE organization_id=$1 AND actor_user_id=$2 AND action='service.move' AND resource_id=$3`, organizationID, userID, serviceID.String()).Scan(&count); err != nil || count != 1 {
		t.Fatalf("service move audit count=%d err=%v", count, err)
	}
}
