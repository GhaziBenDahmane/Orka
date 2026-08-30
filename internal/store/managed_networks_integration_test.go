package store

import (
	"bytes"
	"encoding/json"
	"errors"
	"testing"

	"github.com/google/uuid"
)

func TestManagedNetworkLifecycleAndTenantIsolation(t *testing.T) {
	pool, ctx := migrationTestPool(t)
	if err := Migrate(ctx, pool); err != nil {
		t.Fatal(err)
	}
	db := &Store{Pool: pool}
	organizationID, otherOrganizationID := uuid.New(), uuid.New()
	projectID, environmentID, serviceID := uuid.New(), uuid.New(), uuid.New()
	for _, statement := range []struct {
		query string
		args  []any
	}{
		{`INSERT INTO organizations(id,name,slug) VALUES($1,'Networks',$2),($3,'Other',$4)`, []any{organizationID, "networks-" + organizationID.String(), otherOrganizationID, "networks-" + otherOrganizationID.String()}},
		{`INSERT INTO projects(id,organization_id,name,slug) VALUES($1,$2,'Project','project')`, []any{projectID, organizationID}},
		{`INSERT INTO environments(id,project_id,name,slug) VALUES($1,$2,'Production','production')`, []any{environmentID, projectID}},
		{`INSERT INTO compose_services(id,environment_id,name,slug,stack_name,compose_yaml) VALUES($1,$2,'App','app',$3,'services: {web: {image: nginx}}')`, []any{serviceID, environmentID, "networks-" + serviceID.String()}},
	} {
		if _, err := pool.Exec(ctx, statement.query, statement.args...); err != nil {
			t.Fatal(err)
		}
	}
	mtu := 1450
	item, err := db.CreateManagedNetwork(ctx, ManagedNetwork{OrganizationID: organizationID, Name: "shared_backend", Driver: "overlay", Attachable: true, EnableIPv4: true, MTU: &mtu, IPAM: []NetworkIPAMConfig{{Subnet: "10.42.0.0/24", Gateway: "10.42.0.1"}}})
	if err != nil || item.Status != "provisioning" || item.MTU == nil || *item.MTU != mtu {
		t.Fatalf("created network=%#v err=%v", item, err)
	}
	var createJobs int
	if err = pool.QueryRow(ctx, `SELECT count(*) FROM jobs WHERE kind='network.create' AND payload->>'networkId'=$1`, item.ID.String()).Scan(&createJobs); err != nil || createJobs != 1 {
		t.Fatalf("create jobs=%d err=%v", createJobs, err)
	}
	if _, err = pool.Exec(ctx, `UPDATE jobs SET status='failed',attempts=max_attempts,finished_at=now() WHERE kind='network.create' AND payload->>'networkId'=$1`, item.ID.String()); err != nil {
		t.Fatal(err)
	}
	if _, err = pool.Exec(ctx, `UPDATE managed_networks SET status='error',last_error='DO_NOT_EXPOSE_NETWORK_ERROR_SECRET' WHERE id=$1`, item.ID); err != nil {
		t.Fatal(err)
	}
	snapshot, err := db.BuildAIAuditSnapshot(ctx, organizationID)
	if err != nil || len(snapshot.ManagedNetworks) != 1 || snapshot.ManagedNetworks[0].ID != item.ID || snapshot.ManagedNetworks[0].Status != "error" || snapshot.ManagedNetworks[0].UpdatedAt.IsZero() {
		t.Fatalf("managed network audit posture=%#v err=%v", snapshot.ManagedNetworks, err)
	}
	encodedSnapshot, err := json.Marshal(snapshot)
	if err != nil || bytes.Contains(encodedSnapshot, []byte("DO_NOT_EXPOSE_NETWORK_ERROR_SECRET")) || bytes.Contains(encodedSnapshot, []byte(`"lastError"`)) {
		t.Fatalf("AI snapshot leaked managed-network failure text: error=%v body=%s", err, encodedSnapshot)
	}
	if _, err = db.RetryManagedNetworkProvisioning(ctx, otherOrganizationID, item.ID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("cross-tenant retry error=%v", err)
	}
	retried, err := db.RetryManagedNetworkProvisioning(ctx, organizationID, item.ID)
	if err != nil || retried.Status != "provisioning" || retried.LastError != "" {
		t.Fatalf("retried network=%#v err=%v", retried, err)
	}
	if err = pool.QueryRow(ctx, `SELECT count(*) FROM jobs WHERE kind='network.create' AND payload->>'networkId'=$1`, item.ID.String()).Scan(&createJobs); err != nil || createJobs != 2 {
		t.Fatalf("retried create jobs=%d err=%v", createJobs, err)
	}
	if _, err = db.RetryManagedNetworkProvisioning(ctx, organizationID, item.ID); !errors.Is(err, ErrBusy) {
		t.Fatalf("non-terminal retry error=%v", err)
	}
	if _, err = pool.Exec(ctx, `UPDATE managed_networks SET status='ready',docker_id='docker-network-id' WHERE id=$1`, item.ID); err != nil {
		t.Fatal(err)
	}
	assigned, err := db.ReplaceServiceNetworks(ctx, organizationID, serviceID, []uuid.UUID{item.ID})
	if err != nil || len(assigned) != 1 || assigned[0].DockerID != "docker-network-id" {
		t.Fatalf("assigned=%#v err=%v", assigned, err)
	}
	var revision int64
	if err = pool.QueryRow(ctx, `SELECT revision FROM compose_services WHERE id=$1`, serviceID).Scan(&revision); err != nil || revision != 2 {
		t.Fatalf("service revision=%d err=%v", revision, err)
	}
	foreign, err := db.CreateManagedNetwork(ctx, ManagedNetwork{OrganizationID: otherOrganizationID, Name: "foreign", Driver: "overlay", Attachable: true, EnableIPv4: true})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = pool.Exec(ctx, `UPDATE managed_networks SET status='ready' WHERE id=$1`, foreign.ID); err != nil {
		t.Fatal(err)
	}
	if _, err = db.ReplaceServiceNetworks(ctx, organizationID, serviceID, []uuid.UUID{foreign.ID}); !errors.Is(err, ErrNotFound) {
		t.Fatalf("cross-tenant assignment error=%v", err)
	}
	assigned, err = db.ListServiceNetworks(ctx, organizationID, serviceID)
	if err != nil || len(assigned) != 1 || assigned[0].ID != item.ID {
		t.Fatalf("failed replacement changed assignment=%#v err=%v", assigned, err)
	}
	if err = db.QueueManagedNetworkDeletion(ctx, organizationID, item.ID); !errors.Is(err, ErrBusy) {
		t.Fatalf("assigned network deletion error=%v", err)
	}
	if _, err = db.ReplaceServiceNetworks(ctx, organizationID, serviceID, nil); err != nil {
		t.Fatal(err)
	}
	if err = db.QueueManagedNetworkDeletion(ctx, organizationID, item.ID); err != nil {
		t.Fatal(err)
	}
	deleting, err := db.GetManagedNetwork(ctx, organizationID, item.ID)
	if err != nil || deleting.Status != "deleting" || deleting.DeletionRequestedAt == nil {
		t.Fatalf("deleting network=%#v err=%v", deleting, err)
	}
}
