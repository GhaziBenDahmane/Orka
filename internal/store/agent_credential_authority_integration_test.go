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

func TestAgentMutationsAreFencedByCertificateSupersession(t *testing.T) {
	databaseURL := os.Getenv("DOCKYARD_TEST_DATABASE_URL")
	if databaseURL == "" {
		t.Skip("DOCKYARD_TEST_DATABASE_URL is not set")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	db, err := Open(ctx, databaseURL)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(db.Pool.Close)

	organizationID, clusterID := uuid.New(), uuid.New()
	oldSerial, newSerial := "old-"+uuid.NewString(), "new-"+uuid.NewString()
	claimCommandID, renewCommandID, completeCommandID := uuid.New(), uuid.New(), uuid.New()
	renewLeaseID, completeLeaseID := uuid.New(), uuid.New()
	for _, statement := range []struct {
		query string
		args  []any
	}{
		{`INSERT INTO organizations(id,name,slug) VALUES($1,'Agent authority',$2)`, []any{organizationID, "agent-authority-" + organizationID.String()}},
		{`INSERT INTO clusters(id,organization_id,name,slug,state,certificate_serial,certificate_not_after,last_seen_at) VALUES($1,$2,'Remote','remote','active',$3,now()+interval '1 hour',now())`, []any{clusterID, organizationID, oldSerial}},
		{`INSERT INTO cluster_commands(id,cluster_id,kind,encrypted_payload,status,created_at) VALUES($1,$2,'swarm.nodes','claim','pending',now()-interval '3 seconds')`, []any{claimCommandID, clusterID}},
		{`INSERT INTO cluster_commands(id,cluster_id,kind,encrypted_payload,status,attempts,lease_id,lease_expires_at,created_at) VALUES($1,$2,'swarm.nodes','renew','leased',1,$3,now()+interval '10 minutes',now()-interval '2 seconds')`, []any{renewCommandID, clusterID, renewLeaseID}},
		{`INSERT INTO cluster_commands(id,cluster_id,kind,encrypted_payload,status,attempts,lease_id,lease_expires_at,created_at) VALUES($1,$2,'swarm.nodes','complete','leased',1,$3,now()+interval '10 minutes',now()-interval '1 second')`, []any{completeCommandID, clusterID, completeLeaseID}},
	} {
		if _, err = db.Pool.Exec(ctx, statement.query, statement.args...); err != nil {
			t.Fatal(err)
		}
	}
	t.Cleanup(func() {
		_, _ = db.Pool.Exec(context.Background(), `DELETE FROM organizations WHERE id=$1`, organizationID)
	})
	if err = db.AuthenticateClusterCertificate(ctx, clusterID, oldSerial); err != nil {
		t.Fatal(err)
	}
	var originalRenewExpiry time.Time
	if err = db.Pool.QueryRow(ctx, `SELECT lease_expires_at FROM cluster_commands WHERE id=$1`, renewCommandID).Scan(&originalRenewExpiry); err != nil {
		t.Fatal(err)
	}

	supersession, err := db.Pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer supersession.Rollback(context.Background())
	if _, err = supersession.Exec(ctx, `UPDATE clusters SET certificate_serial=$2 WHERE id=$1`, clusterID, newSerial); err != nil {
		t.Fatal(err)
	}

	results := make(chan error, 4)
	go func() {
		results <- db.RecordAuthenticatedClusterHeartbeat(ctx, clusterID, oldSerial, "stale-agent", "registry.example/agent@sha256:"+strings.Repeat("a", 64), "", "29.0.0", clustercontract.Capacity{Nodes: 1, ReadyNodes: 1, ActiveNodes: 1, SchedulableNodes: 1}, clustercontract.Baseline())
	}()
	go func() {
		_, claimErr := db.ClaimAuthenticatedClusterCommand(ctx, clusterID, oldSerial, time.Minute)
		results <- claimErr
	}()
	go func() {
		results <- db.RenewAuthenticatedClusterCommand(ctx, clusterID, renewCommandID, renewLeaseID, oldSerial, time.Minute)
	}()
	go func() {
		results <- db.CompleteAuthenticatedClusterCommand(ctx, clusterID, completeCommandID, completeLeaseID, oldSerial, "stale-result", false)
	}()

	waitForBlockedAgentCredentialQueries(t, ctx, db, 4)
	if err = supersession.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 4; i++ {
		select {
		case mutationErr := <-results:
			if !errors.Is(mutationErr, ErrAuthenticationStateChanged) {
				t.Fatalf("stale agent mutation error=%v, want authentication state changed", mutationErr)
			}
		case <-ctx.Done():
			t.Fatal(ctx.Err())
		}
	}

	var agentVersion string
	if err = db.Pool.QueryRow(ctx, `SELECT agent_version FROM clusters WHERE id=$1`, clusterID).Scan(&agentVersion); err != nil || agentVersion != "" {
		t.Fatalf("stale heartbeat agent_version=%q err=%v", agentVersion, err)
	}
	var claimStatus string
	var claimAttempts int
	if err = db.Pool.QueryRow(ctx, `SELECT status,attempts FROM cluster_commands WHERE id=$1`, claimCommandID).Scan(&claimStatus, &claimAttempts); err != nil || claimStatus != "pending" || claimAttempts != 0 {
		t.Fatalf("stale claim state=(%q,%d) err=%v", claimStatus, claimAttempts, err)
	}
	var renewed time.Time
	if err = db.Pool.QueryRow(ctx, `SELECT lease_expires_at FROM cluster_commands WHERE id=$1`, renewCommandID).Scan(&renewed); err != nil || !renewed.Equal(originalRenewExpiry) {
		t.Fatalf("stale renewal changed expiry: got=%s want=%s err=%v", renewed, originalRenewExpiry, err)
	}
	var completeStatus, encryptedResult string
	if err = db.Pool.QueryRow(ctx, `SELECT status,encrypted_result FROM cluster_commands WHERE id=$1`, completeCommandID).Scan(&completeStatus, &encryptedResult); err != nil || completeStatus != "leased" || encryptedResult != "" {
		t.Fatalf("stale completion state=(%q,%q) err=%v", completeStatus, encryptedResult, err)
	}
}

func waitForBlockedAgentCredentialQueries(t *testing.T, ctx context.Context, db *Store, want int) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		var blocked int
		err := db.Pool.QueryRow(ctx, `SELECT count(*) FROM pg_stat_activity WHERE datname=current_database() AND pid<>pg_backend_pid() AND wait_event_type='Lock' AND query LIKE '%SELECT id FROM clusters WHERE id=$1 AND state IN (%FOR NO KEY UPDATE%'`).Scan(&blocked)
		if err != nil {
			t.Fatal(err)
		}
		if blocked >= want {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("%d authenticated agent mutations did not block behind certificate supersession", want)
}
