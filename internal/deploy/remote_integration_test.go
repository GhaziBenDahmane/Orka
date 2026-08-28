package deploy

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"testing"
	"time"

	"github.com/bendahma/dokploy-go/internal/cryptox"
	"github.com/bendahma/dokploy-go/internal/store"
	"github.com/google/uuid"
)

func TestRemoteSwarmQueuesEncryptedCommandAndWaitsForFencedResult(t *testing.T) {
	databaseURL := os.Getenv("DOCKYARD_TEST_DATABASE_URL")
	if databaseURL == "" {
		t.Skip("DOCKYARD_TEST_DATABASE_URL is not set")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	db, err := store.Open(ctx, databaseURL)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(db.Pool.Close)
	box, err := cryptox.New(make([]byte, 32))
	if err != nil {
		t.Fatal(err)
	}
	orgID, clusterID := uuid.New(), uuid.New()
	if _, err = db.Pool.Exec(ctx, `INSERT INTO organizations(id,name,slug) VALUES($1,'Remote',$2)`, orgID, "remote-"+orgID.String()); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _ = db.Pool.Exec(context.Background(), `DELETE FROM organizations WHERE id=$1`, orgID) })
	if _, err = db.Pool.Exec(ctx, `INSERT INTO clusters(id,organization_id,name,slug,state) VALUES($1,$2,'Remote','remote','active')`, clusterID, orgID); err != nil {
		t.Fatal(err)
	}
	remote := RemoteSwarm{Store: db, Box: box, ClusterID: clusterID, Timeout: 5 * time.Second}
	type result struct {
		output string
		err    error
	}
	resultChannel := make(chan result, 1)
	go func() {
		output, runErr := remote.Deploy(ctx, "test-stack", "services: {}", map[string]string{"SECRET": "value"})
		resultChannel <- result{output, runErr}
	}()
	var command store.ClusterCommand
	deadline := time.Now().Add(3 * time.Second)
	for {
		command, err = db.ClaimClusterCommand(ctx, clusterID, time.Minute)
		if err == nil || !errors.Is(err, store.ErrNotFound) || time.Now().After(deadline) {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if err != nil {
		t.Fatal(err)
	}
	plain, err := box.Decrypt(command.EncryptedPayload, "cluster-command:"+command.ID.String())
	if err != nil {
		t.Fatal(err)
	}
	var payload map[string]any
	if err = json.Unmarshal(plain, &payload); err != nil || payload["stackName"] != "test-stack" {
		t.Fatalf("payload=%s err=%v", plain, err)
	}
	resultPayload, _ := json.Marshal(map[string]string{"output": "deployed"})
	encryptedResult, err := box.Encrypt(resultPayload, "cluster-command-result:"+command.ID.String())
	if err != nil {
		t.Fatal(err)
	}
	if err = db.CompleteClusterCommand(ctx, clusterID, command.ID, *command.LeaseID, encryptedResult, false); err != nil {
		t.Fatal(err)
	}
	resultValue := <-resultChannel
	if resultValue.err != nil || resultValue.output != "deployed" {
		t.Fatalf("output=%q err=%v", resultValue.output, resultValue.err)
	}
}
