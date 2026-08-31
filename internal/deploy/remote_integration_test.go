package deploy

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/bendahma/dokploy-go/internal/cryptox"
	"github.com/bendahma/dokploy-go/internal/database"
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
	orgID, clusterID, jobID, jobLeaseID := uuid.New(), uuid.New(), uuid.New(), uuid.New()
	if _, err = db.Pool.Exec(ctx, `INSERT INTO organizations(id,name,slug) VALUES($1,'Remote',$2)`, orgID, "remote-"+orgID.String()); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = db.Pool.Exec(context.Background(), `DELETE FROM organizations WHERE id=$1`, orgID)
		_, _ = db.Pool.Exec(context.Background(), `DELETE FROM jobs WHERE id=$1`, jobID)
	})
	if _, err = db.Pool.Exec(ctx, `INSERT INTO clusters(id,organization_id,name,slug,state,last_seen_at) VALUES($1,$2,'Remote','remote','active',now())`, clusterID, orgID); err != nil {
		t.Fatal(err)
	}
	if _, err = db.Pool.Exec(ctx, `INSERT INTO jobs(id,kind,payload,status,locked_at,locked_by,lease_id) VALUES($1,'test.remote','{}','running',now(),'worker-a',$2)`, jobID, jobLeaseID); err != nil {
		t.Fatal(err)
	}
	remote := RemoteSwarm{Store: db, Box: box, ClusterID: clusterID, Timeout: 5 * time.Second}
	ownedContext := withRemoteCommandOwner(ctx, jobID, jobLeaseID)
	type result struct {
		output DeploymentResult
		err    error
	}
	resultChannel := make(chan result, 1)
	go func() {
		output, runErr := remote.Deploy(ownedContext, "test-stack", "services: {}", map[string]string{"SECRET": "value"}, &Credential{Kind: "registry", Server: "registry.example.test", Username: "robot", Secret: "registry-secret"})
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
	if strings.Contains(command.EncryptedPayload, "registry-secret") {
		t.Fatal("cluster command persisted a plaintext registry credential")
	}
	var commandJobID, commandJobLeaseID uuid.UUID
	if err = db.Pool.QueryRow(ctx, `SELECT owner_job_id,owner_job_lease_id FROM cluster_commands WHERE id=$1`, command.ID).Scan(&commandJobID, &commandJobLeaseID); err != nil || commandJobID != jobID || commandJobLeaseID != jobLeaseID {
		t.Fatalf("remote command owner job=%s lease=%s err=%v", commandJobID, commandJobLeaseID, err)
	}
	plain, err := box.Decrypt(command.EncryptedPayload, "cluster-command:"+command.ID.String())
	if err != nil {
		t.Fatal(err)
	}
	var payload map[string]any
	if err = json.Unmarshal(plain, &payload); err != nil {
		t.Fatalf("payload=%s err=%v", plain, err)
	}
	credential, _ := payload["registryCredential"].(map[string]any)
	if payload["stackName"] != "test-stack" || credential["secret"] != "registry-secret" {
		t.Fatalf("payload=%s err=%v", plain, err)
	}
	remoteDeployment, _ := json.Marshal(DeploymentResult{Output: "deployed", ResolvedImages: map[string]string{}})
	resultPayload, _ := json.Marshal(map[string]string{"output": string(remoteDeployment)})
	encryptedResult, err := box.Encrypt(resultPayload, "cluster-command-result:"+command.ID.String())
	if err != nil {
		t.Fatal(err)
	}
	if err = db.CompleteClusterCommand(ctx, clusterID, command.ID, *command.LeaseID, encryptedResult, false); err != nil {
		t.Fatal(err)
	}
	resultValue := <-resultChannel
	if resultValue.err != nil || resultValue.output.Output != "deployed" || resultValue.output.ResolvedImages == nil {
		t.Fatalf("output=%#v err=%v", resultValue.output, resultValue.err)
	}

	transferChannel := make(chan struct {
		result DatabaseTransferResult
		err    error
	}, 1)
	go func() {
		transferResult, transferErr := remote.RunDatabaseTransfer(ownedContext, DatabaseTransferJob{Network: "db_default", ArtifactName: "transfer.dump", Backup: database.BackupPlan{Image: "postgres@sha256:" + strings.Repeat("a", 64), Command: []string{"pg_dump"}}, Restore: database.RestorePlan{Image: "postgres@sha256:" + strings.Repeat("a", 64), Command: []string{"pg_restore"}}})
		transferChannel <- struct {
			result DatabaseTransferResult
			err    error
		}{transferResult, transferErr}
	}()
	deadline = time.Now().Add(3 * time.Second)
	for {
		command, err = db.ClaimClusterCommand(ctx, clusterID, time.Minute)
		if err == nil || !errors.Is(err, store.ErrNotFound) || time.Now().After(deadline) {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if err != nil || command.Kind != "database.transfer" {
		t.Fatalf("database transfer command=%#v err=%v", command, err)
	}
	plain, err = box.Decrypt(command.EncryptedPayload, "cluster-command:"+command.ID.String())
	if err != nil || !strings.Contains(string(plain), `"artifactName":"transfer.dump"`) {
		t.Fatalf("database transfer payload=%s err=%v", plain, err)
	}
	encodedTransfer, _ := json.Marshal(DatabaseTransferResult{Output: "restored", SHA256: strings.Repeat("a", 64), SizeBytes: 42})
	resultPayload, _ = json.Marshal(map[string]string{"output": string(encodedTransfer)})
	encryptedResult, err = box.Encrypt(resultPayload, "cluster-command-result:"+command.ID.String())
	if err != nil {
		t.Fatal(err)
	}
	if err = db.CompleteClusterCommand(ctx, clusterID, command.ID, *command.LeaseID, encryptedResult, false); err != nil {
		t.Fatal(err)
	}
	transferValue := <-transferChannel
	if transferValue.err != nil || transferValue.result.SizeBytes != 42 || transferValue.result.SHA256 != strings.Repeat("a", 64) {
		t.Fatalf("remote transfer=%#v err=%v", transferValue.result, transferValue.err)
	}
}
