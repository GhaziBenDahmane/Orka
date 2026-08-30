package deploy

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/bendahma/dokploy-go/internal/database"
	"github.com/bendahma/dokploy-go/internal/volumeartifact"
)

func TestRunVolumeArtifactUsesPinnedHelperAndSecretPayload(t *testing.T) {
	directory := t.TempDir()
	docker, calls, secretPayload := filepath.Join(directory, "docker"), filepath.Join(directory, "calls"), filepath.Join(directory, "secret")
	digest := strings.Repeat("a", 64)
	script := `#!/bin/sh
printf '%s\n' "$*" >> "` + calls + `"
if [ "$1" = service ] && [ "$2" = inspect ]; then echo 'registry.example/dockyard@sha256:` + digest + `'; exit 0; fi
if [ "$1" = secret ] && [ "$2" = create ]; then cat > "` + secretPayload + `"; echo secret-id; exit 0; fi
if [ "$1" = service ] && [ "$2" = create ]; then echo service-id; exit 0; fi
if [ "$1" = service ] && [ "$2" = ps ]; then echo 'Complete 1 second ago|'; exit 0; fi
if [ "$1" = service ] && [ "$2" = logs ]; then echo '{"sha256":"` + strings.Repeat("b", 64) + `","plaintextSha256":"` + strings.Repeat("c", 64) + `","sizeBytes":42}'; exit 0; fi
if [ "$1" = service ] && [ "$2" = rm ]; then exit 0; fi
if [ "$1" = secret ] && [ "$2" = rm ]; then exit 0; fi
exit 1
`
	if err := os.WriteFile(docker, []byte(script), 0700); err != nil {
		t.Fatal(err)
	}
	key := base64.RawStdEncoding.EncodeToString(make([]byte, 32))
	result, err := (Swarm{DockerBin: docker, ServiceName: "dockyard_dockyard", Timeout: time.Second}).RunVolumeArtifact(context.Background(), VolumeArtifactJob{Job: volumeartifact.Job{Mode: "backup", TransferURL: "https://objects.example.test/signed?token=secret", EncryptionKey: key, EncryptionAAD: "volume-backup:test"}, VolumeName: "stack_data", NodeID: "nodeabc123", Network: "dockyard-public"})
	if err != nil || result.SizeBytes != 42 {
		t.Fatalf("result=%#v err=%v", result, err)
	}
	arguments, err := os.ReadFile(calls)
	if err != nil {
		t.Fatal(err)
	}
	callText := string(arguments)
	for _, expected := range []string{"node.id==nodeabc123", "type=volume,source=stack_data,target=/volume", "registry.example/dockyard@sha256:" + digest, "volume-artifact"} {
		if !strings.Contains(callText, expected) {
			t.Fatalf("missing %q in calls:\n%s", expected, callText)
		}
	}
	if strings.Contains(callText, "token=secret") || strings.Contains(callText, key) {
		t.Fatalf("secret material leaked into Docker arguments:\n%s", callText)
	}
	payload, err := os.ReadFile(secretPayload)
	if err != nil || !strings.Contains(string(payload), "token=secret") || !strings.Contains(string(payload), key) {
		t.Fatalf("secret payload=%q err=%v", payload, err)
	}
}

func TestValidateVolumeArtifactJobRejectsUnsafePlacement(t *testing.T) {
	base := VolumeArtifactJob{Job: volumeartifact.Job{Mode: "backup", TransferURL: "https://objects.example.test/upload", EncryptionKey: base64.RawStdEncoding.EncodeToString(make([]byte, 32)), EncryptionAAD: "volume-backup:test"}, VolumeName: "stack_data", NodeID: "nodeabc123"}
	for name, mutate := range map[string]func(*VolumeArtifactJob){
		"volume":  func(job *VolumeArtifactJob) { job.VolumeName = "../host" },
		"node":    func(job *VolumeArtifactJob) { job.NodeID = "node;bad" },
		"network": func(job *VolumeArtifactJob) { job.Network = "Bad Network" },
	} {
		t.Run(name, func(t *testing.T) {
			job := base
			mutate(&job)
			if err := ValidateVolumeArtifactJob(job); err == nil {
				t.Fatal("unsafe volume artifact job was accepted")
			}
		})
	}
}

func TestDeployForwardsRegistryAuthentication(t *testing.T) {
	directory := t.TempDir()
	docker, logPath := filepath.Join(directory, "docker"), filepath.Join(directory, "calls")
	script := `#!/bin/sh
printf '%s\n' "$*" >> "` + logPath + `"
if [ "$1" = info ]; then echo active; exit 0; fi
if [ "$1" = network ] && [ "$2" = inspect ]; then echo 'overlay|swarm|true|{"encrypted":""}'; exit 0; fi
if [ "$1" = stack ] && [ "$2" = deploy ]; then cp "$DOCKER_CONFIG/config.json" "` + directory + `/registry.json"; exit 0; fi
if [ "$1" = service ] && [ "$2" = ls ]; then echo 'test_web 1/1'; exit 0; fi
if [ "$1" = service ] && [ "$2" = inspect ]; then echo 'null'; exit 0; fi
exit 1
`
	if err := os.WriteFile(docker, []byte(script), 0700); err != nil {
		t.Fatal(err)
	}
	credential := &Credential{Kind: "registry", Server: "registry.example.test", Username: "robot", Secret: "private-token"}
	_, err := (Swarm{DockerBin: docker, Network: "dockyard-public", Timeout: time.Second}).Deploy(context.Background(), "test", "services:\n  web:\n    image: registry.example.test/app:1\n", nil, credential)
	if err != nil {
		t.Fatal(err)
	}
	calls, _ := os.ReadFile(logPath)
	if !strings.Contains(string(calls), "stack deploy") || !strings.Contains(string(calls), "--with-registry-auth") {
		t.Fatalf("registry auth was not forwarded: %s", calls)
	}
	config, err := os.ReadFile(filepath.Join(directory, "registry.json"))
	if err != nil {
		t.Fatal(err)
	}
	want := base64.StdEncoding.EncodeToString([]byte("robot:private-token"))
	if !strings.Contains(string(config), want) {
		t.Fatal("temporary Docker configuration did not contain the expected encoded credential")
	}
}

func TestDeployRejectsAutomaticRollbackAsSuccess(t *testing.T) {
	directory := t.TempDir()
	docker := filepath.Join(directory, "docker")
	script := `#!/bin/sh
if [ "$1" = info ]; then echo active; exit 0; fi
if [ "$1" = network ] && [ "$2" = inspect ]; then echo 'overlay|swarm|true|{"encrypted":""}'; exit 0; fi
if [ "$1" = stack ] && [ "$2" = deploy ]; then exit 0; fi
if [ "$1" = service ] && [ "$2" = ls ]; then echo 'test_web 1/1'; exit 0; fi
if [ "$1" = service ] && [ "$2" = inspect ]; then echo '{"State":"rollback_completed","Message":"task failed health check"}'; exit 0; fi
exit 1
`
	if err := os.WriteFile(docker, []byte(script), 0700); err != nil {
		t.Fatal(err)
	}
	output, err := (Swarm{DockerBin: docker, Network: "dockyard-public", Timeout: time.Second}).Deploy(context.Background(), "test", "services:\n  web:\n    image: example/web:2\n", nil, nil)
	if err == nil || !strings.Contains(err.Error(), "rollback_completed") {
		t.Fatalf("automatic rollback was not reported as a failed deployment: output=%q err=%v", output, err)
	}
}

func TestEnsureReadyCreatesEncryptedOverlay(t *testing.T) {
	directory := t.TempDir()
	docker, logPath := filepath.Join(directory, "docker"), filepath.Join(directory, "calls")
	script := `#!/bin/sh
printf '%s\n' "$*" >> "` + logPath + `"
if [ "$1" = info ]; then echo active; exit 0; fi
if [ "$1" = network ] && [ "$2" = inspect ]; then exit 1; fi
if [ "$1" = network ] && [ "$2" = create ]; then exit 0; fi
exit 1
`
	if err := os.WriteFile(docker, []byte(script), 0700); err != nil {
		t.Fatal(err)
	}
	if err := (Swarm{DockerBin: docker, Network: "dockyard-public"}).EnsureReady(context.Background()); err != nil {
		t.Fatal(err)
	}
	calls, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(calls), "network create --driver overlay --opt encrypted --attachable dockyard-public") {
		t.Fatalf("encrypted overlay was not created: %s", calls)
	}
}

func TestEnsureReadyRejectsUnsafeExistingNetwork(t *testing.T) {
	for _, properties := range []string{
		`bridge|local|true|{"encrypted":""}`,
		`overlay|swarm|false|{"encrypted":""}`,
		`overlay|swarm|true|{}`,
		`overlay|swarm|true|not-json`,
	} {
		t.Run(properties, func(t *testing.T) {
			directory := t.TempDir()
			docker := filepath.Join(directory, "docker")
			script := "#!/bin/sh\nif [ \"$1\" = info ]; then echo active; exit 0; fi\n" +
				"if [ \"$1\" = network ] && [ \"$2\" = inspect ]; then echo '" + properties + "'; exit 0; fi\n" +
				"exit 1\n"
			if err := os.WriteFile(docker, []byte(script), 0700); err != nil {
				t.Fatal(err)
			}
			if err := (Swarm{DockerBin: docker, Network: "dockyard-public"}).EnsureReady(context.Background()); err == nil {
				t.Fatalf("accepted unsafe network properties %q", properties)
			}
		})
	}
}

func TestResolveStorageNodeDiscoversExistingOrChoosesDeterministically(t *testing.T) {
	directory := t.TempDir()
	docker := filepath.Join(directory, "docker")
	script := `#!/bin/sh
if [ "$1" = service ] && [ "$2" = ls ]; then
  if [ "${STACK_EMPTY:-}" = true ]; then exit 0; fi
  echo 'database_db'
  exit 0
fi
if [ "$1" = service ] && [ "$2" = ps ]; then echo 'worker-b'; exit 0; fi
if [ "$1" = node ] && [ "$2" = ls ]; then
	  printf '%s\n' '{"ID":"nodeb","Hostname":"worker-b","Status":"Ready","Availability":"Active"}' '{"ID":"nodea","Hostname":"worker-a","Status":"Ready","Availability":"Active"}'
  exit 0
fi
if [ "$1" = node ] && [ "$2" = inspect ]; then echo '{"NanoCPUs":1,"MemoryBytes":1}'; exit 0; fi
exit 1
`
	if err := os.WriteFile(docker, []byte(script), 0700); err != nil {
		t.Fatal(err)
	}
	swarm := Swarm{DockerBin: docker}
	if node, err := swarm.ResolveStorageNode(context.Background(), "database"); err != nil || node != "nodeb" {
		t.Fatalf("existing node=%q err=%v", node, err)
	}
	t.Setenv("STACK_EMPTY", "true")
	if node, err := swarm.ResolveStorageNode(context.Background(), "database"); err != nil || node != "nodea" {
		t.Fatalf("selected node=%q err=%v", node, err)
	}
}

func TestResolveStorageNodeRejectsAmbiguousExistingStack(t *testing.T) {
	directory := t.TempDir()
	docker := filepath.Join(directory, "docker")
	script := `#!/bin/sh
if [ "$1" = service ] && [ "$2" = ls ]; then echo 'database_db'; exit 0; fi
if [ "$1" = service ] && [ "$2" = ps ]; then printf '%s\n' worker-a worker-b; exit 0; fi
if [ "$1" = node ] && [ "$2" = ls ]; then
	  printf '%s\n' '{"ID":"nodea","Hostname":"worker-a","Status":"Ready","Availability":"Active"}' '{"ID":"nodeb","Hostname":"worker-b","Status":"Ready","Availability":"Active"}'
  exit 0
fi
if [ "$1" = node ] && [ "$2" = inspect ]; then echo '{"NanoCPUs":1,"MemoryBytes":1}'; exit 0; fi
exit 1
`
	if err := os.WriteFile(docker, []byte(script), 0700); err != nil {
		t.Fatal(err)
	}
	if _, err := (Swarm{DockerBin: docker}).ResolveStorageNode(context.Background(), "database"); err == nil || !strings.Contains(err.Error(), "exactly one") {
		t.Fatalf("ambiguous stack error=%v", err)
	}
}

func TestStatusReportsMissingHealthyAndDegradedStacks(t *testing.T) {
	directory := t.TempDir()
	docker := filepath.Join(directory, "docker")
	script := `#!/bin/sh
case "$*" in
  *namespace=missing*) exit 0 ;;
  *namespace=healthy*) printf 'healthy_web 2/2\nhealthy_worker 0/0\nhealthy_migrate 0/1 (1/1 completed)\n'; exit 0 ;;
  *namespace=degraded*) printf 'degraded_web 1/2\ndegraded_worker 1/1\n'; exit 0 ;;
esac
exit 1
`
	if err := os.WriteFile(docker, []byte(script), 0700); err != nil {
		t.Fatal(err)
	}
	swarm := Swarm{DockerBin: docker}
	missing, err := swarm.Status(context.Background(), "missing")
	if err != nil || missing.Exists {
		t.Fatalf("missing=%#v err=%v", missing, err)
	}
	healthy, err := swarm.Status(context.Background(), "healthy")
	if err != nil || !healthy.Exists || healthy.Services != 3 || healthy.HealthyServices != 3 || healthy.RunningTasks != 2 || healthy.DesiredTasks != 3 {
		t.Fatalf("healthy=%#v err=%v", healthy, err)
	}
	degraded, err := swarm.Status(context.Background(), "degraded")
	if err != nil || degraded.HealthyServices != 1 || degraded.RunningTasks != 2 || degraded.DesiredTasks != 3 || len(degraded.Degraded) != 1 || degraded.Degraded[0] != "degraded_web" {
		t.Fatalf("degraded=%#v err=%v", degraded, err)
	}
}

func TestRunContainerJobOverridesImageEntrypoint(t *testing.T) {
	directory := t.TempDir()
	docker := filepath.Join(directory, "docker")
	if err := os.WriteFile(docker, []byte("#!/bin/sh\nprintf '%s\\n' \"$@\"\n"), 0700); err != nil {
		t.Fatal(err)
	}
	output, err := (Swarm{DockerBin: docker}).RunContainerJob(context.Background(), "test-network", "postgres:17", directory, map[string]string{"PGPASSWORD": "secret"}, []string{"pg_dump", "--host", "database"})
	if err != nil {
		t.Fatal(err)
	}
	entrypointAt := strings.Index(output, "--entrypoint\npg_dump\n")
	imageAt := strings.Index(output, "postgres:17\n")
	commandAt := strings.Index(output, "--host\ndatabase\n")
	if entrypointAt < 0 || imageAt < entrypointAt || commandAt < imageAt {
		t.Fatalf("unexpected docker arguments:\n%s", output)
	}
	if strings.Contains(output, "secret") {
		t.Fatal("environment secret leaked into command arguments")
	}
}

func TestRunDatabaseTransferBacksUpChecksumsAndRestores(t *testing.T) {
	directory := t.TempDir()
	docker := filepath.Join(directory, "docker")
	restoreMarker := filepath.Join(directory, "restored")
	script := `#!/bin/sh
mount=""
entrypoint=""
while [ "$#" -gt 0 ]; do
  case "$1" in
    --volume) mount=${2%:/backup}; shift 2 ;;
    --entrypoint) entrypoint=$2; shift 2 ;;
    *) shift ;;
  esac
done
case "$entrypoint" in
  pg_dump) printf 'consistent native dump' > "$mount/transfer.dump"; printf 'backup complete' ;;
  pg_restore) test "$(cat "$mount/transfer.dump")" = 'consistent native dump' || exit 9; touch "` + restoreMarker + `"; printf 'restore complete' ;;
  *) exit 8 ;;
esac
`
	if err := os.WriteFile(docker, []byte(script), 0700); err != nil {
		t.Fatal(err)
	}
	job := DatabaseTransferJob{
		Network:      "database-stack_default",
		ArtifactName: "transfer.dump",
		Backup:       database.BackupPlan{Image: "postgres:17", Command: []string{"pg_dump", "--file", "/backup/transfer.dump"}, Environment: map[string]string{"PGPASSWORD": "source-secret"}},
		Restore:      database.RestorePlan{Image: "postgres:17", Command: []string{"pg_restore", "/backup/transfer.dump"}, Environment: map[string]string{"PGPASSWORD": "target-secret"}},
	}
	result, err := (Swarm{DockerBin: docker}).RunDatabaseTransfer(context.Background(), job)
	if err != nil {
		t.Fatal(err)
	}
	wantHash := fmt.Sprintf("%x", sha256.Sum256([]byte("consistent native dump")))
	if result.SHA256 != wantHash || result.SizeBytes != int64(len("consistent native dump")) || !strings.Contains(result.Output, "backup complete") || !strings.Contains(result.Output, "restore complete") {
		t.Fatalf("unexpected transfer result: %#v", result)
	}
	if _, err := os.Stat(restoreMarker); err != nil {
		t.Fatal("restore was not invoked")
	}
}

func TestRemoveVolumesOnlyUsesStackLabelResults(t *testing.T) {
	directory := t.TempDir()
	docker := filepath.Join(directory, "docker")
	script := `#!/bin/sh
if [ "$1" = "volume" ] && [ "$2" = "ls" ]; then
  printf 'my-stack_data\nmy-stack_cache\n'
  exit 0
fi
printf '%s\n' "$@"
`
	if err := os.WriteFile(docker, []byte(script), 0700); err != nil {
		t.Fatal(err)
	}
	output, err := (Swarm{DockerBin: docker}).RemoveVolumes(context.Background(), "my-stack")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(output, "rm\nmy-stack_data") || !strings.Contains(output, "rm\nmy-stack_cache") {
		t.Fatalf("unexpected removal commands:\n%s", output)
	}
}

func TestRemoveVolumesRejectsUnexpectedLabelResult(t *testing.T) {
	directory := t.TempDir()
	docker := filepath.Join(directory, "docker")
	if err := os.WriteFile(docker, []byte("#!/bin/sh\nprintf 'other_data\\n'\n"), 0700); err != nil {
		t.Fatal(err)
	}
	if _, err := (Swarm{DockerBin: docker}).RemoveVolumes(context.Background(), "my-stack"); err == nil {
		t.Fatal("volume outside the stack namespace was accepted")
	}
}

func TestConvergenceStatusTracksSwarmRolloutState(t *testing.T) {
	for _, tc := range []struct {
		name       string
		replicas   string
		status     string
		wantDone   bool
		wantErr    string
		wantOutput string
	}{
		{name: "initial deployment", replicas: "1/1", status: "null", wantDone: true},
		{name: "completed update", replicas: "2/2", status: `{"State":"completed","Message":"update completed"}`, wantDone: true, wantOutput: "update=completed"},
		{name: "update still running despite old replicas", replicas: "1/1", status: `{"State":"updating","Message":"update in progress"}`, wantOutput: "update=updating"},
		{name: "automatic rollback still running", replicas: "1/1", status: `{"State":"rollback_started","Message":"rolling back"}`, wantOutput: "update=rollback_started"},
		{name: "replicas pending", replicas: "0/1", status: "null"},
		{name: "paused update", replicas: "1/1", status: `{"State":"paused","Message":"task failed"}`, wantErr: "entered paused"},
		{name: "automatic rollback", replicas: "1/1", status: `{"State":"rollback_completed","Message":"rolled back"}`, wantErr: "entered rollback_completed"},
		{name: "unknown state", replicas: "1/1", status: `{"State":"future_state"}`, wantErr: "unknown update state"},
		{name: "malformed status", replicas: "1/1", status: `{`, wantErr: "decode update status"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			directory := t.TempDir()
			docker := filepath.Join(directory, "docker")
			script := "#!/bin/sh\n" +
				"if [ \"$1\" = service ] && [ \"$2\" = ls ]; then printf '%s\\n' 'test_web " + tc.replicas + "'; exit 0; fi\n" +
				"if [ \"$1\" = service ] && [ \"$2\" = inspect ]; then printf '%s\\n' '" + tc.status + "'; exit 0; fi\n" +
				"exit 1\n"
			if err := os.WriteFile(docker, []byte(script), 0700); err != nil {
				t.Fatal(err)
			}
			done, output, err := (Swarm{DockerBin: docker}).convergenceStatus(context.Background(), "test", time.Time{})
			if done != tc.wantDone {
				t.Fatalf("done=%v, want %v; output=%q err=%v", done, tc.wantDone, output, err)
			}
			if tc.wantErr == "" && err != nil {
				t.Fatal(err)
			}
			if tc.wantErr != "" && (err == nil || !strings.Contains(err.Error(), tc.wantErr)) {
				t.Fatalf("err=%v, want containing %q", err, tc.wantErr)
			}
			if tc.wantOutput != "" && !strings.Contains(output, tc.wantOutput) {
				t.Fatalf("output=%q, want containing %q", output, tc.wantOutput)
			}
		})
	}
}

func TestConvergenceStatusIgnoresStaleRollbackMetadata(t *testing.T) {
	directory := t.TempDir()
	docker := filepath.Join(directory, "docker")
	script := `#!/bin/sh
if [ "$1" = service ] && [ "$2" = ls ]; then printf '%s\n' 'test_web 1/1'; exit 0; fi
if [ "$1" = service ] && [ "$2" = inspect ]; then printf '%s\n' '{"State":"rollback_completed","Message":"old rollback","StartedAt":"2026-08-01T00:00:00Z"}'; exit 0; fi
exit 1
`
	if err := os.WriteFile(docker, []byte(script), 0700); err != nil {
		t.Fatal(err)
	}
	done, _, err := (Swarm{DockerBin: docker}).convergenceStatus(context.Background(), "test", time.Date(2026, 8, 2, 0, 0, 0, 0, time.UTC))
	if err != nil || !done {
		t.Fatalf("stale rollback blocked no-op reconciliation: done=%v err=%v", done, err)
	}
}
