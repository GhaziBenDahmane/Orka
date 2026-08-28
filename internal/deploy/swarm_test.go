package deploy

import (
	"context"
	"encoding/base64"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestDeployForwardsRegistryAuthentication(t *testing.T) {
	directory := t.TempDir()
	docker, logPath := filepath.Join(directory, "docker"), filepath.Join(directory, "calls")
	script := `#!/bin/sh
printf '%s\n' "$*" >> "` + logPath + `"
if [ "$1" = info ]; then echo active; exit 0; fi
if [ "$1" = network ] && [ "$2" = inspect ]; then exit 0; fi
if [ "$1" = stack ] && [ "$2" = deploy ]; then cp "$DOCKER_CONFIG/config.json" "` + directory + `/registry.json"; exit 0; fi
if [ "$1" = service ] && [ "$2" = ls ]; then echo 'test_web 1/1'; exit 0; fi
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
