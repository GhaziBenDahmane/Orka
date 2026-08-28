package deploy

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

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
