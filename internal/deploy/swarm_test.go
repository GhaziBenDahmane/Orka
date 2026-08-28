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
