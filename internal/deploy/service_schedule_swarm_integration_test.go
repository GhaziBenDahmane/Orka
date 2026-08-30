package deploy

import (
	"context"
	"os"
	"strings"
	"testing"
	"time"
)

func TestServiceScheduleRunsAsClonedSwarmJob(t *testing.T) {
	if os.Getenv("DOCKYARD_TEST_SWARM") != "1" {
		t.Skip("DOCKYARD_TEST_SWARM is not set")
	}
	image := os.Getenv("DOCKYARD_TEST_SWARM_PROBE_IMAGE")
	if image == "" {
		image = "node@sha256:e67514e5d0f6c46656005e1b693b2ec9d52e80b641307de684d4a015ba7a4eaf"
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	suffix := strings.ToLower(time.Now().Format("150405"))
	network := "schedule-net-" + suffix
	swarm := Swarm{DockerBin: "docker", Network: network, Timeout: time.Minute}
	stack := "schedule-live-" + suffix
	t.Cleanup(func() {
		cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), time.Minute)
		defer cleanupCancel()
		_, _ = swarm.Remove(cleanupCtx, stack)
		for range 30 {
			if _, err := swarm.run(cleanupCtx, "network", "rm", network); err == nil {
				break
			}
			time.Sleep(100 * time.Millisecond)
		}
	})
	compose := "services:\n  app:\n    image: " + image + "\n    command: [node, -e, 'setInterval(() => {}, 60000)']\n    environment:\n      SCHEDULE_PROBE: inherited\n    deploy:\n      resources:\n        limits:\n          memory: 128M\n"
	if _, err := swarm.Deploy(ctx, stack, compose, nil, nil); err != nil {
		t.Fatal(err)
	}
	output, err := swarm.RunServiceCommand(ctx, stack, "app", "sh", `printf '%s' "$SCHEDULE_PROBE"`)
	if err != nil {
		t.Fatal(err)
	}
	if strings.TrimSpace(output) != "inherited" {
		t.Fatalf("output=%q", output)
	}
}
