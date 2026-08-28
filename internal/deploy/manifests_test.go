package deploy

import (
	"os"
	"slices"
	"testing"

	"gopkg.in/yaml.v3"
)

type deploymentManifest struct {
	Services map[string]struct {
		Command     []string `yaml:"command"`
		Healthcheck struct {
			Test []string `yaml:"test"`
		} `yaml:"healthcheck"`
		Deploy struct {
			Replicas     int `yaml:"replicas"`
			UpdateConfig struct {
				Order         string `yaml:"order"`
				FailureAction string `yaml:"failure_action"`
			} `yaml:"update_config"`
			RollbackConfig struct {
				Order string `yaml:"order"`
			} `yaml:"rollback_config"`
		} `yaml:"deploy"`
	} `yaml:"services"`
}

func readDeploymentManifest(t *testing.T, path string) deploymentManifest {
	t.Helper()
	contents, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var manifest deploymentManifest
	if err = yaml.Unmarshal(contents, &manifest); err != nil {
		t.Fatal(err)
	}
	return manifest
}

func TestControllerManifestHasHealthGatedRollbackUpdates(t *testing.T) {
	manifest := readDeploymentManifest(t, "../../deploy/swarm.yml")
	for _, name := range []string{"postgres", "dockyard", "traefik"} {
		service, ok := manifest.Services[name]
		if !ok {
			t.Fatalf("missing %s service", name)
		}
		if len(service.Healthcheck.Test) == 0 {
			t.Fatalf("%s has no health check", name)
		}
		if service.Deploy.Replicas != 1 || service.Deploy.UpdateConfig.FailureAction != "rollback" {
			t.Fatalf("%s rollout is not single-replica and rollback-safe: %#v", name, service.Deploy)
		}
		if service.Deploy.RollbackConfig.Order != "stop-first" {
			t.Fatalf("%s rollback order=%q", name, service.Deploy.RollbackConfig.Order)
		}
	}
	if got := manifest.Services["dockyard"].Deploy.UpdateConfig.Order; got != "start-first" {
		t.Fatalf("dockyard update order=%q", got)
	}
	for _, name := range []string{"postgres", "traefik"} {
		if got := manifest.Services[name].Deploy.UpdateConfig.Order; got != "stop-first" {
			t.Fatalf("%s update order=%q", name, got)
		}
	}
	if !slices.Contains(manifest.Services["traefik"].Command, "--ping=true") {
		t.Fatal("Traefik ping endpoint is not enabled")
	}
}

func TestAgentManifestRollsBackFailedStartFirstUpdate(t *testing.T) {
	service := readDeploymentManifest(t, "../../deploy/agent-swarm.yml").Services["agent"]
	if service.Deploy.Replicas != 1 || service.Deploy.UpdateConfig.Order != "start-first" || service.Deploy.UpdateConfig.FailureAction != "rollback" || service.Deploy.RollbackConfig.Order != "stop-first" {
		t.Fatalf("unsafe agent rollout policy: %#v", service.Deploy)
	}
}

func TestDevelopmentComposeChecksControllerReadiness(t *testing.T) {
	service := readDeploymentManifest(t, "../../compose.yml").Services["dockyard"]
	if len(service.Healthcheck.Test) == 0 {
		t.Fatal("development controller has no health check")
	}
}
