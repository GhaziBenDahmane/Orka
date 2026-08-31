package deploy

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/bendahma/dokploy-go/internal/clustercontract"
)

func TestNodesIncludesResourceCapacity(t *testing.T) {
	docker := filepath.Join(t.TempDir(), "docker")
	script := `#!/bin/sh
if [ "$1" = node ] && [ "$2" = ls ]; then
  echo '{"ID":"node-1","Hostname":"worker-1","Status":"Ready","Availability":"Active","ManagerStatus":"Leader","EngineVersion":"29.3.0"}'
  exit 0
fi
if [ "$1" = node ] && [ "$2" = inspect ] && [ "$3" = node-1 ]; then
  echo '{"NanoCPUs":8000000000,"MemoryBytes":17179869184}'
  exit 0
fi
exit 1
`
	if err := os.WriteFile(docker, []byte(script), 0700); err != nil {
		t.Fatal(err)
	}
	nodes, err := (Swarm{DockerBin: docker}).Nodes(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(nodes) != 1 || nodes[0].NanoCPUs != 8_000_000_000 || nodes[0].MemoryBytes != 17_179_869_184 {
		t.Fatalf("unexpected nodes: %#v", nodes)
	}
}

func TestLocalClusterPostureAggregatesOnlySecretFreeState(t *testing.T) {
	docker := filepath.Join(t.TempDir(), "docker")
	script := `#!/bin/sh
if [ "$1" = node ] && [ "$2" = ls ]; then
  echo '{"ID":"secret-node-1","Hostname":"secret-host-1","Status":"Ready","Availability":"Active","ManagerStatus":"Leader","EngineVersion":"29.3.0"}'
  echo '{"ID":"secret-node-2","Hostname":"secret-host-2","Status":"Down","Availability":"Drain","ManagerStatus":"","EngineVersion":"29.3.0"}'
  exit 0
fi
if [ "$1" = node ] && [ "$2" = inspect ] && [ "$3" = secret-node-1 ]; then
  echo '{"NanoCPUs":8000000000,"MemoryBytes":17179869184}'
  exit 0
fi
if [ "$1" = node ] && [ "$2" = inspect ] && [ "$3" = secret-node-2 ]; then
  echo '{"NanoCPUs":4000000000,"MemoryBytes":8589934592}'
  exit 0
fi
exit 1
`
	if err := os.WriteFile(docker, []byte(script), 0700); err != nil {
		t.Fatal(err)
	}
	posture := (Swarm{DockerBin: docker}).LocalClusterPosture(context.Background())
	if posture.InspectionStatus != clustercontract.LocalInspectionReady || posture.Nodes != 2 || posture.ReadyNodes != 1 || posture.ActiveNodes != 1 || posture.SchedulableNodes != 1 || posture.Managers != 1 || posture.NanoCPUs != 8_000_000_000 || posture.MemoryBytes != 17_179_869_184 || !posture.DockerSwarm || !posture.DockerCompose {
		t.Fatalf("unexpected posture: %#v", posture)
	}
	encoded, err := json.Marshal(posture)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(encoded), "secret-node") || strings.Contains(string(encoded), "secret-host") || strings.Contains(string(encoded), "29.3.0") {
		t.Fatalf("node identity leaked in posture: %s", encoded)
	}
}

func TestLocalClusterPostureFailsClosedWithoutDocker(t *testing.T) {
	posture := (Swarm{DockerBin: filepath.Join(t.TempDir(), "missing-docker")}).LocalClusterPosture(context.Background())
	if posture.InspectionStatus != clustercontract.LocalInspectionFailed || posture.DockerSwarm || posture.DockerCompose || posture.Nodes != 0 || posture.ObservedAt.IsZero() {
		t.Fatalf("unexpected failed posture: %#v", posture)
	}
}
