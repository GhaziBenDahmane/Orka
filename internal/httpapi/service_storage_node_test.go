package httpapi

import (
	"errors"
	"testing"

	"github.com/GhaziBenDahmane/Orka/internal/deploy"
	"github.com/GhaziBenDahmane/Orka/internal/store"
)

func TestValidateStorageNodeTargetRequiresClusterMembershipAndAvailability(t *testing.T) {
	nodes := []deploy.Node{
		{ID: "readynode", Status: "Ready", Availability: "Active"},
		{ID: "drainednode", Status: "ready", Availability: "drain"},
		{ID: "downnode", Status: "down", Availability: "active"},
	}

	if err := validateStorageNodeTarget(nodes, "readynode"); err != nil {
		t.Fatalf("ready active node rejected: %v", err)
	}
	for _, nodeID := range []string{"drainednode", "downnode"} {
		if err := validateStorageNodeTarget(nodes, nodeID); !errors.Is(err, errStorageNodeUnavailable) {
			t.Fatalf("node %q error=%v, want unavailable", nodeID, err)
		}
	}
	for _, nodeID := range []string{"missingnode", "../invalid"} {
		if err := validateStorageNodeTarget(nodes, nodeID); !errors.Is(err, store.ErrInvalidStorageNode) {
			t.Fatalf("node %q error=%v, want invalid storage node", nodeID, err)
		}
	}
}
