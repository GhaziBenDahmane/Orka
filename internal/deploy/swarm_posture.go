package deploy

import (
	"context"
	"strings"
	"time"

	"github.com/GhaziBenDahmane/Orka/internal/clustercontract"
)

// LocalClusterPosture inspects only aggregate local Swarm state. Raw Docker
// errors and node identities never enter the returned audit/metrics contract.
func (s Swarm) LocalClusterPosture(ctx context.Context) clustercontract.LocalPosture {
	posture := clustercontract.LocalPosture{
		ObservedAt: time.Now().UTC(), InspectionStatus: clustercontract.LocalInspectionFailed,
		EdgeProxyConfigured: s.EdgeProxyServiceName != "" || s.EdgeProxyDynamicConfigurationPath != "",
	}
	nodes, err := s.Nodes(ctx)
	if err != nil {
		if posture.EdgeProxyConfigured {
			posture.EdgeProxyStatus = "inspection_failed"
		}
		return posture
	}
	posture.InspectionStatus = clustercontract.LocalInspectionReady
	posture.DockerSwarm = true
	posture.DockerCompose = true
	posture.Nodes = int64(len(nodes))
	for _, node := range nodes {
		ready := strings.EqualFold(node.Status, "ready")
		active := strings.EqualFold(node.Availability, "active")
		if ready {
			posture.ReadyNodes++
		}
		if active {
			posture.ActiveNodes++
		}
		if ready && active {
			posture.SchedulableNodes++
			posture.NanoCPUs += node.NanoCPUs
			posture.MemoryBytes += node.MemoryBytes
		}
		if node.ManagerStatus != "" {
			posture.Managers++
		}
	}
	if clustercontract.ValidateCapacity(posture.Capacity()) != nil {
		return clustercontract.LocalPosture{ObservedAt: posture.ObservedAt, InspectionStatus: clustercontract.LocalInspectionFailed, EdgeProxyConfigured: posture.EdgeProxyConfigured, EdgeProxyStatus: "inspection_failed"}
	}
	if !posture.EdgeProxyConfigured {
		return posture
	}
	posture.EdgeProxyStatus = "inspection_failed"
	if s.EdgeProxyServiceName == "" || s.EdgeProxyDynamicConfigurationPath == "" {
		return posture
	}
	if s.verifyEdgeProxyContract(ctx, EdgeProxySpec{ServiceName: s.EdgeProxyServiceName, DynamicConfigurationPath: s.EdgeProxyDynamicConfigurationPath}) == nil {
		posture.EdgeProxyReady = true
		posture.EdgeProxyStatus = "ready"
	}
	return posture
}
