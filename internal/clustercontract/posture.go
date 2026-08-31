package clustercontract

import "time"

const (
	LocalInspectionNotSampled = "not_sampled"
	LocalInspectionReady      = "ready"
	LocalInspectionFailed     = "inspection_failed"
)

// LocalPosture is the bounded, secret-free runtime view of the controller's
// own Swarm. It intentionally excludes node IDs, hostnames, labels, service
// names, network names, filesystem paths, and raw Docker errors.
type LocalPosture struct {
	ObservedAt          time.Time `json:"observedAt,omitempty"`
	InspectionStatus    string    `json:"inspectionStatus"`
	Nodes               int64     `json:"nodes"`
	ReadyNodes          int64     `json:"readyNodes"`
	ActiveNodes         int64     `json:"activeNodes"`
	SchedulableNodes    int64     `json:"schedulableNodes"`
	Managers            int64     `json:"managers"`
	NanoCPUs            int64     `json:"nanoCpus"`
	MemoryBytes         int64     `json:"memoryBytes"`
	DockerSwarm         bool      `json:"dockerSwarm"`
	DockerCompose       bool      `json:"dockerCompose"`
	EdgeProxyConfigured bool      `json:"edgeProxyConfigured"`
	EdgeProxyReady      bool      `json:"edgeProxyReady"`
	EdgeProxyStatus     string    `json:"edgeProxyStatus,omitempty"`
}

func (p LocalPosture) Capacity() Capacity {
	return Capacity{
		Nodes: p.Nodes, ReadyNodes: p.ReadyNodes, ActiveNodes: p.ActiveNodes,
		SchedulableNodes: p.SchedulableNodes, Managers: p.Managers,
		NanoCPUs: p.NanoCPUs, MemoryBytes: p.MemoryBytes,
	}
}
