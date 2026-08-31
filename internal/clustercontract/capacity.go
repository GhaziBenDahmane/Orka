package clustercontract

import "errors"

const (
	MaxClusterNodes       = int64(10_000)
	MaxClusterNanoCPUs    = int64(1_000_000_000_000)
	MaxClusterMemoryBytes = int64(1_125_899_906_842_624)
)

type Capacity struct {
	Nodes            int64 `json:"nodes"`
	ReadyNodes       int64 `json:"readyNodes"`
	ActiveNodes      int64 `json:"activeNodes"`
	SchedulableNodes int64 `json:"schedulableNodes"`
	Managers         int64 `json:"managers"`
	NanoCPUs         int64 `json:"nanoCpus"`
	MemoryBytes      int64 `json:"memoryBytes"`
}

func ValidateCapacity(capacity Capacity) error {
	if capacity.Nodes < 0 || capacity.Nodes > MaxClusterNodes ||
		capacity.ReadyNodes < 0 || capacity.ReadyNodes > capacity.Nodes ||
		capacity.ActiveNodes < 0 || capacity.ActiveNodes > capacity.Nodes ||
		capacity.SchedulableNodes < 0 || capacity.SchedulableNodes > capacity.ReadyNodes || capacity.SchedulableNodes > capacity.ActiveNodes ||
		capacity.Managers < 0 || capacity.Managers > capacity.Nodes ||
		capacity.NanoCPUs < 0 || capacity.NanoCPUs > MaxClusterNanoCPUs ||
		capacity.MemoryBytes < 0 || capacity.MemoryBytes > MaxClusterMemoryBytes ||
		capacity.SchedulableNodes == 0 && (capacity.NanoCPUs != 0 || capacity.MemoryBytes != 0) {
		return errors.New("invalid cluster capacity")
	}
	return nil
}
