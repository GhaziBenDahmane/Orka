package clustercontract

import "testing"

func TestValidateCapacity(t *testing.T) {
	valid := Capacity{Nodes: 3, ReadyNodes: 2, ActiveNodes: 2, SchedulableNodes: 2, Managers: 1, NanoCPUs: 8_000_000_000, MemoryBytes: 16 << 30}
	if err := ValidateCapacity(valid); err != nil {
		t.Fatalf("valid capacity rejected: %v", err)
	}
	invalid := []Capacity{
		{Nodes: -1},
		{Nodes: MaxClusterNodes + 1},
		{Nodes: 1, ReadyNodes: 2},
		{Nodes: 1, ActiveNodes: 2},
		{Nodes: 1, ReadyNodes: 1, ActiveNodes: 1, SchedulableNodes: 2},
		{Nodes: 1, Managers: 2},
		{NanoCPUs: 1},
		{MemoryBytes: 1},
		{Nodes: 1, ReadyNodes: 1, ActiveNodes: 1, SchedulableNodes: 1, NanoCPUs: MaxClusterNanoCPUs + 1},
		{Nodes: 1, ReadyNodes: 1, ActiveNodes: 1, SchedulableNodes: 1, MemoryBytes: MaxClusterMemoryBytes + 1},
	}
	for index, capacity := range invalid {
		if err := ValidateCapacity(capacity); err == nil {
			t.Errorf("invalid capacity %d accepted: %#v", index, capacity)
		}
	}
}
