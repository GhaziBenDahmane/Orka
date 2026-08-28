package database

import (
	"strings"
	"testing"
)

func TestRegistryRendersAllDrivers(t *testing.T) {
	registry := NewRegistry()
	if len(registry.Names()) < 10 {
		t.Fatalf("expected broad driver catalog, got %v", registry.Names())
	}
	for _, engine := range registry.Names() {
		result, err := registry.Render(engine, Request{Name: "data"})
		if err != nil {
			t.Fatalf("%s: %v", engine, err)
		}
		if !strings.Contains(result.ComposeYAML, "services:") || result.InternalURL == "" || result.Version == "" {
			t.Fatalf("%s returned incomplete result", engine)
		}
	}
}
