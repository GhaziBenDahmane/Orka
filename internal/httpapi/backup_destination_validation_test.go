package httpapi

import (
	"strings"
	"testing"
)

func TestNormalizedBackupDestinationName(t *testing.T) {
	if name, ok := normalizedBackupDestinationName("  production backups  "); !ok || name != "production backups" {
		t.Fatalf("name=%q valid=%t", name, ok)
	}
	for _, value := range []string{"", "  ", "line\nbreak", strings.Repeat("n", maxBackupDestinationNameBytes+1)} {
		if name, ok := normalizedBackupDestinationName(value); ok {
			t.Errorf("invalid name %q normalized to %q", value, name)
		}
	}
}
