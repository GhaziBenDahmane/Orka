package deploy

import (
	"strings"
	"testing"
)

func TestValidateBackupArtifactMetadata(t *testing.T) {
	size := int64(1024)
	checksum := strings.Repeat("a", 64)
	plaintextChecksum := strings.Repeat("b", 64)
	if err := validateBackupArtifactMetadata(&size, checksum, plaintextChecksum, true); err != nil {
		t.Fatalf("valid encrypted metadata rejected: %v", err)
	}
	if err := validateBackupArtifactMetadata(&size, checksum, "", false); err != nil {
		t.Fatalf("valid plaintext metadata rejected: %v", err)
	}
	tests := map[string]struct {
		size              *int64
		checksum          string
		plaintextChecksum string
		encrypted         bool
	}{
		"missing size":                 {nil, checksum, plaintextChecksum, true},
		"zero size":                    {new(int64), checksum, plaintextChecksum, true},
		"malformed checksum":           {&size, strings.Repeat("z", 64), plaintextChecksum, true},
		"short checksum":               {&size, strings.Repeat("a", 62), plaintextChecksum, true},
		"missing plaintext checksum":   {&size, checksum, "", true},
		"malformed plaintext checksum": {&size, checksum, strings.Repeat("z", 64), true},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			if err := validateBackupArtifactMetadata(test.size, test.checksum, test.plaintextChecksum, test.encrypted); err == nil {
				t.Fatal("invalid backup metadata was accepted")
			}
		})
	}
}
