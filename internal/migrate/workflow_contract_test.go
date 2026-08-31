package migrate

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestMigrationEvidenceConsumersRequireBackupCutoverProof(t *testing.T) {
	for _, path := range []string{
		filepath.Join("..", "..", "scripts", "ci", "test-migration-conformance.sh"),
		filepath.Join("..", "..", ".github", "workflows", "migration-conformance.yml"),
		filepath.Join("..", "..", ".github", "workflows", "release.yml"),
	} {
		contents, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		for _, required := range []string{".databaseBackupCutoverVerified", ".volumeBackupCutoverVerified"} {
			if !strings.Contains(string(contents), required) {
				t.Errorf("%s does not require migration evidence field %s", path, required)
			}
		}
	}
}
