package httpapi

import (
	"encoding/json"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/bendahma/dokploy-go/internal/database"
)

func TestDatabaseEnginesReturnsStructuredExternalMetadataWithoutPaths(t *testing.T) {
	directory := t.TempDir()
	path := filepath.Join(directory, "cockroach-driver")
	script := `#!/bin/sh
case "$(cat)" in
  *'"operation":"describe"'*) echo '{"protocolVersion":1,"description":{"name":"cockroach","defaultVersion":"v25.2","capabilities":["backup-restore"],"backupExtension":"dump"}}' ;;
  *) exit 1 ;;
esac
`
	if err := os.WriteFile(path, []byte(script), 0700); err != nil {
		t.Fatal(err)
	}
	registry := database.NewRegistry()
	if err := registry.LoadExternal(directory); err != nil {
		t.Fatal(err)
	}
	server := &Server{Databases: registry}
	recorder := httptest.NewRecorder()
	server.databaseEngines(recorder, httptest.NewRequest("GET", "/v1/database-engines", nil))
	if recorder.Code != 200 {
		t.Fatalf("status=%d body=%s", recorder.Code, recorder.Body.String())
	}
	var response struct {
		Items         []string              `json:"items"`
		BackupCapable []string              `json:"backupCapable"`
		Engines       []database.EngineInfo `json:"engines"`
	}
	if err := json.Unmarshal(recorder.Body.Bytes(), &response); err != nil {
		t.Fatal(err)
	}
	if !containsEngineName(response.Items, "cockroach") || !containsEngineName(response.BackupCapable, "cockroach") {
		t.Fatalf("legacy compatibility fields are incomplete: %#v", response)
	}
	found := false
	for _, engine := range response.Engines {
		if engine.Name == "cockroach" {
			found = engine.Source == "external" && engine.DefaultVersion == "v25.2" && strings.HasPrefix(engine.ArtifactDigest, "sha256:") && len(engine.ArtifactDigest) == 71 && engine.BackupCapable && engine.BackupExtension == "dump"
		}
	}
	if !found {
		t.Fatalf("structured external metadata missing: %#v", response.Engines)
	}
	if strings.Contains(recorder.Body.String(), directory) || strings.Contains(recorder.Body.String(), path) {
		t.Fatalf("driver path leaked: %s", recorder.Body.String())
	}
}

func containsEngineName(values []string, expected string) bool {
	for _, value := range values {
		if value == expected {
			return true
		}
	}
	return false
}
