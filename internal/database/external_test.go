package database

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestExternalDriverProtocol(t *testing.T) {
	directory := t.TempDir()
	path := filepath.Join(directory, "cockroach-driver")
	script := `#!/bin/sh
request=$(cat)
case "$request" in
  *'"operation":"describe"'*) echo '{"protocolVersion":1,"description":{"name":"cockroach","defaultVersion":"v25.2","capabilities":["backup-restore"],"backupExtension":"dump"}}' ;;
  *'"operation":"render"'*) echo '{"protocolVersion":1,"result":{"composeYaml":"services: {}","environment":{},"credentials":{"username":"root","password":"generated","database":"defaultdb"},"internalUrl":"postgres://data:26257/defaultdb","version":"v25.2"}}' ;;
  *) echo '{"protocolVersion":1,"plan":{"image":"cockroachdb/cockroach:v25.2","command":["cockroach","version"],"environment":{},"extension":"dump"}}' ;;
esac
`
	if err := os.WriteFile(path, []byte(script), 0700); err != nil {
		t.Fatal(err)
	}
	registry := NewRegistry()
	if err := registry.LoadExternal(directory); err != nil {
		t.Fatal(err)
	}
	if !containsString(registry.Names(), "cockroach") {
		t.Fatalf("external driver missing: %v", registry.Names())
	}
	result, err := registry.Render("cockroach", Request{Name: "data"})
	if err != nil || !strings.Contains(result.ComposeYAML, "services:") {
		t.Fatalf("render=%#v err=%v", result, err)
	}
	if extension, ok := registry.BackupExtension("cockroach"); !ok || extension != "dump" {
		t.Fatalf("backup extension=%q supported=%v", extension, ok)
	}
	if plan, err := registry.Backup("cockroach", "v25.2", "data", map[string]string{}, "backup.dump"); err != nil || len(plan.Command) == 0 {
		t.Fatalf("backup plan=%#v err=%v", plan, err)
	}
}

func containsString(values []string, expected string) bool {
	for _, value := range values {
		if value == expected {
			return true
		}
	}
	return false
}
