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

func TestExternalDriverRejectsSymlinkedDirectory(t *testing.T) {
	parent := t.TempDir()
	target := filepath.Join(parent, "drivers")
	if err := os.Mkdir(target, 0700); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(parent, "driver-link")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	if err := NewRegistry().LoadExternal(link); err == nil || !strings.Contains(err.Error(), "symbolic link") {
		t.Fatalf("symlinked directory error=%v", err)
	}
}

func TestExternalDriverRejectsWritableDirectoryAndIgnoresSymlinks(t *testing.T) {
	directory := t.TempDir()
	if err := os.Chmod(directory, 0775); err != nil {
		t.Fatal(err)
	}
	if err := NewRegistry().LoadExternal(directory); err == nil || !strings.Contains(err.Error(), "group/world writable") {
		t.Fatalf("writable directory error=%v", err)
	}
	if err := os.Chmod(directory, 0700); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(t.TempDir(), "external-target")
	if err := os.WriteFile(target, []byte("#!/bin/sh\nexit 1\n"), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, filepath.Join(directory, "linked-driver")); err != nil {
		t.Fatal(err)
	}
	registry := NewRegistry()
	if err := registry.LoadExternal(directory); err != nil {
		t.Fatal(err)
	}
	if containsString(registry.Names(), "linked-driver") {
		t.Fatal("symlinked executable was loaded")
	}
}

func TestExternalDriverRevalidatesExecutableBeforeEveryCall(t *testing.T) {
	directory := t.TempDir()
	path := filepath.Join(directory, "mutable-driver")
	script := `#!/bin/sh
case "$(cat)" in
  *'"operation":"describe"'*) echo '{"protocolVersion":1,"description":{"name":"mutable","defaultVersion":"1","capabilities":[]}}' ;;
  *) echo '{"protocolVersion":1,"result":{"composeYaml":"services: {}","environment":{},"credentials":{},"internalUrl":"http://data:1","version":"1"}}' ;;
esac
`
	if err := os.WriteFile(path, []byte(script), 0700); err != nil {
		t.Fatal(err)
	}
	registry := NewRegistry()
	if err := registry.LoadExternal(directory); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0777); err != nil {
		t.Fatal(err)
	}
	if _, err := registry.Render("mutable", Request{Name: "data"}); err == nil || !strings.Contains(err.Error(), "group/world writable") {
		t.Fatalf("mutated driver error=%v", err)
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("/bin/true", path); err != nil {
		t.Fatal(err)
	}
	if _, err := registry.Render("mutable", Request{Name: "data"}); err == nil {
		t.Fatal("symlink swapped after registration was executed")
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
