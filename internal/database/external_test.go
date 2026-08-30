package database

import (
	"encoding/json"
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
	var metadata *EngineInfo
	engines := registry.Engines()
	for index := range engines {
		if engines[index].Name == "cockroach" {
			metadata = &engines[index]
			break
		}
	}
	if metadata == nil || metadata.DefaultVersion != "v25.2" || metadata.Source != "external" || !strings.HasPrefix(metadata.ArtifactDigest, "sha256:") || len(metadata.ArtifactDigest) != 71 || !metadata.BackupCapable || metadata.BackupExtension != "dump" {
		t.Fatalf("external metadata=%#v", metadata)
	}
	encoded, err := json.Marshal(metadata)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(encoded), directory) || strings.Contains(string(encoded), path) {
		t.Fatalf("external driver path leaked in metadata: %s", encoded)
	}
	if plan, err := registry.Backup("cockroach", "v25.2", "data", map[string]string{}, "backup.dump"); err != nil || len(plan.Command) == 0 {
		t.Fatalf("backup plan=%#v err=%v", plan, err)
	}
}

func TestExternalDriverRejectsExecutableReplacementAfterDescription(t *testing.T) {
	directory := t.TempDir()
	path := filepath.Join(directory, "replaceable-driver")
	original := `#!/bin/sh
case "$(cat)" in
  *'"operation":"describe"'*) echo '{"protocolVersion":1,"description":{"name":"replaceable","defaultVersion":"1","capabilities":[]}}' ;;
  *) echo '{"protocolVersion":1,"result":{"composeYaml":"services: {}","environment":{},"credentials":{},"internalUrl":"http://data:1","version":"1"}}' ;;
esac
`
	if err := os.WriteFile(path, []byte(original), 0700); err != nil {
		t.Fatal(err)
	}
	registry := NewRegistry()
	if err := registry.LoadExternal(directory); err != nil {
		t.Fatal(err)
	}
	replacement := filepath.Join(directory, "replacement")
	if err := os.WriteFile(replacement, []byte(strings.Replace(original, "services: {}", "services: {changed: {}}", 1)), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(replacement, path); err != nil {
		t.Fatal(err)
	}
	if _, err := registry.Render("replaceable", Request{Name: "data"}); err == nil || !strings.Contains(err.Error(), "changed since startup") {
		t.Fatalf("replacement error=%v", err)
	}
}

func TestExternalDriverRejectsOversizedExecutable(t *testing.T) {
	directory := t.TempDir()
	path := filepath.Join(directory, "oversized-driver")
	if err := os.WriteFile(path, []byte("#!/bin/sh\n"), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.Truncate(path, maxExternalDriverBytes+1); err != nil {
		t.Fatal(err)
	}
	if err := NewRegistry().LoadExternal(directory); err == nil || !strings.Contains(err.Error(), "size is outside") {
		t.Fatalf("oversized driver error=%v", err)
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

func TestExternalDriverDoesNotExposeControlledErrors(t *testing.T) {
	for _, test := range []struct {
		name   string
		failed string
	}{
		{name: "stderr", failed: `echo 'password=driver-secret' >&2; exit 1`},
		{name: "protocol", failed: `echo '{"protocolVersion":1,"error":"password=driver-secret"}'`},
	} {
		t.Run(test.name, func(t *testing.T) {
			directory := t.TempDir()
			path := filepath.Join(directory, "secret-driver")
			script := `#!/bin/sh
request=$(cat)
case "$request" in
  *'"operation":"describe"'*) echo '{"protocolVersion":1,"description":{"name":"secret-test","defaultVersion":"1","capabilities":[]}}' ;;
  *) ` + test.failed + ` ;;
esac
`
			if err := os.WriteFile(path, []byte(script), 0700); err != nil {
				t.Fatal(err)
			}
			registry := NewRegistry()
			if err := registry.LoadExternal(directory); err != nil {
				t.Fatal(err)
			}
			_, err := registry.Render("secret-test", Request{Name: "data", Config: map[string]any{"password": "request-secret"}})
			if err == nil || !strings.Contains(err.Error(), "secret-test") || !strings.Contains(err.Error(), "render") {
				t.Fatalf("unexpected driver error: %v", err)
			}
			if strings.Contains(err.Error(), "driver-secret") || strings.Contains(err.Error(), "request-secret") {
				t.Fatalf("driver-controlled secret leaked: %v", err)
			}
		})
	}
}

func TestExternalDriverUsesSanitizedEnvironment(t *testing.T) {
	directory := t.TempDir()
	path := filepath.Join(directory, "environment-driver")
	script := `#!/bin/sh
[ "$PATH" = '/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin' ] || exit 9
[ -z "${DOCKYARD_MASTER_KEY:-}" ] || exit 10
echo '{"protocolVersion":1,"description":{"name":"environment-test","defaultVersion":"1","capabilities":[]}}'
`
	if err := os.WriteFile(path, []byte(script), 0700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", t.TempDir())
	t.Setenv("DOCKYARD_MASTER_KEY", "controller-secret")
	if err := NewRegistry().LoadExternal(directory); err != nil {
		t.Fatalf("sanitized driver environment: %v", err)
	}
}

func TestExternalDriverRequiresDeclaredRecoveryCapability(t *testing.T) {
	directory := t.TempDir()
	path := filepath.Join(directory, "no-recovery-driver")
	script := `#!/bin/sh
case "$(cat)" in
  *'"operation":"describe"'*) echo '{"protocolVersion":1,"description":{"name":"no-recovery","defaultVersion":"1","capabilities":[],"backupExtension":"dump"}}' ;;
  *) echo '{"protocolVersion":1,"plan":{"image":"tools:1","command":["dump"],"extension":"dump"}}' ;;
esac
`
	if err := os.WriteFile(path, []byte(script), 0700); err != nil {
		t.Fatal(err)
	}
	registry := NewRegistry()
	if err := registry.LoadExternal(directory); err != nil {
		t.Fatal(err)
	}
	if _, err := registry.Backup("no-recovery", "1", "db", map[string]string{}, "backup.dump"); err == nil || !strings.Contains(err.Error(), "does not declare") {
		t.Fatalf("undeclared recovery capability error=%v", err)
	}
}

func TestExternalDriverRequiresConsistentArtifactExtension(t *testing.T) {
	directory := t.TempDir()
	path := filepath.Join(directory, "extension-driver")
	script := `#!/bin/sh
case "$(cat)" in
  *'"operation":"describe"'*) echo '{"protocolVersion":1,"description":{"name":"extension-test","defaultVersion":"1","capabilities":["backup-restore"],"backupExtension":"dump"}}' ;;
  *) echo '{"protocolVersion":1,"plan":{"image":"tools:1","command":["dump"],"extension":"sql"}}' ;;
esac
`
	if err := os.WriteFile(path, []byte(script), 0700); err != nil {
		t.Fatal(err)
	}
	registry := NewRegistry()
	if err := registry.LoadExternal(directory); err != nil {
		t.Fatal(err)
	}
	if _, err := registry.Backup("extension-test", "1", "db", map[string]string{}, "backup.dump"); err == nil || !strings.Contains(err.Error(), "inconsistent") {
		t.Fatalf("inconsistent extension error=%v", err)
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
