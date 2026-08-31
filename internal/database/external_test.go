package database

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/bendahma/dokploy-go/pkg/databaseplugin"
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

func TestExternalDriverRequiresAtLeastOneTrustedExecutable(t *testing.T) {
	for _, setup := range []struct {
		name string
		run  func(*testing.T, string)
	}{
		{name: "empty directory", run: func(*testing.T, string) {}},
		{name: "non executable file", run: func(t *testing.T, directory string) {
			t.Helper()
			if err := os.WriteFile(filepath.Join(directory, "README"), []byte("no drivers\n"), 0600); err != nil {
				t.Fatal(err)
			}
		}},
	} {
		t.Run(setup.name, func(t *testing.T) {
			directory := t.TempDir()
			setup.run(t, directory)
			if err := NewRegistry().LoadExternal(directory); err == nil || !strings.Contains(err.Error(), "no trusted executable drivers") {
				t.Fatalf("empty driver directory error=%v", err)
			}
		})
	}
}

func TestExternalDriverDiscoveryIsAtomic(t *testing.T) {
	directory := t.TempDir()
	valid := `#!/bin/sh
echo '{"protocolVersion":1,"description":{"name":"atomic-test","defaultVersion":"1","capabilities":[]}}'
`
	invalid := `#!/bin/sh
echo '{"protocolVersion":1,"description":{"name":"INVALID","defaultVersion":"1","capabilities":[]}}'
`
	if err := os.WriteFile(filepath.Join(directory, "a-valid"), []byte(valid), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(directory, "z-invalid"), []byte(invalid), 0700); err != nil {
		t.Fatal(err)
	}
	registry := NewRegistry()
	if err := registry.LoadExternal(directory); err == nil {
		t.Fatal("invalid driver set was accepted")
	}
	if _, exists := registry.Engine("atomic-test"); exists {
		t.Fatal("valid driver was partially registered before discovery failed")
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

func TestExternalDriverRejectsWritableDirectoryAndDoesNotFollowSymlinks(t *testing.T) {
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
	if err := NewRegistry().LoadExternal(directory); err == nil || !strings.Contains(err.Error(), "no trusted executable drivers") {
		t.Fatalf("symlinked executable was not ignored: %v", err)
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

func TestExternalDriverBoundsInheritedOutputDescriptors(t *testing.T) {
	directory := t.TempDir()
	path := filepath.Join(directory, "forking-driver")
	pidFile := filepath.Join(directory, "child.pid")
	script := strings.Replace(`#!/bin/sh
request=$(cat)
case "$request" in
  *'"operation":"describe"'*) echo '{"protocolVersion":1,"description":{"name":"forking-test","defaultVersion":"1","capabilities":[]}}' ;;
  *) sleep 30 & child=$!; printf '%s' "$child" >'__PID_FILE__'; echo '{"protocolVersion":1,"result":{"composeYaml":"services: {}","environment":{},"credentials":{},"internalUrl":"http://data:1","version":"1"}}' ;;
esac
`, "__PID_FILE__", pidFile, 1)
	if err := os.WriteFile(path, []byte(script), 0700); err != nil {
		t.Fatal(err)
	}
	registry := NewRegistry()
	if err := registry.LoadExternal(directory); err != nil {
		t.Fatal(err)
	}
	started := time.Now()
	_, err := registry.Render("forking-test", Request{Name: "data"})
	if elapsed := time.Since(started); elapsed > 3*time.Second {
		t.Fatalf("driver call waited %s for an inherited output descriptor", elapsed)
	}
	if err == nil || !strings.Contains(err.Error(), "failed during render") {
		t.Fatalf("forking driver error=%v", err)
	}
	pidData, err := os.ReadFile(pidFile)
	if err != nil {
		t.Fatal(err)
	}
	pid, err := strconv.Atoi(string(pidData))
	if err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(2 * time.Second)
	for externalDriverProcessRunning(pid) && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if externalDriverProcessRunning(pid) {
		t.Fatalf("driver descendant %d survived process-group cleanup", pid)
	}
}

func externalDriverProcessRunning(pid int) bool {
	status, err := os.ReadFile("/proc/" + strconv.Itoa(pid) + "/stat")
	if os.IsNotExist(err) {
		return false
	}
	fields := strings.Fields(string(status))
	return err == nil && len(fields) > 2 && fields[2] != "Z" && fields[2] != "X"
}

func TestExternalDriverRejectsBackupExtensionWithoutCapability(t *testing.T) {
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
	if err := registry.LoadExternal(directory); err == nil || !strings.Contains(err.Error(), "invalid external database driver description") {
		t.Fatalf("inconsistent description error=%v", err)
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

func TestExternalDriverRejectsInvalidRenderBoundaries(t *testing.T) {
	tests := map[string]string{
		"unsafe version":   `{"protocolVersion":1,"result":{"composeYaml":"services: {}","environment":{},"credentials":{},"internalUrl":"postgres://data:5432/db","version":"../../latest"}}`,
		"environment name": `{"protocolVersion":1,"result":{"composeYaml":"services: {}","environment":{"BAD-NAME":"secret"},"credentials":{},"internalUrl":"postgres://data:5432/db","version":"1"}}`,
		"credential name":  `{"protocolVersion":1,"result":{"composeYaml":"services: {}","environment":{},"credentials":{"bad name":"secret"},"internalUrl":"postgres://data:5432/db","version":"1"}}`,
		"relative URL":     `{"protocolVersion":1,"result":{"composeYaml":"services: {}","environment":{},"credentials":{},"internalUrl":"data:5432/db","version":"1"}}`,
		"unicode control":  `{"protocolVersion":1,"result":{"composeYaml":"services: {}","environment":{},"credentials":{},"internalUrl":"postgres://data\u0085:5432/db","version":"1"}}`,
		"unicode format":   `{"protocolVersion":1,"result":{"composeYaml":"services: {}","environment":{},"credentials":{},"internalUrl":"postgres://data\u202e:5432/db","version":"1"}}`,
	}
	for name, response := range tests {
		t.Run(name, func(t *testing.T) {
			registry := externalRenderRegistry(t, response)
			if _, err := registry.Render("render-test", Request{Name: "data"}); err == nil {
				t.Fatal("invalid external render result was accepted")
			}
		})
	}
}

func TestExternalDriverRejectsInvalidUTF8InternalURL(t *testing.T) {
	if err := validateExternalInternalURL("postgres://data:5432/db\xff"); err == nil {
		t.Fatal("invalid UTF-8 internal URL was accepted")
	}
}

func TestExternalDriverRejectsInvalidRenderRequestsBeforeExecution(t *testing.T) {
	driver := &externalDriver{path: filepath.Join(t.TempDir(), "missing-driver"), description: databaseplugin.Description{Name: "render-test", DefaultVersion: "1"}}
	tests := []Request{
		{Name: "../data", Version: "1"},
		{Name: "data", Version: "../../latest"},
		{Name: "data", Version: "1", Config: map[string]any{"unsupported": make(chan int)}},
		{Name: "data", Version: "1", Config: map[string]any{"oversized": strings.Repeat("x", databaseplugin.MaxRequestBytes)}},
	}
	for _, request := range tests {
		if _, err := driver.Render(request); err == nil || strings.Contains(err.Error(), "open database driver") {
			t.Fatalf("invalid render request reached driver execution: request=%#v err=%v", request, err)
		}
	}
}

func TestExternalDriverRejectsInvalidUtilityRequestsBeforeExecution(t *testing.T) {
	driver := &externalDriver{
		path: filepath.Join(t.TempDir(), "missing-driver"),
		description: databaseplugin.Description{
			Name: "utility-test", DefaultVersion: "1", Capabilities: []string{"backup-restore"}, BackupExtension: "dump",
		},
	}
	tests := []struct {
		operation string
		request   databaseplugin.UtilityRequest
	}{
		{operation: "backup", request: databaseplugin.UtilityRequest{Version: "../1", Host: "data", Filename: "backup.dump"}},
		{operation: "backup", request: databaseplugin.UtilityRequest{Version: "1", Host: "data;evil", Filename: "backup.dump"}},
		{operation: "backup", request: databaseplugin.UtilityRequest{Version: "1", Host: "data", Credentials: map[string]string{"bad name": "secret"}, Filename: "backup.dump"}},
		{operation: "restore", request: databaseplugin.UtilityRequest{Version: "1", Host: "data", Filename: "../backup.dump"}},
		{operation: "restore", request: databaseplugin.UtilityRequest{Version: "1", Host: "data", Filename: "backup.sql"}},
		{operation: "readiness", request: databaseplugin.UtilityRequest{Version: "1", Host: "data", Filename: "unexpected.dump"}},
		{operation: "unknown", request: databaseplugin.UtilityRequest{Version: "1", Host: "data"}},
	}
	for _, test := range tests {
		if _, err := driver.plan(test.operation, test.request); err == nil || strings.Contains(err.Error(), "open database driver") {
			t.Fatalf("invalid utility request reached driver execution: operation=%s request=%#v err=%v", test.operation, test.request, err)
		}
	}
}

func TestExternalDriverRejectsInvalidProtocolResponseShape(t *testing.T) {
	tests := map[string]string{
		"unknown field":         `{"protocolVersion":1,"result":{"composeYaml":"services: {}","environment":{},"credentials":{},"internalUrl":"postgres://data:5432/db","version":"1"},"unexpected":true}`,
		"wrong operation field": `{"protocolVersion":1,"description":{"name":"other","defaultVersion":"1","capabilities":[]},"result":{"composeYaml":"services: {}","environment":{},"credentials":{},"internalUrl":"postgres://data:5432/db","version":"1"}}`,
		"trailing JSON":         `{"protocolVersion":1,"result":{"composeYaml":"services: {}","environment":{},"credentials":{},"internalUrl":"postgres://data:5432/db","version":"1"}} {}`,
	}
	for name, response := range tests {
		t.Run(name, func(t *testing.T) {
			registry := externalRenderRegistry(t, response)
			if _, err := registry.Render("render-test", Request{Name: "data"}); err == nil {
				t.Fatal("invalid protocol response was accepted")
			}
		})
	}
}

func TestExternalDriverRejectsInvalidDescriptions(t *testing.T) {
	tests := map[string]string{
		"unknown capability":   `{"name":"invalid-description","defaultVersion":"1","capabilities":["shell"]}`,
		"duplicate capability": `{"name":"invalid-description","defaultVersion":"1","capabilities":["backup-restore","backup-restore"],"backupExtension":"dump"}`,
		"missing extension":    `{"name":"invalid-description","defaultVersion":"1","capabilities":["backup-restore"]}`,
	}
	for name, description := range tests {
		t.Run(name, func(t *testing.T) {
			directory := t.TempDir()
			path := filepath.Join(directory, "invalid-description-driver")
			script := "#!/bin/sh\necho '{\"protocolVersion\":1,\"description\":" + description + "}'\n"
			if err := os.WriteFile(path, []byte(script), 0700); err != nil {
				t.Fatal(err)
			}
			if err := NewRegistry().LoadExternal(directory); err == nil {
				t.Fatal("invalid driver description was accepted")
			}
		})
	}
}

func externalRenderRegistry(t *testing.T, renderResponse string) *Registry {
	t.Helper()
	directory := t.TempDir()
	path := filepath.Join(directory, "render-driver")
	script := `#!/bin/sh
case "$(cat)" in
  *'"operation":"describe"'*) echo '{"protocolVersion":1,"description":{"name":"render-test","defaultVersion":"1","capabilities":[]}}' ;;
  *) echo '` + renderResponse + `' ;;
esac
`
	if err := os.WriteFile(path, []byte(script), 0700); err != nil {
		t.Fatal(err)
	}
	registry := NewRegistry()
	if err := registry.LoadExternal(directory); err != nil {
		t.Fatal(err)
	}
	return registry
}

func containsString(values []string, expected string) bool {
	for _, value := range values {
		if value == expected {
			return true
		}
	}
	return false
}
