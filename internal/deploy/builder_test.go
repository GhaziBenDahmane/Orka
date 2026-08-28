package deploy

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestSafeJoin(t *testing.T) {
	root := t.TempDir()
	if _, err := safeJoin(root, "../../etc/passwd"); err == nil {
		t.Fatal("expected path traversal rejection")
	}
	path, err := safeJoin(root, "app/Dockerfile")
	if err != nil || !strings.HasPrefix(path, root) {
		t.Fatalf("unexpected safe path %q: %v", path, err)
	}
}

func TestResolveInsideRejectsSymlinkEscape(t *testing.T) {
	root := t.TempDir()
	outside := t.TempDir()
	if err := os.Symlink(outside, filepath.Join(root, "escape")); err != nil {
		t.Fatal(err)
	}
	if _, err := resolveInside(root, filepath.Join(root, "escape")); err == nil {
		t.Fatal("expected symlink escape to be rejected")
	}
}
func TestSetServiceImage(t *testing.T) {
	out, err := SetServiceImage("services:\n  web:\n    build: .\n", "web", "registry.example/web:123")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out, "registry.example/web:123") || strings.Contains(out, "build:") {
		t.Fatalf("image was not applied:\n%s", out)
	}
}
