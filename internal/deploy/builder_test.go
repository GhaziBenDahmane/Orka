package deploy

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/bendahma/dokploy-go/internal/store"
	"github.com/google/uuid"
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

func TestImageRegistry(t *testing.T) {
	for image, want := range map[string]string{"postgres": "docker.io", "library/postgres": "docker.io", "ghcr.io/acme/api": "ghcr.io", "localhost:5000/api": "localhost:5000"} {
		if got := imageRegistry(image); got != want {
			t.Errorf("imageRegistry(%q) = %q, want %q", image, got, want)
		}
	}
}

func TestDockerConfigPermissionsAndAuth(t *testing.T) {
	directory, err := writeDockerConfig(Credential{Server: "registry.example", Username: "robot", Secret: "secret"})
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(directory)
	path := filepath.Join(directory, "config.json")
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0600 {
		t.Fatalf("config permissions = %o", info.Mode().Perm())
	}
	data, _ := os.ReadFile(path)
	if strings.Contains(string(data), "secret") {
		t.Fatal("Docker config contains a plaintext secret")
	}
}

func TestBuildRejectsCredentialHostMismatchBeforeClone(t *testing.T) {
	source := store.ApplicationSource{RepositoryURL: "https://github.com/acme/app.git", GitRef: "main", ContextDirectory: ".", Dockerfile: "Dockerfile", RegistryImage: "ghcr.io/acme/app"}
	_, _, err := (Builder{}).Build(context.Background(), source, uuid.New(), BuildCredentials{Git: Credential{Server: "gitlab.com", Username: "robot", Secret: "secret"}})
	if err == nil || !strings.Contains(err.Error(), "does not match") {
		t.Fatalf("expected host mismatch, got %v", err)
	}
}

func TestBuildRequiresPinnedSSHCredential(t *testing.T) {
	source := store.ApplicationSource{RepositoryURL: "ssh://git@example.com/acme/app.git", GitRef: "main", ContextDirectory: ".", Dockerfile: "Dockerfile", RegistryImage: "ghcr.io/acme/app"}
	_, _, err := (Builder{}).Build(context.Background(), source, uuid.New(), BuildCredentials{Git: Credential{Kind: "git-ssh", Server: "example.com", Username: "git", Secret: "key"}})
	if err == nil || !strings.Contains(err.Error(), "pinned host keys") {
		t.Fatalf("expected pinned-host-key rejection, got %v", err)
	}
}

func TestSSHCredentialFilesArePrivate(t *testing.T) {
	directory, err := writeSSHConfig(Credential{Secret: "private", KnownHosts: "example.com ssh-ed25519 AAAA"})
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(directory)
	for _, name := range []string{"key", "known_hosts"} {
		info, statErr := os.Stat(filepath.Join(directory, name))
		if statErr != nil {
			t.Fatal(statErr)
		}
		if info.Mode().Perm() != 0600 {
			t.Fatalf("%s permissions=%v", name, info.Mode().Perm())
		}
	}
}
