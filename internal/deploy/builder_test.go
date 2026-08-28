package deploy

import (
	"context"
	"fmt"
	"net/url"
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

func TestValidateBuildSettings(t *testing.T) {
	valid := store.ApplicationBuildConfig{Arguments: map[string]string{"GO_VERSION": "1.26"}, Secrets: map[string]string{"NPM_TOKEN": "secret"}}
	if err := ValidateBuildSettings("runtime", valid); err != nil {
		t.Fatal(err)
	}
	for name, config := range map[string]store.ApplicationBuildConfig{
		"invalid name": {Arguments: map[string]string{"BAD-NAME": "value"}},
		"overlap":      {Arguments: map[string]string{"TOKEN": "public"}, Secrets: map[string]string{"TOKEN": "secret"}},
	} {
		t.Run(name, func(t *testing.T) {
			if err := ValidateBuildSettings("runtime", config); err == nil {
				t.Fatal("expected invalid build settings")
			}
		})
	}
	if err := ValidateBuildSettings("../../escape", valid); err == nil {
		t.Fatal("expected invalid build target")
	}
}

func TestValidateStaticBuild(t *testing.T) {
	if err := ValidateBuildMode("static", "dist", "", store.ApplicationBuildConfig{}); err != nil {
		t.Fatal(err)
	}
	for name, output := range map[string]string{"empty": "", "context root": ".", "escape": "../dist", "absolute": "/dist"} {
		t.Run(name, func(t *testing.T) {
			if err := ValidateBuildMode("static", output, "", store.ApplicationBuildConfig{}); err == nil {
				t.Fatal("expected invalid static output directory")
			}
		})
	}
	if err := ValidateBuildMode("static", "dist", "runtime", store.ApplicationBuildConfig{}); err == nil {
		t.Fatal("expected Docker target to be rejected for a static build")
	}
}

func TestStaticBuildUsesPinnedRuntimeAndOutputDirectory(t *testing.T) {
	directory := t.TempDir()
	gitPath := filepath.Join(directory, "git")
	dockerPath := filepath.Join(directory, "docker")
	argsPath := filepath.Join(directory, "docker-args")
	dockerfileCopy := filepath.Join(directory, "Dockerfile.generated")
	t.Setenv("DOCKYARD_BUILD_TEST_LOG", argsPath)
	t.Setenv("DOCKYARD_BUILD_TEST_DOCKERFILE", dockerfileCopy)
	gitScript := "#!/bin/sh\nfor destination do :; done\nmkdir -p \"$destination/public\"\nprintf '<h1>ready</h1>\\n' >\"$destination/public/index.html\"\n"
	dockerScript := "#!/bin/sh\nprintf '%s\\n' \"$@\" >\"$DOCKYARD_BUILD_TEST_LOG\"\nprevious=''\nfor value do\n  if [ \"$previous\" = '--file' ]; then cp \"$value\" \"$DOCKYARD_BUILD_TEST_DOCKERFILE\"; fi\n  previous=$value\ndone\n"
	if err := os.WriteFile(gitPath, []byte(gitScript), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(dockerPath, []byte(dockerScript), 0700); err != nil {
		t.Fatal(err)
	}
	source := store.ApplicationSource{RepositoryURL: "https://git.example.test/acme/site.git", GitRef: "main", ContextDirectory: ".", BuildType: "static", OutputDirectory: "public", RegistryImage: "registry.example.test/acme/site"}
	if _, _, err := (Builder{GitBin: gitPath, DockerBin: dockerPath}).Build(context.Background(), source, uuid.New(), BuildCredentials{}); err != nil {
		t.Fatal(err)
	}
	arguments, err := os.ReadFile(argsPath)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(arguments), "buildx\nbuild\n") || !strings.HasSuffix(strings.TrimSpace(string(arguments)), "/public") {
		t.Fatalf("unexpected static build arguments:\n%s", arguments)
	}
	definition, err := os.ReadFile(dockerfileCopy)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(definition), "FROM "+defaultStaticImage) || !strings.Contains(string(definition), "COPY . /srv") {
		t.Fatalf("unexpected generated Dockerfile:\n%s", definition)
	}
}

func TestNixpacksBuildAndPush(t *testing.T) {
	directory := t.TempDir()
	gitPath, nixpacksPath, dockerPath := filepath.Join(directory, "git"), filepath.Join(directory, "nixpacks"), filepath.Join(directory, "docker")
	logPath := filepath.Join(directory, "calls")
	t.Setenv("DOCKYARD_BUILD_TEST_LOG", logPath)
	gitScript := "#!/bin/sh\nfor destination do :; done\nmkdir -p \"$destination\"\n"
	toolScript := "#!/bin/sh\nprintf '%s:%s\\n' \"$(basename \"$0\")\" \"$*\" >>\"$DOCKYARD_BUILD_TEST_LOG\"\n"
	for path, content := range map[string]string{gitPath: gitScript, nixpacksPath: toolScript, dockerPath: toolScript} {
		if err := os.WriteFile(path, []byte(content), 0700); err != nil {
			t.Fatal(err)
		}
	}
	source := store.ApplicationSource{RepositoryURL: "https://git.example.test/acme/app.git", GitRef: "main", ContextDirectory: ".", BuildType: "nixpacks", RegistryImage: "registry.example.test/acme/app", BuildArguments: map[string]string{"NODE_VERSION": "24"}}
	tag, _, err := (Builder{GitBin: gitPath, NixpacksBin: nixpacksPath, DockerBin: dockerPath}).Build(context.Background(), source, uuid.MustParse("00000000-0000-0000-0000-000000000124"), BuildCredentials{})
	if err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatal(err)
	}
	calls := string(data)
	if !strings.Contains(calls, "nixpacks:build ") || !strings.Contains(calls, "--name "+tag) || !strings.Contains(calls, "--env NODE_VERSION=24") || !strings.Contains(calls, "docker:push "+tag) {
		t.Fatalf("unexpected build calls:\n%s", calls)
	}
	if err := ValidateBuildMode("nixpacks", "", "", store.ApplicationBuildConfig{Secrets: map[string]string{"TOKEN": "secret"}}); err == nil {
		t.Fatal("expected Nixpacks secrets to be rejected")
	}
}

func TestBuildUsesTargetArgumentsAndFileBackedSecrets(t *testing.T) {
	directory := t.TempDir()
	gitPath := filepath.Join(directory, "git")
	dockerPath := filepath.Join(directory, "docker")
	logPath := filepath.Join(directory, "docker-args")
	t.Setenv("DOCKYARD_BUILD_TEST_LOG", logPath)
	gitScript := "#!/bin/sh\nfor destination do :; done\nmkdir -p \"$destination\"\nprintf 'FROM scratch\\n' >\"$destination/Dockerfile\"\n"
	dockerScript := "#!/bin/sh\nprintf '%s\\n' \"$@\" >\"$DOCKYARD_BUILD_TEST_LOG\"\n"
	if err := os.WriteFile(gitPath, []byte(gitScript), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(dockerPath, []byte(dockerScript), 0700); err != nil {
		t.Fatal(err)
	}
	source := store.ApplicationSource{
		RepositoryURL: "https://git.example.test/acme/app.git", GitRef: "main", ContextDirectory: ".", Dockerfile: "Dockerfile",
		RegistryImage: "registry.example.test/acme/app", BuildTarget: "runtime",
		BuildArguments: map[string]string{"GO_VERSION": "1.26"}, BuildSecrets: map[string]string{"NPM_TOKEN": "s3cr3t"},
	}
	tag, _, err := (Builder{GitBin: gitPath, DockerBin: dockerPath}).Build(context.Background(), source, uuid.MustParse("00000000-0000-0000-0000-000000000123"), BuildCredentials{})
	if err != nil {
		t.Fatal(err)
	}
	if tag != "registry.example.test/acme/app:00000000-0000-0000-0000-000000000123" {
		t.Fatalf("tag=%q", tag)
	}
	data, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatal(err)
	}
	arguments := string(data)
	for _, expected := range []string{"--target\nruntime\n", "--build-arg\nGO_VERSION=1.26\n", "--secret\nid=NPM_TOKEN,src="} {
		if !strings.Contains(arguments, expected) {
			t.Errorf("Docker arguments omit %q:\n%s", expected, arguments)
		}
	}
	if strings.Contains(arguments, "s3cr3t") {
		t.Fatal("BuildKit secret value leaked into Docker argv")
	}
	secretMarker := "id=NPM_TOKEN,src="
	start := strings.Index(arguments, secretMarker)
	if start < 0 {
		t.Fatal("secret source argument missing")
	}
	secretPath := strings.TrimSpace(strings.SplitN(arguments[start+len(secretMarker):], "\n", 2)[0])
	if _, err := os.Stat(secretPath); !os.IsNotExist(err) {
		t.Fatalf("temporary build secret was not removed: %v", err)
	}
}

func TestBuildSecretFilesArePrivate(t *testing.T) {
	directory, err := writeBuildSecrets(map[string]string{"TOKEN": "secret"})
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(directory)
	info, err := os.Stat(filepath.Join(directory, "TOKEN"))
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0600 {
		t.Fatalf("build secret permissions=%o, want 600", info.Mode().Perm())
	}
}

func TestSafeSubmoduleURL(t *testing.T) {
	repository, _ := url.Parse("https://github.com/acme/app.git")
	for raw, want := range map[string]bool{
		"../shared.git":                         true,
		"https://github.com/acme/shared.git":    true,
		"https://gitlab.com/acme/stolen.git":    false,
		"https://github.com:8443/acme/evil.git": false,
		"ssh://git@github.com/acme/shared.git":  false,
		"file:///etc":                           false,
	} {
		t.Run(fmt.Sprintf("%s=%t", raw, want), func(t *testing.T) {
			if got := safeSubmoduleURL(raw, repository); got != want {
				t.Fatalf("safeSubmoduleURL(%q)=%t, want %t", raw, got, want)
			}
		})
	}
}
