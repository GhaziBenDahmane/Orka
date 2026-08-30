package deploy

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/bendahma/dokploy-go/internal/netpolicy"
	"github.com/bendahma/dokploy-go/internal/store"
	"github.com/google/uuid"
)

type builderResolver map[string][]netip.Addr

func (r builderResolver) LookupNetIP(_ context.Context, _, host string) ([]netip.Addr, error) {
	return r[host], nil
}

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

func TestBuildRejectsPrivateRepositoryDestination(t *testing.T) {
	source := store.ApplicationSource{RepositoryURL: "https://127.0.0.1/repository.git", GitRef: "main", ContextDirectory: ".", BuildType: "dockerfile", RegistryImage: "registry.example.test/acme/app"}
	_, _, err := (Builder{EgressPolicy: &netpolicy.Policy{}}).Build(context.Background(), source, uuid.New(), BuildCredentials{})
	if err == nil || !strings.Contains(err.Error(), "egress policy blocks") {
		t.Fatalf("private repository error=%v", err)
	}
}

func TestBuildPinsHTTPSGitToPolicyResolution(t *testing.T) {
	directory := t.TempDir()
	gitPath, dockerPath, logPath := filepath.Join(directory, "git"), filepath.Join(directory, "docker"), filepath.Join(directory, "git-environment")
	t.Setenv("DOCKYARD_BUILD_TEST_LOG", logPath)
	gitScript := "#!/bin/sh\nprintf '%s' \"$GIT_CONFIG_VALUE_0\" >\"$DOCKYARD_BUILD_TEST_LOG\"\nfor destination do :; done\nmkdir -p \"$destination\"\nprintf 'FROM scratch\\n' >\"$destination/Dockerfile\"\n"
	if err := os.WriteFile(gitPath, []byte(gitScript), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(dockerPath, []byte("#!/bin/sh\nexit 0\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	policy := &netpolicy.Policy{Resolver: builderResolver{"git.example.test": {netip.MustParseAddr("93.184.216.34")}}}
	source := store.ApplicationSource{RepositoryURL: "https://git.example.test/acme/repository.git", GitRef: "main", ContextDirectory: ".", BuildType: "dockerfile", Dockerfile: "Dockerfile", RegistryImage: "registry.example.test/acme/app"}
	if _, _, err := (Builder{GitBin: gitPath, DockerBin: dockerPath, EgressPolicy: policy}).Build(context.Background(), source, uuid.New(), BuildCredentials{}); err != nil {
		t.Fatal(err)
	}
	pinned, err := os.ReadFile(logPath)
	if err != nil || string(pinned) != "git.example.test:443:93.184.216.34" {
		t.Fatalf("Git resolution pin=%q error=%v", pinned, err)
	}
}

func TestBuildRejectsOversizedCheckoutBeforeDocker(t *testing.T) {
	directory := t.TempDir()
	gitPath, dockerPath, dockerLog := filepath.Join(directory, "git"), filepath.Join(directory, "docker"), filepath.Join(directory, "docker.log")
	gitScript := "#!/bin/sh\nfor destination do :; done\nmkdir -p \"$destination\"\nprintf 'FROM scratch\\n' >\"$destination/Dockerfile\"\nprintf 'oversized repository data' >\"$destination/payload\"\n"
	if err := os.WriteFile(gitPath, []byte(gitScript), 0700); err != nil {
		t.Fatal(err)
	}
	dockerScript := "#!/bin/sh\nprintf called >" + dockerLog + "\n"
	if err := os.WriteFile(dockerPath, []byte(dockerScript), 0700); err != nil {
		t.Fatal(err)
	}
	source := store.ApplicationSource{RepositoryURL: "https://github.com/acme/app.git", GitRef: "main", ContextDirectory: ".", Dockerfile: "Dockerfile", RegistryImage: "ghcr.io/acme/app"}
	_, _, err := (Builder{GitBin: gitPath, DockerBin: dockerPath, MaxWorkspaceBytes: 16}).Build(context.Background(), source, uuid.New(), BuildCredentials{})
	if !errors.Is(err, ErrBuildWorkspaceLimit) {
		t.Fatalf("oversized checkout error=%v", err)
	}
	if _, statErr := os.Stat(dockerLog); !os.IsNotExist(statErr) {
		t.Fatalf("Docker ran for oversized checkout: %v", statErr)
	}
}

func TestEnforceWorkspaceSizeCountsOnlyRegularFiles(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "one"), []byte("1234"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(root, "directory"), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(root, "one"), filepath.Join(root, "link")); err != nil {
		t.Fatal(err)
	}
	if err := enforceWorkspaceSize(root, 4); err != nil {
		t.Fatalf("exact workspace rejected: %v", err)
	}
	if err := enforceWorkspaceSize(root, 3); err == nil {
		t.Fatal("oversized workspace was accepted")
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
	for image, want := range map[string]string{"postgres": "docker.io", "library/postgres": "docker.io", "ghcr.io/acme/api": "ghcr.io", "localhost:5000/api": "localhost:5000", "[2001:db8::1]:5000/acme/api": "[2001:db8::1]:5000"} {
		if got := RegistryHost(image); got != want {
			t.Errorf("RegistryHost(%q) = %q, want %q", image, got, want)
		}
	}
}

func TestValidateRegistryImage(t *testing.T) {
	for _, image := range []string{"postgres", "library/postgres", "ghcr.io/acme/api", "registry.example.test:5000/team/app", "localhost:5000/app", "[2001:db8::1]:5000/acme/app", "team/my_app", "team/my--app"} {
		if err := ValidateRegistryImage(image); err != nil {
			t.Errorf("ValidateRegistryImage(%q) returned %v", image, err)
		}
	}
	for _, image := range []string{"", " postgres", "postgres ", "postgres:latest", "ghcr.io/acme/app:latest", "ghcr.io/acme/app@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "ghcr.io//app", "ghcr.io/acme/app/", "ghcr.io/Acme/app", "registry.example.test:0/acme/app", "registry.example.test:65536/acme/app", "bad_label.example.test/acme/app", "localhost:/app", "team/../app"} {
		if err := ValidateRegistryImage(image); err == nil {
			t.Errorf("ValidateRegistryImage(%q) unexpectedly succeeded", image)
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

func TestDockerConfigRejectsUnscopedRegistryCredentials(t *testing.T) {
	for _, credential := range []Credential{
		{Kind: "git", Server: "registry.example.test", Username: "robot", Secret: "secret"},
		{Kind: "registry", Server: "https://registry.example.test", Username: "robot", Secret: "secret"},
		{Kind: "registry", Server: "registry.example.test/path", Username: "robot", Secret: "secret"},
		{Kind: "registry", Server: "registry.example.test", Username: "robot:admin", Secret: "secret"},
		{Kind: "registry", Server: "registry.example.test", Username: "robot", Secret: "secret\x00suffix"},
	} {
		if directory, err := writeDockerConfig(credential); err == nil {
			_ = os.RemoveAll(directory)
			t.Fatalf("unsafe registry credential was accepted: %#v", credential)
		}
	}
}

func TestBuildRejectsCredentialHostMismatchBeforeClone(t *testing.T) {
	source := store.ApplicationSource{RepositoryURL: "https://github.com/acme/app.git", GitRef: "main", ContextDirectory: ".", Dockerfile: "Dockerfile", RegistryImage: "ghcr.io/acme/app"}
	_, _, err := (Builder{}).Build(context.Background(), source, uuid.New(), BuildCredentials{Git: Credential{Server: "gitlab.com", Username: "robot", Secret: "secret"}})
	if err == nil || !strings.Contains(err.Error(), "does not match") {
		t.Fatalf("expected host mismatch, got %v", err)
	}
}

func TestBuildRejectsCredentialPortMismatchBeforeClone(t *testing.T) {
	source := store.ApplicationSource{RepositoryURL: "https://git.example.test:8443/acme/app.git", GitRef: "main", ContextDirectory: ".", Dockerfile: "Dockerfile", RegistryImage: "ghcr.io/acme/app"}
	_, _, err := (Builder{}).Build(context.Background(), source, uuid.New(), BuildCredentials{Git: Credential{Kind: "git", Server: "git.example.test:9443", Username: "robot", Secret: "secret"}})
	if err == nil || !strings.Contains(err.Error(), "authority") {
		t.Fatalf("expected authority mismatch, got %v", err)
	}
}

func TestGitCredentialHelperMatchesExactProtocolAndAuthority(t *testing.T) {
	helper, err := writeCredentialHelper()
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(helper)
	run := func(protocol, host string) string {
		t.Helper()
		command := exec.Command(helper, "get")
		command.Env = append(os.Environ(), "DOCKYARD_GIT_AUTHORITY=git.example.test:8443", "DOCKYARD_GIT_USERNAME=robot", "DOCKYARD_GIT_SECRET=secret")
		command.Stdin = strings.NewReader("protocol=" + protocol + "\nhost=" + host + "\n\n")
		output, runErr := command.Output()
		if runErr != nil {
			t.Fatal(runErr)
		}
		return string(output)
	}
	if output := run("https", "git.example.test:8443"); output != "username=robot\npassword=secret\n\n" {
		t.Fatalf("exact credential output = %q", output)
	}
	git := exec.Command("git", "-c", "credential.helper=!"+helper, "credential", "fill")
	git.Env = append(os.Environ(), "GIT_TERMINAL_PROMPT=0", "DOCKYARD_GIT_AUTHORITY=git.example.test:8443", "DOCKYARD_GIT_USERNAME=robot", "DOCKYARD_GIT_SECRET=secret")
	git.Stdin = strings.NewReader("protocol=https\nhost=git.example.test:8443\n\n")
	output, err := git.Output()
	if err != nil || !strings.Contains(string(output), "username=robot\n") || !strings.Contains(string(output), "password=secret\n") {
		t.Fatalf("Git did not invoke the credential helper correctly: output=%q err=%v", output, err)
	}
	for _, attempt := range []struct{ protocol, host string }{{"https", "git.example.test.attacker:8443"}, {"https", "git.example.test:9443"}, {"http", "git.example.test:8443"}} {
		if output := run(attempt.protocol, attempt.host); output != "" {
			t.Errorf("credential helper disclosed credentials for %#v: %q", attempt, output)
		}
	}
}

func TestBuildRejectsUnsafeHTTPSCredentialMaterial(t *testing.T) {
	source := store.ApplicationSource{RepositoryURL: "https://git.example.test/acme/app.git", GitRef: "main", ContextDirectory: ".", Dockerfile: "Dockerfile", RegistryImage: "ghcr.io/acme/app"}
	for _, credential := range []Credential{
		{Kind: "git", Server: "git.example.test", Username: "", Secret: "secret"},
		{Kind: "git", Server: "git.example.test", Username: "robot\nusername=attacker", Secret: "secret"},
		{Kind: "git", Server: "git.example.test", Username: "robot", Secret: "secret\npassword=attacker"},
	} {
		if _, _, err := (Builder{}).Build(context.Background(), source, uuid.New(), BuildCredentials{Git: credential}); err == nil || !strings.Contains(err.Error(), "invalid username or secret") {
			t.Errorf("unsafe credential %#v returned %v", credential, err)
		}
	}
}

func TestValidateGitSourceRejectsUnsafeURLsAndRefs(t *testing.T) {
	for _, repository := range []string{
		"http://git.example.test/acme/app.git",
		"https://user@git.example.test/acme/app.git",
		"ssh://git:password@git.example.test/acme/app.git",
		"https://bad_label.example.test/acme/app.git",
		"https://git.example.test:0/acme/app.git",
		"https://git.example.test/acme//app.git",
		"https://git.example.test/acme/../app.git",
		"https://git.example.test/%2e%2e/app.git",
		"https://git.example.test",
		" https://git.example.test/acme/app.git",
	} {
		if _, err := ValidateGitSource(repository, "main"); err == nil {
			t.Errorf("unsafe repository URL %q was accepted", repository)
		}
	}
	for _, ref := range []string{"", ".hidden", "feature..branch", "refs//heads/main", "branch.lock", "feature@{one", "feature branch"} {
		if _, err := ValidateGitSource("https://git.example.test/acme/app.git", ref); err == nil {
			t.Errorf("unsafe Git ref %q was accepted", ref)
		}
	}
	for _, repository := range []string{"https://git.example.test/acme/app.git", "ssh://git@git.example.test:2222/acme/app.git"} {
		if _, err := ValidateGitSource(repository, "refs/heads/main"); err != nil {
			t.Errorf("valid repository %q was rejected: %v", repository, err)
		}
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

func TestRailpackUsesFrontendAndFileBackedSecrets(t *testing.T) {
	directory := t.TempDir()
	gitPath, railpackPath, dockerPath := filepath.Join(directory, "git"), filepath.Join(directory, "railpack"), filepath.Join(directory, "docker")
	logPath := filepath.Join(directory, "calls")
	t.Setenv("DOCKYARD_BUILD_TEST_LOG", logPath)
	gitScript := "#!/bin/sh\nfor destination do :; done\nmkdir -p \"$destination\"\n"
	railpackScript := "#!/bin/sh\nprintf 'railpack:%s\\n' \"$*\" >>\"$DOCKYARD_BUILD_TEST_LOG\"\nprintf 'malicious output: %s\\n' \"$NPM_TOKEN\"\nprevious=''\nfor value do\n  if [ \"$previous\" = '--plan-out' ]; then printf '{}\\n' >\"$value\"; fi\n  previous=$value\ndone\n"
	dockerScript := "#!/bin/sh\nprintf 'docker:%s\\n' \"$*\" >>\"$DOCKYARD_BUILD_TEST_LOG\"\n"
	for path, content := range map[string]string{gitPath: gitScript, railpackPath: railpackScript, dockerPath: dockerScript} {
		if err := os.WriteFile(path, []byte(content), 0700); err != nil {
			t.Fatal(err)
		}
	}
	source := store.ApplicationSource{RepositoryURL: "https://git.example.test/acme/app.git", GitRef: "main", ContextDirectory: ".", BuildType: "railpack", RegistryImage: "registry.example.test/acme/app", BuildArguments: map[string]string{"NODE_VERSION": "24"}, BuildSecrets: map[string]string{"NPM_TOKEN": "never-log-this"}}
	_, output, err := (Builder{GitBin: gitPath, RailpackBin: railpackPath, DockerBin: dockerPath}).Build(context.Background(), source, uuid.New(), BuildCredentials{})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(output, "never-log-this") || !strings.Contains(output, "[REDACTED]") {
		t.Fatalf("Railpack output was not redacted: %s", output)
	}
	data, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatal(err)
	}
	calls := string(data)
	for _, expected := range []string{"railpack:prepare ", "--env NODE_VERSION", "--env NPM_TOKEN", "BUILDKIT_SYNTAX=" + defaultRailpackFrontend, "--secret id=NPM_TOKEN,src=", "--push"} {
		if !strings.Contains(calls, expected) {
			t.Errorf("calls omit %q:\n%s", expected, calls)
		}
	}
	if strings.Contains(calls, "never-log-this") {
		t.Fatal("Railpack secret leaked into process arguments")
	}
	marker := "id=NPM_TOKEN,src="
	start := strings.Index(calls, marker)
	if start < 0 {
		t.Fatal("Railpack secret mount argument missing")
	}
	secretPath := strings.Fields(calls[start+len(marker):])[0]
	if _, err := os.Stat(secretPath); !os.IsNotExist(err) {
		t.Fatalf("temporary Railpack secret was not removed: %v", err)
	}
}

func TestBuildpacksUsesPinnedBuilderAndPublish(t *testing.T) {
	directory := t.TempDir()
	gitPath, packPath := filepath.Join(directory, "git"), filepath.Join(directory, "pack")
	logPath := filepath.Join(directory, "calls")
	t.Setenv("DOCKYARD_BUILD_TEST_LOG", logPath)
	gitScript := "#!/bin/sh\nfor destination do :; done\nmkdir -p \"$destination\"\n"
	packScript := "#!/bin/sh\nprintf '%s\\n' \"$*\" >\"$DOCKYARD_BUILD_TEST_LOG\"\n"
	for path, content := range map[string]string{gitPath: gitScript, packPath: packScript} {
		if err := os.WriteFile(path, []byte(content), 0700); err != nil {
			t.Fatal(err)
		}
	}
	source := store.ApplicationSource{RepositoryURL: "https://git.example.test/acme/app.git", GitRef: "main", ContextDirectory: ".", BuildType: "buildpacks", RegistryImage: "registry.example.test/acme/app", BuildArguments: map[string]string{"BP_JVM_VERSION": "21"}}
	if _, _, err := (Builder{GitBin: gitPath, PackBin: packPath}).Build(context.Background(), source, uuid.New(), BuildCredentials{}); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatal(err)
	}
	arguments := string(data)
	for _, expected := range []string{"build registry.example.test/acme/app:", "--builder " + defaultBuildpackBuilder, "--publish", "--trust-builder", "--env BP_JVM_VERSION"} {
		if !strings.Contains(arguments, expected) {
			t.Errorf("pack arguments omit %q:\n%s", expected, arguments)
		}
	}
	if strings.Contains(arguments, "BP_JVM_VERSION=21") {
		t.Fatal("buildpack environment value leaked into process arguments")
	}
	if err := ValidateBuildMode("buildpacks", "", "", store.ApplicationBuildConfig{Secrets: map[string]string{"TOKEN": "secret"}}); err == nil {
		t.Fatal("expected buildpack secrets to be rejected")
	}
	source.BuildType = "heroku_buildpacks"
	source.BuildArguments = map[string]string{"NODE_ENV": "production"}
	if _, _, err = (Builder{GitBin: gitPath, PackBin: packPath}).Build(context.Background(), source, uuid.New(), BuildCredentials{}); err != nil {
		t.Fatal(err)
	}
	data, err = os.ReadFile(logPath)
	if err != nil || !strings.Contains(string(data), "--builder "+defaultHerokuBuilder) {
		t.Fatalf("Heroku build did not use its pinned builder: %s, %v", data, err)
	}
	customBuilder := "registry.example.test/builders/custom:v1@sha256:" + strings.Repeat("a", 64)
	source.BuildType, source.BuilderImage = "buildpacks", customBuilder
	if _, _, err = (Builder{GitBin: gitPath, PackBin: packPath}).Build(context.Background(), source, uuid.New(), BuildCredentials{}); err != nil {
		t.Fatal(err)
	}
	data, err = os.ReadFile(logPath)
	if err != nil || !strings.Contains(string(data), "--builder "+customBuilder) {
		t.Fatalf("custom CNB build did not use configured builder: %s, %v", data, err)
	}
	if err = ValidateBuildpackBuilder("buildpacks", "heroku/builder:24"); err == nil {
		t.Fatal("expected mutable custom builder tag to be rejected")
	}
	if err = ValidateBuildpackBuilder("dockerfile", customBuilder); err == nil {
		t.Fatal("expected custom builder on Dockerfile build to be rejected")
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

func TestBuildCommandOutputModesAreBounded(t *testing.T) {
	directory := t.TempDir()
	command := filepath.Join(directory, "build-tool")
	if err := os.WriteFile(command, []byte("#!/bin/sh\nyes x | head -c 1100000\n"), 0700); err != nil {
		t.Fatal(err)
	}
	strict, err := run(context.Background(), command, nil)
	if err == nil || !strings.Contains(err.Error(), "output exceeded") || len(strict) > maxDockerCommandOutputBytes || !strings.HasSuffix(strict, dockerOutputTruncatedMarker) {
		t.Fatalf("strict bytes=%d err=%v", len(strict), err)
	}
	verbose, err := runVerbose(context.Background(), command, nil)
	if err != nil || len(verbose) > maxDockerCommandOutputBytes || !strings.HasSuffix(verbose, dockerOutputTruncatedMarker) {
		t.Fatalf("verbose bytes=%d err=%v", len(verbose), err)
	}
}
