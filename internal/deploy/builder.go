package deploy

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"github.com/bendahma/dokploy-go/internal/store"
	"github.com/google/uuid"
	"gopkg.in/yaml.v3"
)

type Builder struct{ GitBin, DockerBin string }

type Credential struct {
	Kind       string `json:"kind"`
	Server     string `json:"server"`
	Username   string `json:"username"`
	Secret     string `json:"secret"`
	KnownHosts string `json:"knownHosts,omitempty"`
}
type BuildCredentials struct {
	Git      Credential
	Registry Credential
}

var safeRef = regexp.MustCompile(`^[A-Za-z0-9._/-]{1,200}$`)
var registryImage = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:/-]{0,254}$`)
var buildSettingName = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]{0,127}$`)
var buildTargetName = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$`)

func ValidateBuildSettings(target string, config store.ApplicationBuildConfig) error {
	if target != "" && !buildTargetName.MatchString(target) {
		return errors.New("build target must be a valid Docker stage name")
	}
	if len(config.Arguments) > 64 || len(config.Secrets) > 64 {
		return errors.New("at most 64 build arguments and 64 build secrets are allowed")
	}
	total := 0
	for kind, values := range map[string]map[string]string{"argument": config.Arguments, "secret": config.Secrets} {
		for name, value := range values {
			if !buildSettingName.MatchString(name) {
				return fmt.Errorf("build %s name %q is invalid", kind, name)
			}
			if len(value) > 64<<10 {
				return fmt.Errorf("build %s %q exceeds 64 KiB", kind, name)
			}
			total += len(name) + len(value)
		}
	}
	if total > 256<<10 {
		return errors.New("combined build configuration exceeds 256 KiB")
	}
	for name := range config.Arguments {
		if _, duplicate := config.Secrets[name]; duplicate {
			return fmt.Errorf("build setting %q cannot be both an argument and a secret", name)
		}
	}
	return nil
}

func (b Builder) Build(ctx context.Context, source store.ApplicationSource, deploymentID uuid.UUID, credentials BuildCredentials) (string, string, error) {
	if err := ValidateBuildSettings(source.BuildTarget, store.ApplicationBuildConfig{Arguments: source.BuildArguments, Secrets: source.BuildSecrets}); err != nil {
		return "", "", err
	}
	repo, err := url.Parse(source.RepositoryURL)
	if err != nil || (repo.Scheme != "https" && repo.Scheme != "ssh") || repo.Host == "" || repo.Scheme == "https" && repo.User != nil {
		return "", "", fmt.Errorf("repository URL must use HTTPS or SSH")
	}
	if !safeRef.MatchString(source.GitRef) {
		return "", "", fmt.Errorf("invalid git ref")
	}
	if !registryImage.MatchString(source.RegistryImage) || strings.Contains(source.RegistryImage, "..") {
		return "", "", fmt.Errorf("invalid registry image")
	}
	if credentials.Git.Secret != "" && !strings.EqualFold(repo.Hostname(), credentials.Git.Server) {
		return "", "", fmt.Errorf("Git credential server does not match repository host")
	}
	if credentials.Registry.Secret != "" && !strings.EqualFold(imageRegistry(source.RegistryImage), credentials.Registry.Server) {
		return "", "", fmt.Errorf("registry credential server does not match image registry")
	}
	directory, err := os.MkdirTemp("", "dockyard-build-*")
	if err != nil {
		return "", "", err
	}
	defer os.RemoveAll(directory)
	gitEnvironment := map[string]string{"GIT_TERMINAL_PROMPT": "0"}
	if repo.Scheme == "ssh" {
		if credentials.Git.Kind != "git-ssh" || credentials.Git.Secret == "" || credentials.Git.KnownHosts == "" {
			return "", "", errors.New("SSH repository requires a git-ssh credential with pinned host keys")
		}
		if repo.User == nil || repo.User.Username() != credentials.Git.Username {
			return "", "", errors.New("SSH credential username does not match repository URL")
		}
		sshDirectory, createErr := writeSSHConfig(credentials.Git)
		if createErr != nil {
			return "", "", createErr
		}
		defer os.RemoveAll(sshDirectory)
		gitEnvironment["GIT_SSH_COMMAND"] = "ssh -F /dev/null -i " + filepath.Join(sshDirectory, "key") + " -o IdentitiesOnly=yes -o StrictHostKeyChecking=yes -o UserKnownHostsFile=" + filepath.Join(sshDirectory, "known_hosts")
	} else if credentials.Git.Secret != "" {
		askPass, createErr := writeAskPass()
		if createErr != nil {
			return "", "", createErr
		}
		defer os.Remove(askPass)
		gitEnvironment["GIT_ASKPASS"] = askPass
		gitEnvironment["DOCKYARD_GIT_SERVER"] = credentials.Git.Server
		gitEnvironment["DOCKYARD_GIT_USERNAME"] = credentials.Git.Username
		gitEnvironment["DOCKYARD_GIT_SECRET"] = credentials.Git.Secret
	}
	output, err := run(ctx, b.git(), gitEnvironment, "clone", "--depth", "1", "--branch", source.GitRef, "--", source.RepositoryURL, directory)
	if err != nil {
		return "", output, err
	}
	if source.EnableSubmodules {
		submoduleOutput, submoduleErr := b.updateSubmodules(ctx, directory, repo, gitEnvironment)
		output += submoduleOutput
		if submoduleErr != nil {
			return "", output, submoduleErr
		}
	}
	contextPath, err := safeJoin(directory, source.ContextDirectory)
	if err != nil {
		return "", output, err
	}
	contextPath, err = resolveInside(directory, contextPath)
	if err != nil {
		return "", output, fmt.Errorf("invalid build context: %w", err)
	}
	dockerfilePath, err := safeJoin(contextPath, source.Dockerfile)
	if err != nil {
		return "", output, err
	}
	dockerfilePath, err = resolveInside(contextPath, dockerfilePath)
	if err != nil {
		return "", output, fmt.Errorf("invalid Dockerfile: %w", err)
	}
	info, err := os.Stat(dockerfilePath)
	if err != nil || !info.Mode().IsRegular() {
		return "", output, fmt.Errorf("Dockerfile must be a regular file")
	}
	tag := source.RegistryImage + ":" + deploymentID.String()
	buildEnvironment := map[string]string{}
	if credentials.Registry.Secret != "" {
		configDir, configErr := writeDockerConfig(credentials.Registry)
		if configErr != nil {
			return "", output, configErr
		}
		defer os.RemoveAll(configDir)
		buildEnvironment["DOCKER_CONFIG"] = configDir
	}
	buildArgs := []string{"buildx", "build", "--pull", "--push", "--tag", tag, "--file", dockerfilePath}
	if source.BuildTarget != "" {
		buildArgs = append(buildArgs, "--target", source.BuildTarget)
	}
	argumentNames := sortedKeys(source.BuildArguments)
	for _, name := range argumentNames {
		// Build arguments are explicitly non-secret and may be retained in image
		// metadata. Secret values use BuildKit's file-backed secret transport.
		buildArgs = append(buildArgs, "--build-arg", name+"="+source.BuildArguments[name])
	}
	secretDirectory, err := writeBuildSecrets(source.BuildSecrets)
	if err != nil {
		return "", output, err
	}
	if secretDirectory != "" {
		defer os.RemoveAll(secretDirectory)
		for _, name := range sortedKeys(source.BuildSecrets) {
			buildArgs = append(buildArgs, "--secret", "id="+name+",src="+filepath.Join(secretDirectory, name))
		}
	}
	buildArgs = append(buildArgs, contextPath)
	buildOutput, err := run(ctx, b.docker(), buildEnvironment, buildArgs...)
	return tag, output + buildOutput, err
}

func (b Builder) updateSubmodules(ctx context.Context, directory string, repository *url.URL, environment map[string]string) (string, error) {
	configPath := filepath.Join(directory, ".gitmodules")
	if _, err := os.Stat(configPath); errors.Is(err, os.ErrNotExist) {
		return "", nil
	} else if err != nil {
		return "", err
	}
	output, err := run(ctx, b.git(), environment, "-C", directory, "config", "--file", ".gitmodules", "--get-regexp", `^submodule\..*\.url$`)
	if err != nil {
		if strings.TrimSpace(output) == "" {
			return "", nil
		}
		return output, fmt.Errorf("read Git submodules: %w", err)
	}
	for _, line := range strings.Split(strings.TrimSpace(output), "\n") {
		_, rawURL, ok := strings.Cut(line, " ")
		if !ok || !safeSubmoduleURL(strings.TrimSpace(rawURL), repository) {
			return output, errors.New("Git submodules must use relative URLs or the source repository host and protocol")
		}
	}
	updated, err := run(ctx, b.git(), environment, "-C", directory, "-c", "protocol.allow=never", "-c", "protocol."+repository.Scheme+".allow=always", "submodule", "update", "--init", "--recursive", "--depth", "1")
	return output + updated, err
}

func safeSubmoduleURL(raw string, repository *url.URL) bool {
	if strings.HasPrefix(raw, "./") || strings.HasPrefix(raw, "../") {
		return true
	}
	parsed, err := url.Parse(raw)
	if err == nil && parsed.IsAbs() {
		if parsed.Scheme != repository.Scheme || !strings.EqualFold(parsed.Host, repository.Host) {
			return false
		}
		if parsed.Scheme == "https" {
			return parsed.User == nil
		}
		return parsed.Scheme == "ssh" && (parsed.User == nil || repository.User != nil && parsed.User.Username() == repository.User.Username())
	}
	if repository.Scheme == "ssh" {
		beforePath, _, found := strings.Cut(raw, ":")
		host := beforePath
		if at := strings.LastIndex(host, "@"); at >= 0 {
			host = host[at+1:]
		}
		return found && strings.EqualFold(host, repository.Hostname())
	}
	return false
}

func writeBuildSecrets(secrets map[string]string) (string, error) {
	if len(secrets) == 0 {
		return "", nil
	}
	directory, err := os.MkdirTemp("", "dockyard-build-secrets-*")
	if err != nil {
		return "", err
	}
	for _, name := range sortedKeys(secrets) {
		if err = os.WriteFile(filepath.Join(directory, name), []byte(secrets[name]), 0600); err != nil {
			_ = os.RemoveAll(directory)
			return "", err
		}
	}
	return directory, nil
}

func sortedKeys(values map[string]string) []string {
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}

func writeSSHConfig(credential Credential) (string, error) {
	directory, err := os.MkdirTemp("", "dockyard-ssh-*")
	if err != nil {
		return "", err
	}
	if err = os.WriteFile(filepath.Join(directory, "key"), []byte(credential.Secret), 0600); err == nil {
		err = os.WriteFile(filepath.Join(directory, "known_hosts"), []byte(credential.KnownHosts), 0600)
	}
	if err != nil {
		_ = os.RemoveAll(directory)
		return "", err
	}
	return directory, nil
}

func writeAskPass() (string, error) {
	file, err := os.CreateTemp("", "dockyard-askpass-*")
	if err != nil {
		return "", err
	}
	path := file.Name()
	content := "#!/bin/sh\ncase \"$1\" in *\"//$DOCKYARD_GIT_SERVER\"*) ;; *) exit 1 ;; esac\ncase \"$1\" in *Username*) printf '%s' \"$DOCKYARD_GIT_USERNAME\" ;; *) printf '%s' \"$DOCKYARD_GIT_SECRET\" ;; esac\n"
	if _, err = file.WriteString(content); err == nil {
		err = file.Chmod(0700)
	}
	closeErr := file.Close()
	if err == nil {
		err = closeErr
	}
	if err != nil {
		_ = os.Remove(path)
		return "", err
	}
	return path, nil
}

func writeDockerConfig(credential Credential) (string, error) {
	directory, err := os.MkdirTemp("", "dockyard-docker-config-*")
	if err != nil {
		return "", err
	}
	config := map[string]any{"auths": map[string]any{credential.Server: map[string]string{"auth": base64.StdEncoding.EncodeToString([]byte(credential.Username + ":" + credential.Secret))}}}
	data, err := json.Marshal(config)
	if err == nil {
		err = os.WriteFile(filepath.Join(directory, "config.json"), data, 0600)
	}
	if err != nil {
		_ = os.RemoveAll(directory)
		return "", err
	}
	return directory, nil
}

func imageRegistry(image string) string {
	first, _, _ := strings.Cut(image, "/")
	if strings.ContainsAny(first, ".:") || first == "localhost" {
		return strings.ToLower(first)
	}
	return "docker.io"
}
func (b Builder) git() string {
	if b.GitBin == "" {
		return "git"
	}
	return b.GitBin
}
func (b Builder) docker() string {
	if b.DockerBin == "" {
		return "docker"
	}
	return b.DockerBin
}
func run(ctx context.Context, binary string, environment map[string]string, args ...string) (string, error) {
	cmd := exec.CommandContext(ctx, binary, args...)
	cmd.Env = os.Environ()
	for key, value := range environment {
		cmd.Env = append(cmd.Env, key+"="+value)
	}
	var output bytes.Buffer
	cmd.Stdout = &output
	cmd.Stderr = &output
	err := cmd.Run()
	if err != nil {
		return output.String(), fmt.Errorf("%s failed: %w: %s", filepath.Base(binary), err, strings.TrimSpace(output.String()))
	}
	return output.String(), nil
}
func safeJoin(root, relative string) (string, error) {
	if filepath.IsAbs(relative) {
		return "", fmt.Errorf("path must be relative")
	}
	path := filepath.Clean(filepath.Join(root, relative))
	rel, err := filepath.Rel(root, path)
	if err != nil || strings.HasPrefix(rel, "..") {
		return "", fmt.Errorf("path escapes repository")
	}
	return path, nil
}

func resolveInside(root, path string) (string, error) {
	resolvedRoot, err := filepath.EvalSymlinks(root)
	if err != nil {
		return "", err
	}
	resolvedPath, err := filepath.EvalSymlinks(path)
	if err != nil {
		return "", err
	}
	relative, err := filepath.Rel(resolvedRoot, resolvedPath)
	if err != nil || relative == ".." || strings.HasPrefix(relative, ".."+string(filepath.Separator)) {
		return "", fmt.Errorf("path escapes repository")
	}
	return resolvedPath, nil
}
func SetServiceImage(compose, serviceName, image string) (string, error) {
	var doc map[string]any
	if err := yaml.Unmarshal([]byte(compose), &doc); err != nil {
		return "", err
	}
	services, ok := stringMap(doc["services"])
	if !ok {
		return "", fmt.Errorf("compose services missing")
	}
	service, ok := stringMap(services[serviceName])
	if !ok {
		return "", fmt.Errorf("target service %q missing", serviceName)
	}
	service["image"] = image
	delete(service, "build")
	services[serviceName] = service
	doc["services"] = services
	out, err := yaml.Marshal(doc)
	return string(out), err
}
