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

func (b Builder) Build(ctx context.Context, source store.ApplicationSource, deploymentID uuid.UUID, credentials BuildCredentials) (string, string, error) {
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
		gitEnvironment["DOCKYARD_GIT_USERNAME"] = credentials.Git.Username
		gitEnvironment["DOCKYARD_GIT_SECRET"] = credentials.Git.Secret
	}
	output, err := run(ctx, b.git(), gitEnvironment, "clone", "--depth", "1", "--branch", source.GitRef, "--", source.RepositoryURL, directory)
	if err != nil {
		return "", output, err
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
	buildOutput, err := run(ctx, b.docker(), buildEnvironment, "buildx", "build", "--pull", "--push", "--tag", tag, "--file", dockerfilePath, contextPath)
	return tag, output + buildOutput, err
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
	content := "#!/bin/sh\ncase \"$1\" in *Username*) printf '%s' \"$DOCKYARD_GIT_USERNAME\" ;; *) printf '%s' \"$DOCKYARD_GIT_SECRET\" ;; esac\n"
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
