package deploy

import (
	"bytes"
	"context"
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

var safeRef = regexp.MustCompile(`^[A-Za-z0-9._/-]{1,200}$`)
var registryImage = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:/-]{0,254}$`)

func (b Builder) Build(ctx context.Context, source store.ApplicationSource, deploymentID uuid.UUID) (string, string, error) {
	repo, err := url.Parse(source.RepositoryURL)
	if err != nil || repo.Scheme != "https" || repo.Host == "" || repo.User != nil {
		return "", "", fmt.Errorf("repository URL must use HTTPS")
	}
	if !safeRef.MatchString(source.GitRef) {
		return "", "", fmt.Errorf("invalid git ref")
	}
	if !registryImage.MatchString(source.RegistryImage) || strings.Contains(source.RegistryImage, "..") {
		return "", "", fmt.Errorf("invalid registry image")
	}
	directory, err := os.MkdirTemp("", "dockyard-build-*")
	if err != nil {
		return "", "", err
	}
	defer os.RemoveAll(directory)
	output, err := run(ctx, b.git(), nil, "clone", "--depth", "1", "--branch", source.GitRef, "--", source.RepositoryURL, directory)
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
	buildOutput, err := run(ctx, b.docker(), nil, "buildx", "build", "--pull", "--push", "--tag", tag, "--file", dockerfilePath, contextPath)
	return tag, output + buildOutput, err
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
