package deploy

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"github.com/bendahma/dokploy-go/internal/netpolicy"
	"github.com/bendahma/dokploy-go/internal/ociref"
	"github.com/bendahma/dokploy-go/internal/store"
	"github.com/google/uuid"
	"gopkg.in/yaml.v3"
)

type Builder struct {
	GitBin, DockerBin, NixpacksBin, RailpackBin, PackBin, RailpackFrontend, BuildpackBuilder, HerokuBuilder, StaticImage string
	EgressPolicy                                                                                                         *netpolicy.Policy
	MaxWorkspaceBytes                                                                                                    int64
}

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
var buildSettingName = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]{0,127}$`)
var buildTargetName = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$`)

const (
	maxGitRepositoryURLBytes  = 16 << 10
	maxGitRepositoryPathBytes = 4 << 10
)

// ErrBuildWorkspaceLimit lets callers distinguish an operator-configured
// safety-limit rejection from an ordinary build failure without parsing an
// error string.
var ErrBuildWorkspaceLimit = errors.New("build workspace exceeds configured limit")

const defaultStaticImage = "caddy:2.10.2-alpine@sha256:4c6e91c6ed0e2fa03efd5b44747b625fec79bc9cd06ac5235a779726618e530d"
const defaultRailpackFrontend = "ghcr.io/railwayapp/railpack-frontend:v0.38.0@sha256:b66c90368efcf6f2966cfa504cdbde93af7ba6092d676e0c7604cbc5ddf3acec"
const defaultBuildpackBuilder = "paketobuildpacks/builder-jammy-base:0.4.629@sha256:129bda8835db00b4fe0b2fdf0a545e493f6f0403cbeb9f89ea6125a7a93a69d0"
const defaultHerokuBuilder = "heroku/builder:24@sha256:c855fe9810b29dc60e0a0b1ddbbdd815ea5973c9dd754bf539218296fe3f4af2"
const defaultMaxBuildWorkspaceBytes int64 = 2 << 30

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

func ValidateBuildMode(buildType, outputDirectory, target string, config store.ApplicationBuildConfig) error {
	if buildType == "" {
		buildType = "dockerfile"
	}
	if buildType != "dockerfile" && buildType != "static" && buildType != "nixpacks" && buildType != "railpack" && buildType != "buildpacks" && buildType != "heroku_buildpacks" {
		return fmt.Errorf("unsupported build type %q", buildType)
	}
	if err := ValidateBuildSettings(target, config); err != nil {
		return err
	}
	if buildType == "static" {
		if target != "" || len(config.Arguments) > 0 || len(config.Secrets) > 0 {
			return errors.New("static builds do not accept Docker targets, arguments, or secrets")
		}
		if outputDirectory == "" || outputDirectory == "." || filepath.IsAbs(outputDirectory) {
			return errors.New("static builds require a relative output directory")
		}
		clean := filepath.Clean(outputDirectory)
		if clean == ".." || strings.HasPrefix(clean, ".."+string(filepath.Separator)) {
			return errors.New("static output directory must stay inside the build context")
		}
	}
	if buildType == "nixpacks" {
		if target != "" || outputDirectory != "" {
			return errors.New("Nixpacks builds do not accept Docker targets or static output directories")
		}
		if len(config.Secrets) > 0 {
			return errors.New("Nixpacks build secrets are not supported because its CLI cannot provide BuildKit secret mounts")
		}
	}
	if buildType == "railpack" && (target != "" || outputDirectory != "") {
		return errors.New("Railpack builds do not accept Docker targets or static output directories")
	}
	if buildType == "buildpacks" || buildType == "heroku_buildpacks" {
		if target != "" || outputDirectory != "" {
			return errors.New("buildpack builds do not accept Docker targets or static output directories")
		}
		if len(config.Secrets) > 0 {
			return errors.New("buildpack secrets are not supported because the lifecycle does not guarantee ephemeral secret mounts")
		}
	}
	return nil
}

func ValidateBuildpackBuilder(buildType, builder string) error {
	if builder == "" {
		return nil
	}
	if buildType != "buildpacks" && buildType != "heroku_buildpacks" {
		return errors.New("custom builder images are only supported for buildpack builds")
	}
	if !ociref.IsDigestPinned(builder) {
		return errors.New("custom buildpack builder image must be pinned by sha256 digest")
	}
	return nil
}

func (b Builder) Build(ctx context.Context, source store.ApplicationSource, deploymentID uuid.UUID, credentials BuildCredentials) (string, string, error) {
	if err := validateBuildSource(&source, credentials.Registry); err != nil {
		return "", "", err
	}
	repo, err := ValidateGitSource(source.RepositoryURL, source.GitRef)
	if err != nil {
		return "", "", err
	}
	credentialAuthority := gitCredentialServerAuthority(credentials.Git.Server)
	if credentials.Git.Secret != "" && (credentialAuthority == "" || !strings.EqualFold(repo.Host, credentialAuthority)) {
		return "", "", fmt.Errorf("Git credential server does not match repository authority")
	}
	resolvedAddresses := []string(nil)
	if b.EgressPolicy != nil {
		addresses, resolveErr := b.EgressPolicy.ResolveHost(ctx, repo.Hostname())
		if resolveErr != nil {
			err = resolveErr
			return "", "", fmt.Errorf("repository URL violates egress policy: %w", err)
		}
		for _, address := range addresses {
			value := address.String()
			if address.Is6() {
				value = "[" + value + "]"
			}
			resolvedAddresses = append(resolvedAddresses, value)
		}
	}
	directory, err := os.MkdirTemp("", "dockyard-build-*")
	if err != nil {
		return "", "", err
	}
	defer os.RemoveAll(directory)
	gitEnvironment := map[string]string{"GIT_TERMINAL_PROMPT": "0"}
	if len(resolvedAddresses) > 0 && repo.Scheme == "https" {
		port := repo.Port()
		if port == "" {
			port = "443"
		}
		gitEnvironment["GIT_CONFIG_COUNT"] = "1"
		gitEnvironment["GIT_CONFIG_KEY_0"] = "http.curloptResolve"
		gitEnvironment["GIT_CONFIG_VALUE_0"] = repo.Hostname() + ":" + port + ":" + strings.Join(resolvedAddresses, ",")
	}
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
		if len(resolvedAddresses) > 0 {
			gitEnvironment["GIT_SSH_COMMAND"] += " -o HostName=" + strings.Trim(resolvedAddresses[0], "[]") + " -o HostKeyAlias=" + repo.Hostname()
		}
	} else if credentials.Git.Secret != "" {
		if credentials.Git.Kind != "git" {
			return "", "", errors.New("HTTPS repository requires a Git token credential")
		}
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
	output, err := runVerbose(ctx, b.git(), gitEnvironment, "clone", "--depth", "1", "--branch", source.GitRef, "--", source.RepositoryURL, directory)
	if err != nil {
		return "", output, err
	}
	if err = enforceWorkspaceSize(directory, b.maxWorkspaceBytes()); err != nil {
		return "", output, err
	}
	if source.EnableSubmodules {
		submoduleOutput, submoduleErr := b.updateSubmodules(ctx, directory, repo, gitEnvironment)
		output += submoduleOutput
		if submoduleErr != nil {
			return "", output, submoduleErr
		}
		if err = enforceWorkspaceSize(directory, b.maxWorkspaceBytes()); err != nil {
			return "", output, err
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
	return b.buildWorkspace(ctx, source, deploymentID, credentials.Registry, contextPath, output)
}

func ValidateGitSource(repositoryURL, gitRef string) (*url.URL, error) {
	if repositoryURL == "" || repositoryURL != strings.TrimSpace(repositoryURL) || len(repositoryURL) > maxGitRepositoryURLBytes || strings.ContainsAny(repositoryURL, "\x00\r\n") {
		return nil, errors.New("repository URL must use HTTPS or SSH with a valid host and path")
	}
	repository, err := url.Parse(repositoryURL)
	if err != nil || (repository.Scheme != "https" && repository.Scheme != "ssh") || !netpolicy.ValidURLHost(repository) || repository.RawQuery != "" || repository.Fragment != "" || repository.Opaque != "" || repository.RawPath != "" {
		return nil, errors.New("repository URL must use HTTPS or SSH with a valid host and path")
	}
	if repository.Scheme == "https" && repository.User != nil {
		return nil, errors.New("HTTPS repository URL cannot contain user information")
	}
	if repository.User != nil {
		_, hasPassword := repository.User.Password()
		if repository.User.Username() == "" || hasPassword {
			return nil, errors.New("SSH repository URL cannot contain embedded credentials")
		}
	}
	repositoryPath := strings.Trim(repository.Path, "/")
	parts := strings.Split(repositoryPath, "/")
	if repositoryPath == "" || len(repositoryPath) > maxGitRepositoryPathBytes || strings.Contains(repository.Path, "//") || strings.IndexFunc(repositoryPath, func(char rune) bool { return char < 0x20 || char == 0x7f }) >= 0 || path.Clean("/"+repositoryPath) != "/"+repositoryPath {
		return nil, errors.New("repository URL must contain a canonical repository path")
	}
	for _, part := range parts {
		if part == "" || part == "." || part == ".." || len(part) > 255 {
			return nil, errors.New("repository URL contains an invalid path segment")
		}
	}
	if !validGitRef(gitRef) {
		return nil, errors.New("invalid git ref")
	}
	return repository, nil
}

func validGitRef(ref string) bool {
	if !safeRef.MatchString(ref) || ref == "@" || strings.HasPrefix(ref, ".") || strings.HasSuffix(ref, ".") || strings.HasSuffix(ref, "/") || strings.HasSuffix(ref, ".lock") || strings.Contains(ref, "..") || strings.Contains(ref, "@{") || strings.Contains(ref, "//") {
		return false
	}
	return strings.IndexFunc(ref, func(char rune) bool { return char < 0x20 || char == 0x7f }) < 0
}

func gitCredentialServerAuthority(server string) string {
	endpoint, err := url.Parse("https://" + strings.TrimSpace(server))
	if err != nil || !netpolicy.ValidURLHost(endpoint) || endpoint.User != nil || endpoint.Path != "" || endpoint.RawQuery != "" || endpoint.Fragment != "" || endpoint.Opaque != "" {
		return ""
	}
	return strings.ToLower(endpoint.Host)
}

func (b Builder) maxWorkspaceBytes() int64 {
	if b.MaxWorkspaceBytes > 0 {
		return b.MaxWorkspaceBytes
	}
	return defaultMaxBuildWorkspaceBytes
}

func enforceWorkspaceSize(root string, limit int64) error {
	if limit <= 0 {
		return errors.New("build workspace limit must be positive")
	}
	var size int64
	err := filepath.WalkDir(root, func(path string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if !entry.Type().IsRegular() {
			return nil
		}
		info, err := entry.Info()
		if err != nil {
			return err
		}
		if info.Size() > limit-size {
			return fmt.Errorf("%w of %d bytes", ErrBuildWorkspaceLimit, limit)
		}
		size += info.Size()
		return nil
	})
	if err != nil {
		return fmt.Errorf("inspect build workspace: %w", err)
	}
	return nil
}

func (b Builder) BuildArchive(ctx context.Context, source store.ApplicationSource, deploymentID uuid.UUID, registryCredential Credential, archive []byte) (string, string, error) {
	if err := validateBuildSource(&source, registryCredential); err != nil {
		return "", "", err
	}
	directory, err := os.MkdirTemp("", "dockyard-drop-*")
	if err != nil {
		return "", "", err
	}
	defer os.RemoveAll(directory)
	if err = ExtractArchive(archive, directory); err != nil {
		return "", "", fmt.Errorf("invalid source archive: %w", err)
	}
	if err = enforceWorkspaceSize(directory, b.maxWorkspaceBytes()); err != nil {
		return "", "", err
	}
	contextPath, err := safeJoin(directory, source.ContextDirectory)
	if err != nil {
		return "", "", err
	}
	contextPath, err = resolveInside(directory, contextPath)
	if err != nil {
		return "", "", fmt.Errorf("invalid build context: %w", err)
	}
	return b.buildWorkspace(ctx, source, deploymentID, registryCredential, contextPath, "")
}

func validateBuildSource(source *store.ApplicationSource, registryCredential Credential) error {
	if source.BuildType == "" {
		source.BuildType = "dockerfile"
	}
	if err := ValidateBuildMode(source.BuildType, source.OutputDirectory, source.BuildTarget, store.ApplicationBuildConfig{Arguments: source.BuildArguments, Secrets: source.BuildSecrets}); err != nil {
		return err
	}
	if err := ValidateRegistryImage(source.RegistryImage); err != nil {
		return err
	}
	if registryCredential.Secret != "" && !strings.EqualFold(RegistryHost(source.RegistryImage), registryCredential.Server) {
		return errors.New("registry credential server does not match image registry")
	}
	if err := ValidateBuildpackBuilder(source.BuildType, source.BuilderImage); err != nil {
		return err
	}
	return nil
}

func (b Builder) buildWorkspace(ctx context.Context, source store.ApplicationSource, deploymentID uuid.UUID, registryCredential Credential, contextPath, output string) (string, string, error) {
	tag := source.RegistryImage + ":" + deploymentID.String()
	buildEnvironment := map[string]string{}
	if registryCredential.Secret != "" {
		configDir, configErr := writeDockerConfig(registryCredential)
		if configErr != nil {
			return "", output, configErr
		}
		defer os.RemoveAll(configDir)
		buildEnvironment["DOCKER_CONFIG"] = configDir
	}
	if source.BuildType == "static" {
		buildOutput, buildErr := b.buildStatic(ctx, contextPath, source.OutputDirectory, tag, buildEnvironment)
		return tag, output + buildOutput, buildErr
	}
	if source.BuildType == "nixpacks" {
		buildOutput, buildErr := b.buildNixpacks(ctx, contextPath, tag, buildEnvironment, source.BuildArguments)
		return tag, output + buildOutput, buildErr
	}
	if source.BuildType == "railpack" {
		buildOutput, buildErr := b.buildRailpack(ctx, contextPath, tag, deploymentID, buildEnvironment, source.BuildArguments, source.BuildSecrets)
		return tag, output + buildOutput, buildErr
	}
	if source.BuildType == "buildpacks" {
		buildOutput, buildErr := b.buildBuildpacks(ctx, contextPath, tag, source.BuilderImage, b.paketoBuilder(), buildEnvironment, source.BuildArguments)
		return tag, output + buildOutput, buildErr
	}
	if source.BuildType == "heroku_buildpacks" {
		buildOutput, buildErr := b.buildBuildpacks(ctx, contextPath, tag, source.BuilderImage, b.herokuBuilder(), buildEnvironment, source.BuildArguments)
		return tag, output + buildOutput, buildErr
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
	buildOutput, err := runVerbose(ctx, b.docker(), buildEnvironment, buildArgs...)
	return tag, redactBuildText(output+buildOutput, source.BuildSecrets), redactBuildError(err, source.BuildSecrets)
}

func (b Builder) buildNixpacks(ctx context.Context, contextPath, tag string, environment map[string]string, buildArguments map[string]string) (string, error) {
	arguments := []string{"build", contextPath, "--name", tag}
	for _, name := range sortedKeys(buildArguments) {
		// Nixpacks calls these environment variables; like Docker build args,
		// they are explicitly non-secret and may enter image metadata.
		arguments = append(arguments, "--env", name+"="+buildArguments[name])
	}
	output, err := runVerbose(ctx, b.nixpacks(), environment, arguments...)
	if err != nil {
		return output, err
	}
	pushOutput, err := runVerbose(ctx, b.docker(), environment, "push", tag)
	return output + pushOutput, err
}

func (b Builder) buildRailpack(ctx context.Context, contextPath, tag string, deploymentID uuid.UUID, environment map[string]string, buildArguments, buildSecrets map[string]string) (string, error) {
	frontend := b.RailpackFrontend
	if frontend == "" {
		frontend = defaultRailpackFrontend
	}
	if !ociref.IsDigestPinned(frontend) {
		return "", errors.New("Railpack frontend image must be pinned by sha256 digest")
	}
	plan, err := os.CreateTemp("", "dockyard-railpack-plan-*.json")
	if err != nil {
		return "", err
	}
	planPath := plan.Name()
	if err = plan.Close(); err != nil {
		os.Remove(planPath)
		return "", err
	}
	defer os.Remove(planPath)
	variables := make(map[string]string, len(buildArguments)+len(buildSecrets))
	for name, value := range buildArguments {
		variables[name] = value
	}
	for name, value := range buildSecrets {
		variables[name] = value
	}
	prepareEnvironment := make(map[string]string, len(environment)+len(variables))
	for name, value := range environment {
		prepareEnvironment[name] = value
	}
	prepareArguments := []string{"prepare", contextPath, "--plan-out", planPath, "--hide-pretty-plan"}
	for _, name := range sortedKeys(variables) {
		prepareEnvironment[name] = variables[name]
		prepareArguments = append(prepareArguments, "--env", name)
	}
	output, err := runVerbose(ctx, b.railpack(), prepareEnvironment, prepareArguments...)
	if err != nil {
		return redactBuildText(output, buildSecrets), redactBuildError(err, buildSecrets)
	}
	secretDirectory, err := writeBuildSecrets(variables)
	if err != nil {
		return output, err
	}
	if secretDirectory != "" {
		defer os.RemoveAll(secretDirectory)
	}
	hash := sha256.New()
	for _, name := range sortedKeys(variables) {
		hash.Write([]byte(name))
		hash.Write([]byte{0})
		hash.Write([]byte(variables[name]))
		hash.Write([]byte{0})
	}
	buildArgumentsCLI := []string{"buildx", "build", "--pull", "--push", "--tag", tag, "--file", planPath, "--build-arg", "BUILDKIT_SYNTAX=" + frontend, "--build-arg", "cache-key=" + deploymentID.String(), "--build-arg", "secrets-hash=" + fmt.Sprintf("%x", hash.Sum(nil))}
	for _, name := range sortedKeys(variables) {
		buildArgumentsCLI = append(buildArgumentsCLI, "--secret", "id="+name+",src="+filepath.Join(secretDirectory, name))
	}
	buildArgumentsCLI = append(buildArgumentsCLI, contextPath)
	buildOutput, err := runVerbose(ctx, b.docker(), environment, buildArgumentsCLI...)
	return redactBuildText(output+buildOutput, buildSecrets), redactBuildError(err, buildSecrets)
}

func (b Builder) buildBuildpacks(ctx context.Context, contextPath, tag, configuredBuilder, defaultBuilder string, environment, buildArguments map[string]string) (string, error) {
	builder := configuredBuilder
	if builder == "" {
		builder = defaultBuilder
	}
	if !ociref.IsDigestPinned(builder) {
		return "", errors.New("buildpack builder image must be pinned by sha256 digest")
	}
	buildEnvironment := make(map[string]string, len(environment)+len(buildArguments))
	for name, value := range environment {
		buildEnvironment[name] = value
	}
	arguments := []string{"build", tag, "--path", contextPath, "--builder", builder, "--publish", "--trust-builder"}
	for _, name := range sortedKeys(buildArguments) {
		buildEnvironment[name] = buildArguments[name]
		arguments = append(arguments, "--env", name)
	}
	return runVerbose(ctx, b.pack(), buildEnvironment, arguments...)
}

func (b Builder) paketoBuilder() string {
	if b.BuildpackBuilder != "" {
		return b.BuildpackBuilder
	}
	return defaultBuildpackBuilder
}

func (b Builder) herokuBuilder() string {
	if b.HerokuBuilder != "" {
		return b.HerokuBuilder
	}
	return defaultHerokuBuilder
}

func redactBuildText(value string, secrets map[string]string) string {
	for _, secret := range secrets {
		if secret != "" {
			value = strings.ReplaceAll(value, secret, "[REDACTED]")
		}
	}
	return value
}

func redactBuildError(err error, secrets map[string]string) error {
	if err == nil {
		return nil
	}
	return errors.New(redactBuildText(err.Error(), secrets))
}

func (b Builder) buildStatic(ctx context.Context, contextPath, outputDirectory, tag string, environment map[string]string) (string, error) {
	outputPath, err := safeJoin(contextPath, outputDirectory)
	if err != nil {
		return "", err
	}
	outputPath, err = resolveInside(contextPath, outputPath)
	if err != nil {
		return "", fmt.Errorf("invalid static output directory: %w", err)
	}
	info, err := os.Stat(outputPath)
	if err != nil || !info.IsDir() {
		return "", errors.New("static output directory must be a directory")
	}
	image := b.StaticImage
	if image == "" {
		image = defaultStaticImage
	}
	if !ociref.IsDigestPinned(image) {
		return "", errors.New("static runtime image must be pinned by sha256 digest")
	}
	dockerfile, err := os.CreateTemp("", "dockyard-static-*.Dockerfile")
	if err != nil {
		return "", err
	}
	dockerfilePath := dockerfile.Name()
	defer os.Remove(dockerfilePath)
	definition := "FROM " + image + "\nCOPY . /srv\nEXPOSE 80\nCMD [\"caddy\",\"file-server\",\"--root\",\"/srv\",\"--listen\",\":80\"]\n"
	if _, err = dockerfile.WriteString(definition); err != nil {
		dockerfile.Close()
		return "", err
	}
	if err = dockerfile.Chmod(0600); err != nil {
		dockerfile.Close()
		return "", err
	}
	if err = dockerfile.Close(); err != nil {
		return "", err
	}
	return runVerbose(ctx, b.docker(), environment, "buildx", "build", "--pull", "--push", "--tag", tag, "--file", dockerfilePath, outputPath)
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
	updated, err := runVerbose(ctx, b.git(), environment, "-C", directory, "-c", "protocol.allow=never", "-c", "protocol."+repository.Scheme+".allow=always", "submodule", "update", "--init", "--recursive", "--depth", "1")
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

func ValidateRegistryImage(image string) error {
	if _, err := ociref.ParseRepository(image); err != nil {
		return errors.New("invalid registry image")
	}
	return nil
}

func RegistryHost(image string) string {
	reference, err := ociref.ParseRepository(image)
	if err != nil {
		return ""
	}
	return reference.Registry
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

func (b Builder) nixpacks() string {
	if b.NixpacksBin == "" {
		return "nixpacks"
	}
	return b.NixpacksBin
}
func (b Builder) railpack() string {
	if b.RailpackBin == "" {
		return "railpack"
	}
	return b.RailpackBin
}
func (b Builder) pack() string {
	if b.PackBin == "" {
		return "pack"
	}
	return b.PackBin
}
func run(ctx context.Context, binary string, environment map[string]string, args ...string) (string, error) {
	return runCommand(ctx, binary, environment, false, args...)
}

func runVerbose(ctx context.Context, binary string, environment map[string]string, args ...string) (string, error) {
	return runCommand(ctx, binary, environment, true, args...)
}

func runCommand(ctx context.Context, binary string, environment map[string]string, allowTruncated bool, args ...string) (string, error) {
	cmd := exec.CommandContext(ctx, binary, args...)
	cmd.Env = os.Environ()
	for key, value := range environment {
		cmd.Env = append(cmd.Env, key+"="+value)
	}
	output := newBoundedCommandOutput(maxDockerCommandOutputBytes - len(dockerOutputTruncatedMarker))
	cmd.Stdout = output
	cmd.Stderr = output
	err := cmd.Run()
	captured := output.String()
	if output.truncated {
		captured += dockerOutputTruncatedMarker
	}
	if err != nil {
		return captured, fmt.Errorf("%s failed: %w: %s", filepath.Base(binary), err, strings.TrimSpace(captured))
	}
	if output.truncated && !allowTruncated {
		return captured, fmt.Errorf("%s output exceeded %d bytes", filepath.Base(binary), maxDockerCommandOutputBytes)
	}
	return captured, nil
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
