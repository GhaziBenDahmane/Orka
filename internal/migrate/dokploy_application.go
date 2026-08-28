package migrate

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"path"
	"regexp"
	"sort"
	"strings"

	"github.com/bendahma/dokploy-go/internal/deploy"
	"github.com/bendahma/dokploy-go/internal/store"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"gopkg.in/yaml.v3"
)

type sourceApplication struct {
	ID                string   `json:"applicationId"`
	EnvironmentID     string   `json:"environmentId"`
	Name              string   `json:"name"`
	AppName           string   `json:"appName"`
	Env               string   `json:"env"`
	SourceType        string   `json:"sourceType"`
	BuildType         string   `json:"buildType"`
	HerokuVersion     string   `json:"herokuVersion"`
	DockerImage       string   `json:"dockerImage"`
	RegistryURL       string   `json:"registryUrl"`
	Username          string   `json:"username"`
	Password          string   `json:"password"`
	Command           string   `json:"command"`
	Args              []string `json:"args"`
	Replicas          int      `json:"replicas"`
	Repository        string   `json:"repository"`
	Owner             string   `json:"owner"`
	Branch            string   `json:"branch"`
	BuildPath         string   `json:"buildPath"`
	GitlabRepository  string   `json:"gitlabRepository"`
	GitlabOwner       string   `json:"gitlabOwner"`
	GitlabBranch      string   `json:"gitlabBranch"`
	GitlabBuildPath   string   `json:"gitlabBuildPath"`
	GitlabNamespace   string   `json:"gitlabPathNamespace"`
	GiteaRepository   string   `json:"giteaRepository"`
	GiteaOwner        string   `json:"giteaOwner"`
	GiteaBranch       string   `json:"giteaBranch"`
	GiteaBuildPath    string   `json:"giteaBuildPath"`
	BitbucketRepo     string   `json:"bitbucketRepository"`
	BitbucketRepoSlug string   `json:"bitbucketRepositorySlug"`
	BitbucketOwner    string   `json:"bitbucketOwner"`
	BitbucketBranch   string   `json:"bitbucketBranch"`
	BitbucketBuild    string   `json:"bitbucketBuildPath"`
	CustomGitURL      string   `json:"customGitUrl"`
	CustomGitBranch   string   `json:"customGitBranch"`
	CustomGitBuild    string   `json:"customGitBuildPath"`
	Dockerfile        string   `json:"dockerfile"`
	DockerContextPath string   `json:"dockerContextPath"`
	DockerBuildStage  string   `json:"dockerBuildStage"`
	BuildArgs         string   `json:"buildArgs"`
	BuildSecrets      string   `json:"buildSecrets"`
	EnableSubmodules  bool     `json:"enableSubmodules"`
	PublishDirectory  string   `json:"publishDirectory"`
	MemoryReservation string   `json:"memoryReservation"`
	MemoryLimit       string   `json:"memoryLimit"`
	CPUReservation    string   `json:"cpuReservation"`
	CPULimit          string   `json:"cpuLimit"`
	ProviderURL       string   `json:"-"`
	GitHubID          string   `json:"githubId"`
	GitLabID          string   `json:"gitlabId"`
	GiteaID           string   `json:"giteaId"`
	BitbucketID       string   `json:"bitbucketId"`
	RegistryID        string   `json:"registryId"`
	BuildRegistryID   string   `json:"buildRegistryId"`
}

type sourceApplicationRoute struct {
	id, applicationID, host, path, resolver string
	port                                    int
	tls, enabled                            bool
}

type preparedApplication struct {
	item        sourceApplication
	serviceID   uuid.UUID
	slug        string
	composeYAML string
	environment map[string]string
	source      *store.ApplicationSource
}

var migrationImagePattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:/@-]{0,511}$`)
var migrationGitRefPattern = regexp.MustCompile(`^[A-Za-z0-9._/-]{1,200}$`)

func dokployApplicationReport(item sourceApplication, targetID *uuid.UUID, status, reason string) DokployResourceReport {
	repository, branch, buildPath := applicationRepository(item)
	repository = migrationRepositoryMetadata(repository)
	return DokployResourceReport{
		SourceKind: "application", SourceID: item.ID, TargetID: targetID, Status: status, Reason: reason,
		Metadata: map[string]any{
			"name": item.Name, "appName": item.AppName, "sourceType": item.SourceType, "buildType": item.BuildType,
			"repository": repository, "branch": branch, "buildPath": buildPath, "dockerfile": item.Dockerfile, "herokuVersion": item.HerokuVersion,
			"dockerContextPath": item.DockerContextPath, "dockerBuildStage": item.DockerBuildStage,
			"hasBuildArgs": item.BuildArgs != "", "hasBuildSecrets": item.BuildSecrets != "", "enableSubmodules": item.EnableSubmodules,
			"publishDirectory": item.PublishDirectory,
			"replicas":         item.Replicas, "memoryReservation": item.MemoryReservation, "memoryLimit": item.MemoryLimit,
			"cpuReservation": item.CPUReservation, "cpuLimit": item.CPULimit, "hasRegistryCredentials": item.Username != "" || item.Password != "",
		},
	}
}

func migrationRepositoryMetadata(value string) string {
	parsed, err := url.Parse(value)
	if err != nil || parsed.Host == "" {
		return ""
	}
	parsed.User = nil
	parsed.RawQuery = ""
	parsed.Fragment = ""
	return parsed.String()
}

func readApplications(ctx context.Context, db *pgxpool.Pool, org string) ([]sourceApplication, error) {
	rows, err := db.Query(ctx, `SELECT to_jsonb(a),COALESCE(gh."githubUrl",''),COALESCE(gl."gitlabInternalUrl",gl."gitlabUrl",''),COALESCE(gt."giteaInternalUrl",gt."giteaUrl",'') FROM application a JOIN environment e ON e."environmentId"=a."environmentId" JOIN project p ON p."projectId"=e."projectId" LEFT JOIN github gh ON gh."githubId"=a."githubId" LEFT JOIN gitlab gl ON gl."gitlabId"=a."gitlabId" LEFT JOIN gitea gt ON gt."giteaId"=a."giteaId" WHERE p."organizationId"=$1 ORDER BY a."applicationId"`, org)
	if err != nil {
		return nil, fmt.Errorf("read Dokploy applications: %w", err)
	}
	defer rows.Close()
	items := []sourceApplication{}
	for rows.Next() {
		var data []byte
		var githubURL, gitlabURL, giteaURL string
		if err = rows.Scan(&data, &githubURL, &gitlabURL, &giteaURL); err != nil {
			return nil, err
		}
		var item sourceApplication
		if err = json.Unmarshal(data, &item); err != nil {
			return nil, fmt.Errorf("decode Dokploy application: %w", err)
		}
		switch item.SourceType {
		case "github":
			item.ProviderURL = githubURL
		case "gitlab":
			item.ProviderURL = gitlabURL
		case "gitea":
			item.ProviderURL = giteaURL
		}
		items = append(items, item)
	}
	return items, rows.Err()
}

func readApplicationRoutes(ctx context.Context, db *pgxpool.Pool, org string) ([]sourceApplicationRoute, error) {
	rows, err := db.Query(ctx, `SELECT d."domainId",d."applicationId",d.host,COALESCE(d.path,'/'),COALESCE(d.port,3000),d.https,d.enabled,COALESCE(d."customCertResolver",'') FROM domain d JOIN application a ON a."applicationId"=d."applicationId" JOIN environment e ON e."environmentId"=a."environmentId" JOIN project p ON p."projectId"=e."projectId" WHERE p."organizationId"=$1 AND d."applicationId" IS NOT NULL ORDER BY d."domainId"`, org)
	if err != nil {
		return nil, fmt.Errorf("read Dokploy application routes: %w", err)
	}
	defer rows.Close()
	items := []sourceApplicationRoute{}
	for rows.Next() {
		var item sourceApplicationRoute
		if err = rows.Scan(&item.id, &item.applicationID, &item.host, &item.path, &item.port, &item.tls, &item.enabled, &item.resolver); err != nil {
			return nil, err
		}
		items = append(items, item)
	}
	return items, rows.Err()
}

func prepareApplication(item sourceApplication, options DokployOptions) (preparedApplication, []string, error) {
	serviceID := mappedID(options, "application-service", item.ID)
	slug := migratedSlug(item.AppName, serviceID)
	environment := parseEnv(item.Env)
	service := map[string]any{
		"networks": []any{"default"},
		"deploy":   map[string]any{"replicas": max(item.Replicas, 1), "restart_policy": map[string]any{"condition": "on-failure"}},
	}
	deployConfig := service["deploy"].(map[string]any)
	resources := map[string]any{}
	if item.MemoryReservation != "" || item.CPUReservation != "" {
		reservations := map[string]any{}
		if item.MemoryReservation != "" {
			reservations["memory"] = item.MemoryReservation
		}
		if item.CPUReservation != "" {
			reservations["cpus"] = item.CPUReservation
		}
		resources["reservations"] = reservations
	}
	if item.MemoryLimit != "" || item.CPULimit != "" {
		limits := map[string]any{}
		if item.MemoryLimit != "" {
			limits["memory"] = item.MemoryLimit
		}
		if item.CPULimit != "" {
			limits["cpus"] = item.CPULimit
		}
		resources["limits"] = limits
	}
	if len(resources) > 0 {
		deployConfig["resources"] = resources
	}
	if len(environment) > 0 {
		keys := make([]string, 0, len(environment))
		for key := range environment {
			keys = append(keys, key)
		}
		sort.Strings(keys)
		refs := make([]any, 0, len(keys))
		for _, key := range keys {
			refs = append(refs, key+"=${"+key+"}")
		}
		service["environment"] = refs
	}
	if item.Command != "" {
		command := []any{item.Command}
		for _, arg := range item.Args {
			command = append(command, arg)
		}
		service["command"] = command
	}

	warnings := []string{fmt.Sprintf("application %s requires a manual audit of mounts, published ports, redirects, security rules, and custom Swarm policies", item.ID)}
	var source *store.ApplicationSource
	switch item.SourceType {
	case "docker":
		image := strings.TrimSpace(item.DockerImage)
		if !migrationImagePattern.MatchString(image) || strings.Contains(image, "..") {
			return preparedApplication{}, warnings, errors.New("Docker application has an invalid or empty image")
		}
		service["image"] = image
		if item.Username != "" || item.Password != "" {
			warnings = append(warnings, fmt.Sprintf("application %s uses private image credentials; recreate registry credentials before deployment", item.ID))
		}
	case "git", "github", "gitlab", "gitea", "bitbucket":
		buildType := strings.ToLower(strings.TrimSpace(item.BuildType))
		if buildType == "" {
			buildType = "dockerfile"
		}
		if buildType == "paketo" || buildType == "paketo_buildpacks" || buildType == "buildpack" {
			buildType = "buildpacks"
		}
		if buildType == "heroku_buildpacks" {
			herokuVersion := strings.TrimSpace(item.HerokuVersion)
			if herokuVersion != "" && herokuVersion != "24" {
				return preparedApplication{}, warnings, fmt.Errorf("Heroku builder version %q is not supported; only digest-pinned version 24 can be imported automatically", herokuVersion)
			}
		}
		if buildType != "dockerfile" && buildType != "static" && buildType != "nixpacks" && buildType != "railpack" && buildType != "buildpacks" && buildType != "heroku_buildpacks" {
			return preparedApplication{}, warnings, fmt.Errorf("build type %q is not supported", item.BuildType)
		}
		buildArguments, err := parseDokployBuildSettings(item.BuildArgs, options.EncryptionKeys)
		if err != nil {
			return preparedApplication{}, warnings, fmt.Errorf("decode build arguments: %w", err)
		}
		buildSecrets, err := parseDokployBuildSettings(item.BuildSecrets, options.EncryptionKeys)
		if err != nil {
			return preparedApplication{}, warnings, fmt.Errorf("decode build secrets: %w", err)
		}
		buildConfig := store.ApplicationBuildConfig{Arguments: buildArguments, Secrets: buildSecrets}
		registryPrefix := strings.TrimSuffix(strings.TrimSpace(options.RegistryPrefix), "/")
		registryImage := registryPrefix + "/" + slug
		if registryPrefix == "" || !migrationImagePattern.MatchString(registryImage) || strings.Contains(registryImage, "..") || strings.Contains(registryImage, "@") {
			return preparedApplication{}, warnings, errors.New("Git application requires a valid --registry-prefix")
		}
		repositoryURL, gitRef, contextDirectory := applicationRepository(item)
		parsed, err := url.Parse(repositoryURL)
		if err != nil || parsed.Scheme != "https" || parsed.Host == "" || parsed.User != nil {
			return preparedApplication{}, warnings, errors.New("Git application repository must be an HTTPS URL without embedded credentials")
		}
		if !migrationGitRefPattern.MatchString(gitRef) {
			return preparedApplication{}, warnings, errors.New("Git application has an invalid branch")
		}
		buildDirectory, err := cleanRepositoryPath(contextDirectory)
		if err != nil {
			return preparedApplication{}, warnings, fmt.Errorf("invalid Git build path: %w", err)
		}
		contextDirectory = buildDirectory
		if item.DockerContextPath != "" {
			contextDirectory, err = cleanRepositoryPath(item.DockerContextPath)
			if err != nil {
				return preparedApplication{}, warnings, fmt.Errorf("invalid Docker context path: %w", err)
			}
		}
		dockerfile, outputDirectory := "Dockerfile", ""
		if buildType == "dockerfile" {
			dockerfile = item.Dockerfile
			if dockerfile == "" {
				dockerfile = "Dockerfile"
			}
			dockerfile, err = cleanRepositoryPath(path.Join(buildDirectory, dockerfile))
			if err != nil {
				return preparedApplication{}, warnings, fmt.Errorf("invalid Dockerfile path: %w", err)
			}
			if contextDirectory != "." {
				prefix := contextDirectory + "/"
				if !strings.HasPrefix(dockerfile, prefix) {
					return preparedApplication{}, warnings, errors.New("Dockerfile must be inside the configured Docker context")
				}
				dockerfile = strings.TrimPrefix(dockerfile, prefix)
			}
		} else if buildType == "static" {
			outputDirectory, err = cleanRepositoryPath(item.PublishDirectory)
			if err != nil {
				return preparedApplication{}, warnings, fmt.Errorf("invalid static publish directory: %w", err)
			}
			if contextDirectory != "." && strings.HasPrefix(outputDirectory, contextDirectory+"/") {
				outputDirectory = strings.TrimPrefix(outputDirectory, contextDirectory+"/")
			}
			warnings = append(warnings, fmt.Sprintf("application %s static output must already exist in the Git repository; build commands are not executed", item.ID))
		}
		if err = deploy.ValidateBuildMode(buildType, outputDirectory, item.DockerBuildStage, buildConfig); err != nil {
			return preparedApplication{}, warnings, err
		}
		service["image"] = registryImage + ":pending"
		source = &store.ApplicationSource{ComposeServiceID: serviceID, RepositoryURL: repositoryURL, GitRef: gitRef, ContextDirectory: contextDirectory, Dockerfile: dockerfile, BuildType: buildType, OutputDirectory: outputDirectory, BuildTarget: item.DockerBuildStage, EnableSubmodules: item.EnableSubmodules, HasBuildArguments: len(buildArguments) > 0, HasBuildSecrets: len(buildSecrets) > 0, BuildArguments: buildArguments, BuildSecrets: buildSecrets, TargetService: "app", RegistryImage: registryImage}
		if item.SourceType != "git" {
			warnings = append(warnings, fmt.Sprintf("application %s provider credentials and webhooks are not imported; public clone access is required until they are recreated", item.ID))
		}
	case "drop":
		return preparedApplication{}, warnings, errors.New("drop source archive is stored on Dokploy's filesystem and cannot be copied from PostgreSQL; upload the ZIP manually after creating the application")
	default:
		return preparedApplication{}, warnings, fmt.Errorf("source type %q is not supported", item.SourceType)
	}

	document := map[string]any{"services": map[string]any{"app": service}, "networks": map[string]any{"default": map[string]any{"attachable": true}}}
	composeYAML, err := yaml.Marshal(document)
	if err != nil {
		return preparedApplication{}, warnings, err
	}
	return preparedApplication{item: item, serviceID: serviceID, slug: slug, composeYAML: string(composeYAML), environment: environment, source: source}, warnings, nil
}

func parseDokployBuildSettings(value string, keys [][]byte) (map[string]string, error) {
	if strings.TrimSpace(value) == "" {
		return nil, nil
	}
	plain, err := decryptDokploy(value, keys)
	if err != nil {
		return nil, err
	}
	settings := map[string]string{}
	for index, line := range strings.Split(plain, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		name, setting, ok := strings.Cut(line, "=")
		name = strings.TrimSpace(name)
		if !ok || name == "" {
			return nil, fmt.Errorf("line %d must use NAME=value syntax", index+1)
		}
		setting = strings.TrimSpace(setting)
		if len(setting) >= 2 && ((setting[0] == '"' && setting[len(setting)-1] == '"') || (setting[0] == '\'' && setting[len(setting)-1] == '\'')) {
			setting = setting[1 : len(setting)-1]
		}
		settings[name] = setting
	}
	return settings, nil
}

func cleanRepositoryPath(value string) (string, error) {
	value = strings.TrimSpace(value)
	if value == "" || value == "/" {
		return ".", nil
	}
	if strings.HasPrefix(value, "/") {
		value = strings.TrimPrefix(value, "/")
	}
	cleaned := path.Clean(value)
	if cleaned == ".." || strings.HasPrefix(cleaned, "../") {
		return "", errors.New("path escapes the repository")
	}
	return cleaned, nil
}

func applicationRepository(item sourceApplication) (repository, branch, buildPath string) {
	switch item.SourceType {
	case "git":
		return item.CustomGitURL, item.CustomGitBranch, item.CustomGitBuild
	case "github":
		return providerRepositoryURL(item.ProviderURL, "https://github.com", item.Owner+"/"+item.Repository), item.Branch, item.BuildPath
	case "gitlab":
		path := item.GitlabNamespace
		if path == "" {
			path = strings.Trim(item.GitlabOwner+"/"+item.GitlabRepository, "/")
		}
		return providerRepositoryURL(item.ProviderURL, "https://gitlab.com", path), item.GitlabBranch, item.GitlabBuildPath
	case "gitea":
		return providerRepositoryURL(item.ProviderURL, "https://gitea.com", item.GiteaOwner+"/"+item.GiteaRepository), item.GiteaBranch, item.GiteaBuildPath
	case "bitbucket":
		repository := item.BitbucketRepoSlug
		if repository == "" {
			repository = item.BitbucketRepo
		}
		return "https://bitbucket.org/" + item.BitbucketOwner + "/" + strings.TrimSuffix(repository, ".git") + ".git", item.BitbucketBranch, item.BitbucketBuild
	default:
		return "", "", ""
	}
}

func providerRepositoryURL(providerURL, fallback, repository string) string {
	base := strings.TrimSuffix(providerURL, "/")
	if base == "" {
		base = fallback
	}
	return base + "/" + strings.TrimSuffix(strings.Trim(repository, "/"), ".git") + ".git"
}
