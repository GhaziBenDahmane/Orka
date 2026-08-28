package migrate

import (
	"context"
	"fmt"
	"net/url"
	"strings"

	"github.com/bendahma/dokploy-go/internal/cryptox"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

type sourceCredential struct {
	sourceID, sourceKind, kind, name, server, username, secret string
	supported                                                  bool
	reason                                                     string
}

type preparedSourceCredential struct {
	source sourceCredential
	id     uuid.UUID
	server string
	secret string
}

func readSourceCredentials(ctx context.Context, db *pgxpool.Pool, organizationID string) ([]sourceCredential, error) {
	items := []sourceCredential{}
	queries := []struct {
		kind  string
		query string
	}{
		{"registry", `SELECT r."registryId",r."registryName",COALESCE(r."registryUrl",''),r.username,r.password FROM registry r WHERE r."organizationId"=$1 ORDER BY r."registryId"`},
		{"gitlab", `SELECT g."gitlabId",p.name,COALESCE(g."gitlabInternalUrl",g."gitlabUrl",''),'oauth2',COALESCE(g."access_token",'') FROM gitlab g JOIN git_provider p ON p."gitProviderId"=g."gitProviderId" WHERE p."organizationId"=$1 ORDER BY g."gitlabId"`},
		{"gitea", `SELECT g."giteaId",p.name,COALESCE(g."giteaInternalUrl",g."giteaUrl",''),'oauth2',COALESCE(g."access_token",'') FROM gitea g JOIN git_provider p ON p."gitProviderId"=g."gitProviderId" WHERE p."organizationId"=$1 ORDER BY g."giteaId"`},
		{"bitbucket", `SELECT b."bitbucketId",p.name,'https://bitbucket.org',COALESCE(b."bitbucketUsername",b."bitbucketEmail",''),COALESCE(b."apiToken",b."appPassword",'') FROM bitbucket b JOIN git_provider p ON p."gitProviderId"=b."gitProviderId" WHERE p."organizationId"=$1 ORDER BY b."bitbucketId"`},
	}
	for _, definition := range queries {
		rows, err := db.Query(ctx, definition.query, organizationID)
		if err != nil {
			return nil, fmt.Errorf("read Dokploy %s credentials: %w", definition.kind, err)
		}
		for rows.Next() {
			item := sourceCredential{sourceKind: definition.kind, kind: map[bool]string{true: "registry", false: "git"}[definition.kind == "registry"], supported: true}
			if err = rows.Scan(&item.sourceID, &item.name, &item.server, &item.username, &item.secret); err != nil {
				rows.Close()
				return nil, err
			}
			items = append(items, item)
		}
		if err = rows.Err(); err != nil {
			rows.Close()
			return nil, err
		}
		rows.Close()
	}
	rows, err := db.Query(ctx, `SELECT g."githubId",p.name,COALESCE(g."githubUrl",'https://github.com') FROM github g JOIN git_provider p ON p."gitProviderId"=g."gitProviderId" WHERE p."organizationId"=$1 ORDER BY g."githubId"`, organizationID)
	if err != nil {
		return nil, fmt.Errorf("read Dokploy github credentials: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		item := sourceCredential{sourceKind: "github", kind: "git", supported: false, reason: "GitHub App credentials require short-lived installation tokens and cannot be converted to a static Git credential"}
		if err = rows.Scan(&item.sourceID, &item.name, &item.server); err != nil {
			return nil, err
		}
		items = append(items, item)
	}
	return items, rows.Err()
}

func prepareSourceCredential(box *cryptox.Box, options DokployOptions, item sourceCredential) (preparedSourceCredential, error) {
	if !item.supported {
		return preparedSourceCredential{}, fmt.Errorf("%s", item.reason)
	}
	server, err := credentialServer(item.server, item.kind)
	if err != nil {
		return preparedSourceCredential{}, err
	}
	secret, err := decryptDokploy(item.secret, options.EncryptionKeys)
	if err != nil {
		return preparedSourceCredential{}, fmt.Errorf("decrypt credential: %w", err)
	}
	if strings.TrimSpace(item.name) == "" || item.username == "" || secret == "" {
		return preparedSourceCredential{}, fmt.Errorf("name, username, and secret are required")
	}
	encrypted, err := box.Encrypt([]byte(secret), "source-credential")
	if err != nil {
		return preparedSourceCredential{}, err
	}
	return preparedSourceCredential{source: item, id: mappedID(options, "source-credential:"+item.sourceKind, item.sourceID), server: server, secret: encrypted}, nil
}

func credentialServer(value, kind string) (string, error) {
	value = strings.TrimSpace(value)
	if kind == "registry" && value == "" {
		return "docker.io", nil
	}
	if !strings.Contains(value, "://") {
		value = "https://" + value
	}
	parsed, err := url.Parse(value)
	if err != nil || parsed.Hostname() == "" || (parsed.Scheme != "http" && parsed.Scheme != "https") {
		return "", fmt.Errorf("credential server %q is invalid", value)
	}
	if kind == "registry" && parsed.Path != "" && parsed.Path != "/" {
		return "", fmt.Errorf("registry server must not contain a path")
	}
	if kind == "registry" {
		return strings.ToLower(parsed.Host), nil
	}
	return strings.ToLower(parsed.Hostname()), nil
}

func migrationImageRegistry(image string) string {
	first, _, _ := strings.Cut(image, "/")
	if strings.ContainsAny(first, ".:") || first == "localhost" {
		return strings.ToLower(first)
	}
	return "docker.io"
}

func credentialKey(kind, sourceID string) string { return kind + "\x00" + sourceID }

func applicationProviderID(item sourceApplication) string {
	switch item.SourceType {
	case "github":
		return item.GitHubID
	case "gitlab":
		return item.GitLabID
	case "gitea":
		return item.GiteaID
	case "bitbucket":
		return item.BitbucketID
	default:
		return ""
	}
}

func repositoryHost(repository string) string {
	parsed, err := url.Parse(repository)
	if err != nil {
		return ""
	}
	return strings.ToLower(parsed.Hostname())
}
