package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/bendahma/dokploy-go/internal/apiclient"
)

type config struct {
	URL            string `json:"url"`
	Token          string `json:"token,omitempty"`
	OrganizationID string `json:"organizationId,omitempty"`
}

func main() {
	if err := run(os.Args[1:], os.Stdin, os.Stdout); err != nil {
		fmt.Fprintln(os.Stderr, "dockyardctl:", err)
		os.Exit(1)
	}
}

func run(arguments []string, stdin io.Reader, stdout io.Writer) error {
	stored, path, err := loadConfig()
	if err != nil {
		return err
	}
	flags := flag.NewFlagSet("dockyardctl", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	urlFlag := flags.String("url", envOr("DOCKYARD_URL", stored.URL), "Dockyard API URL")
	tokenFlag := flags.String("token", envOr("DOCKYARD_TOKEN", stored.Token), "bearer token")
	orgFlag := flags.String("org", envOr("DOCKYARD_ORGANIZATION_ID", stored.OrganizationID), "organization UUID")
	if err := flags.Parse(arguments); err != nil {
		return usageError()
	}
	args := flags.Args()
	if len(args) == 0 {
		return usageError()
	}
	if args[0] == "login" {
		return login(context.Background(), *urlFlag, *orgFlag, args[1:], stdin, stdout, path)
	}
	client, err := apiclient.New(*urlFlag, *tokenFlag, *orgFlag)
	if err != nil {
		return err
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	method, apiPath, input, err := commandRequest(args, stdin)
	if err != nil {
		return err
	}
	return client.Do(ctx, method, apiPath, input, stdout)
}

func commandRequest(args []string, stdin io.Reader) (string, string, any, error) {
	require := func(count int) error {
		if len(args) != count {
			return usageError()
		}
		return nil
	}
	switch args[0] {
	case "me":
		return http.MethodGet, "/v1/me", nil, require(1)
	case "members":
		return http.MethodGet, "/v1/members", nil, require(1)
	case "update-member":
		if err := require(3); err != nil {
			return "", "", nil, err
		}
		input, err := parseJSONArgument(args[2], stdin)
		return http.MethodPatch, "/v1/members/" + args[1], input, err
	case "delete-member":
		if err := require(2); err != nil {
			return "", "", nil, err
		}
		return http.MethodDelete, "/v1/members/" + args[1], nil, nil
	case "invitations":
		return http.MethodGet, "/v1/invitations", nil, require(1)
	case "invitation":
		if err := require(2); err != nil {
			return "", "", nil, err
		}
		return http.MethodGet, "/v1/invitations/" + args[1], nil, nil
	case "create-invitation":
		return jsonCommand(args, stdin, http.MethodPost, "/v1/invitations", 2)
	case "revoke-invitation":
		if err := require(2); err != nil {
			return "", "", nil, err
		}
		return http.MethodDelete, "/v1/invitations/" + args[1], nil, nil
	case "service-accounts":
		return http.MethodGet, "/v1/service-accounts", nil, require(1)
	case "create-service-account":
		return jsonCommand(args, stdin, http.MethodPost, "/v1/service-accounts", 2)
	case "rotate-service-account":
		if err := require(3); err != nil {
			return "", "", nil, err
		}
		input, err := parseJSONArgument(args[2], stdin)
		return http.MethodPost, "/v1/service-accounts/" + args[1] + "/rotate", input, err
	case "disable-service-account":
		if err := require(2); err != nil {
			return "", "", nil, err
		}
		return http.MethodDelete, "/v1/service-accounts/" + args[1], nil, nil
	case "ai-audit-runs":
		return http.MethodGet, "/v1/ai/audit-runs", nil, require(1)
	case "ai-audit-findings":
		return http.MethodGet, "/v1/ai/audit-findings", nil, require(1)
	case "ai-audit-run-findings":
		if err := require(2); err != nil {
			return "", "", nil, err
		}
		return http.MethodGet, "/v1/ai/audit-runs/" + args[1] + "/findings", nil, nil
	case "triage-ai-audit-finding":
		if err := require(3); err != nil {
			return "", "", nil, err
		}
		input, err := parseJSONArgument(args[2], stdin)
		return http.MethodPatch, "/v1/ai/audit-findings/" + args[1], input, err
	case "oidc-providers":
		return http.MethodGet, "/v1/sso/oidc-providers", nil, require(1)
	case "create-oidc-provider":
		return jsonCommand(args, stdin, http.MethodPost, "/v1/sso/oidc-providers", 2)
	case "update-oidc-provider":
		if err := require(3); err != nil {
			return "", "", nil, err
		}
		input, err := parseJSONArgument(args[2], stdin)
		return http.MethodPut, "/v1/sso/oidc-providers/" + args[1], input, err
	case "enable-oidc-provider":
		if err := require(2); err != nil {
			return "", "", nil, err
		}
		return http.MethodPost, "/v1/sso/oidc-providers/" + args[1] + "/enable", map[string]any{}, nil
	case "disable-oidc-provider":
		if err := require(2); err != nil {
			return "", "", nil, err
		}
		return http.MethodDelete, "/v1/sso/oidc-providers/" + args[1], nil, nil
	case "sso-settings":
		return http.MethodGet, "/v1/sso/settings", nil, require(1)
	case "put-sso-settings":
		return jsonCommand(args, stdin, http.MethodPut, "/v1/sso/settings", 2)
	case "scim-tokens":
		return http.MethodGet, "/v1/scim/tokens", nil, require(1)
	case "create-scim-token":
		return jsonCommand(args, stdin, http.MethodPost, "/v1/scim/tokens", 2)
	case "revoke-scim-token":
		if err := require(2); err != nil {
			return "", "", nil, err
		}
		return http.MethodDelete, "/v1/scim/tokens/" + args[1], nil, nil
	case "project-grants":
		if err := require(2); err != nil {
			return "", "", nil, err
		}
		return http.MethodGet, "/v1/projects/" + args[1] + "/grants", nil, nil
	case "put-project-grant":
		return grantCommand(args, stdin, "projects", http.MethodPut)
	case "delete-project-grant":
		return grantCommand(args, stdin, "projects", http.MethodDelete)
	case "environment-grants":
		if err := require(2); err != nil {
			return "", "", nil, err
		}
		return http.MethodGet, "/v1/environments/" + args[1] + "/grants", nil, nil
	case "put-environment-grant":
		return grantCommand(args, stdin, "environments", http.MethodPut)
	case "delete-environment-grant":
		return grantCommand(args, stdin, "environments", http.MethodDelete)
	case "policy":
		return http.MethodGet, "/v1/policy", nil, require(1)
	case "put-policy":
		return jsonCommand(args, stdin, http.MethodPut, "/v1/policy", 2)
	case "project-policy":
		if err := require(2); err != nil {
			return "", "", nil, err
		}
		return http.MethodGet, "/v1/projects/" + args[1] + "/policy", nil, nil
	case "put-project-policy":
		return scopedJSONCommand(args, stdin, http.MethodPut, "projects", "policy")
	case "environment-policy":
		if err := require(2); err != nil {
			return "", "", nil, err
		}
		return http.MethodGet, "/v1/environments/" + args[1] + "/policy", nil, nil
	case "put-environment-policy":
		return scopedJSONCommand(args, stdin, http.MethodPut, "environments", "policy")
	case "saml-providers":
		return http.MethodGet, "/v1/sso/saml-providers", nil, require(1)
	case "create-saml-provider":
		return jsonCommand(args, stdin, http.MethodPost, "/v1/sso/saml-providers", 2)
	case "update-saml-provider":
		if err := require(3); err != nil {
			return "", "", nil, err
		}
		input, err := parseJSONArgument(args[2], stdin)
		return http.MethodPut, "/v1/sso/saml-providers/" + args[1], input, err
	case "enable-saml-provider":
		if err := require(2); err != nil {
			return "", "", nil, err
		}
		return http.MethodPost, "/v1/sso/saml-providers/" + args[1] + "/enable", map[string]any{}, nil
	case "disable-saml-provider":
		if err := require(2); err != nil {
			return "", "", nil, err
		}
		return http.MethodDelete, "/v1/sso/saml-providers/" + args[1], nil, nil
	case "rotate-saml-certificate":
		if err := require(2); err != nil {
			return "", "", nil, err
		}
		return http.MethodPost, "/v1/sso/saml-providers/" + args[1] + "/certificate-rotation", map[string]any{}, nil
	case "promote-saml-certificate":
		if err := require(3); err != nil {
			return "", "", nil, err
		}
		return http.MethodPost, "/v1/sso/saml-providers/" + args[1] + "/certificate-rotation/promote", map[string]string{"confirm": args[2]}, nil
	case "cancel-saml-certificate":
		if err := require(2); err != nil {
			return "", "", nil, err
		}
		return http.MethodDelete, "/v1/sso/saml-providers/" + args[1] + "/certificate-rotation", nil, nil
	case "projects":
		return http.MethodGet, "/v1/projects", nil, require(1)
	case "environments":
		if err := require(2); err != nil {
			return "", "", nil, err
		}
		return http.MethodGet, "/v1/projects/" + args[1] + "/environments", nil, nil
	case "services":
		if err := require(2); err != nil {
			return "", "", nil, err
		}
		return http.MethodGet, "/v1/environments/" + args[1] + "/services", nil, nil
	case "deployments":
		if err := require(2); err != nil {
			return "", "", nil, err
		}
		return http.MethodGet, "/v1/services/" + args[1] + "/deployments", nil, nil
	case "logs":
		if err := require(2); err != nil {
			return "", "", nil, err
		}
		return http.MethodGet, "/v1/services/" + args[1] + "/logs", nil, nil
	case "database-engines":
		return http.MethodGet, "/v1/database-engines", nil, require(1)
	case "backup-destinations":
		return http.MethodGet, "/v1/backup-destinations", nil, require(1)
	case "create-backup-destination":
		return jsonCommand(args, stdin, http.MethodPost, "/v1/backup-destinations", 2)
	case "update-backup-destination":
		if err := require(3); err != nil {
			return "", "", nil, err
		}
		input, err := parseJSONArgument(args[2], stdin)
		return http.MethodPut, "/v1/backup-destinations/" + args[1], input, err
	case "delete-backup-destination":
		if err := require(2); err != nil {
			return "", "", nil, err
		}
		return http.MethodDelete, "/v1/backup-destinations/" + args[1], nil, nil
	case "notification-endpoints":
		return http.MethodGet, "/v1/notification-endpoints", nil, require(1)
	case "create-notification-endpoint":
		return jsonCommand(args, stdin, http.MethodPost, "/v1/notification-endpoints", 2)
	case "delete-notification-endpoint":
		if err := require(2); err != nil {
			return "", "", nil, err
		}
		return http.MethodDelete, "/v1/notification-endpoints/" + args[1], nil, nil
	case "databases":
		if err := require(2); err != nil {
			return "", "", nil, err
		}
		return http.MethodGet, "/v1/environments/" + args[1] + "/databases", nil, nil
	case "database":
		if err := require(2); err != nil {
			return "", "", nil, err
		}
		return http.MethodGet, "/v1/databases/" + args[1], nil, nil
	case "backup-policy":
		if err := require(2); err != nil {
			return "", "", nil, err
		}
		return http.MethodGet, "/v1/databases/" + args[1] + "/backup-policy", nil, nil
	case "put-backup-policy":
		if err := require(3); err != nil {
			return "", "", nil, err
		}
		input, err := parseJSONArgument(args[2], stdin)
		return http.MethodPut, "/v1/databases/" + args[1] + "/backup-policy", input, err
	case "delete-backup-policy":
		if err := require(2); err != nil {
			return "", "", nil, err
		}
		return http.MethodDelete, "/v1/databases/" + args[1] + "/backup-policy", nil, nil
	case "database-backups":
		if err := require(2); err != nil {
			return "", "", nil, err
		}
		return http.MethodGet, "/v1/databases/" + args[1] + "/backups", nil, nil
	case "backup-database":
		if err := require(2); err != nil {
			return "", "", nil, err
		}
		return http.MethodPost, "/v1/databases/" + args[1] + "/backups", map[string]any{}, nil
	case "database-restores":
		if err := require(2); err != nil {
			return "", "", nil, err
		}
		return http.MethodGet, "/v1/databases/" + args[1] + "/restores", nil, nil
	case "database-backup":
		if err := require(2); err != nil {
			return "", "", nil, err
		}
		return http.MethodGet, "/v1/database-backups/" + args[1], nil, nil
	case "cancel-database-backup":
		if err := require(2); err != nil {
			return "", "", nil, err
		}
		return http.MethodPost, "/v1/database-backups/" + args[1] + "/cancel", map[string]any{}, nil
	case "restore-database":
		if err := require(3); err != nil {
			return "", "", nil, err
		}
		return http.MethodPost, "/v1/database-backups/" + args[1] + "/restore", map[string]string{"confirm": args[2]}, nil
	case "database-restore":
		if err := require(2); err != nil {
			return "", "", nil, err
		}
		return http.MethodGet, "/v1/database-restores/" + args[1], nil, nil
	case "cancel-database-restore":
		if err := require(2); err != nil {
			return "", "", nil, err
		}
		return http.MethodPost, "/v1/database-restores/" + args[1] + "/cancel", map[string]any{}, nil
	case "volumes":
		if err := require(2); err != nil {
			return "", "", nil, err
		}
		return http.MethodGet, "/v1/services/" + args[1] + "/volumes", nil, nil
	case "volume-policies":
		if err := require(2); err != nil {
			return "", "", nil, err
		}
		return http.MethodGet, "/v1/services/" + args[1] + "/volume-backup-policies", nil, nil
	case "put-volume-policy":
		if err := require(4); err != nil {
			return "", "", nil, err
		}
		input, err := parseJSONArgument(args[3], stdin)
		return http.MethodPut, "/v1/services/" + args[1] + "/volume-backup-policies/" + args[2], input, err
	case "delete-volume-policy":
		if err := require(3); err != nil {
			return "", "", nil, err
		}
		return http.MethodDelete, "/v1/services/" + args[1] + "/volume-backup-policies/" + args[2], nil, nil
	case "volume-backups":
		if err := require(2); err != nil {
			return "", "", nil, err
		}
		return http.MethodGet, "/v1/services/" + args[1] + "/volume-backups", nil, nil
	case "backup-volume":
		if err := require(3); err != nil {
			return "", "", nil, err
		}
		return http.MethodPost, "/v1/services/" + args[1] + "/volume-backups/" + args[2], map[string]any{}, nil
	case "volume-restores":
		if err := require(2); err != nil {
			return "", "", nil, err
		}
		return http.MethodGet, "/v1/services/" + args[1] + "/volume-restores", nil, nil
	case "volume-backup":
		if err := require(2); err != nil {
			return "", "", nil, err
		}
		return http.MethodGet, "/v1/volume-backups/" + args[1], nil, nil
	case "cancel-volume-backup":
		if err := require(2); err != nil {
			return "", "", nil, err
		}
		return http.MethodPost, "/v1/volume-backups/" + args[1] + "/cancel", map[string]any{}, nil
	case "restore-volume":
		if err := require(3); err != nil {
			return "", "", nil, err
		}
		return http.MethodPost, "/v1/volume-backups/" + args[1] + "/restore", map[string]string{"confirm": args[2]}, nil
	case "volume-restore":
		if err := require(2); err != nil {
			return "", "", nil, err
		}
		return http.MethodGet, "/v1/volume-restores/" + args[1], nil, nil
	case "cancel-volume-restore":
		if err := require(2); err != nil {
			return "", "", nil, err
		}
		return http.MethodPost, "/v1/volume-restores/" + args[1] + "/cancel", map[string]any{}, nil
	case "templates":
		return http.MethodGet, "/v1/templates", nil, require(1)
	case "template-repositories":
		return http.MethodGet, "/v1/template-repositories", nil, require(1)
	case "create-template-repository":
		return jsonCommand(args, stdin, http.MethodPost, "/v1/template-repositories", 2)
	case "update-template-repository":
		if err := require(3); err != nil {
			return "", "", nil, err
		}
		input, err := parseJSONArgument(args[2], stdin)
		return http.MethodPatch, "/v1/template-repositories/" + args[1], input, err
	case "sync-template-repository":
		if err := require(2); err != nil {
			return "", "", nil, err
		}
		return http.MethodPost, "/v1/template-repositories/" + args[1] + "/sync", map[string]any{}, nil
	case "rotate-template-repository-webhook":
		if err := require(2); err != nil {
			return "", "", nil, err
		}
		return http.MethodPost, "/v1/template-repositories/" + args[1] + "/webhook-secret", map[string]any{}, nil
	case "disable-template-repository-webhook":
		if err := require(2); err != nil {
			return "", "", nil, err
		}
		return http.MethodDelete, "/v1/template-repositories/" + args[1] + "/webhook-secret", nil, nil
	case "delete-template-repository":
		if err := require(2); err != nil {
			return "", "", nil, err
		}
		return http.MethodDelete, "/v1/template-repositories/" + args[1], nil, nil
	case "clusters":
		return http.MethodGet, "/v1/clusters", nil, require(1)
	case "create-cluster":
		return jsonCommand(args, stdin, http.MethodPost, "/v1/clusters", 2)
	case "update-cluster":
		return scopedJSONCommand(args, stdin, http.MethodPatch, "clusters", "")
	case "delete-cluster":
		if err := require(2); err != nil {
			return "", "", nil, err
		}
		return http.MethodDelete, "/v1/clusters/" + args[1], nil, nil
	case "deploy":
		if err := require(2); err != nil {
			return "", "", nil, err
		}
		return http.MethodPost, "/v1/services/" + args[1] + "/deployments", map[string]any{}, nil
	case "rollback":
		if err := require(2); err != nil {
			return "", "", nil, err
		}
		return http.MethodPost, "/v1/services/" + args[1] + "/rollback", map[string]any{}, nil
	case "cancel":
		if err := require(2); err != nil {
			return "", "", nil, err
		}
		return http.MethodPost, "/v1/deployments/" + args[1] + "/cancel", map[string]any{}, nil
	case "create-project":
		return jsonCommand(args, stdin, http.MethodPost, "/v1/projects", 2)
	case "create-environment":
		if len(args) != 3 {
			return "", "", nil, usageError()
		}
		input, err := parseJSONArgument(args[2], stdin)
		return http.MethodPost, "/v1/projects/" + args[1] + "/environments", input, err
	case "create-service":
		if len(args) != 3 {
			return "", "", nil, usageError()
		}
		input, err := parseJSONArgument(args[2], stdin)
		return http.MethodPost, "/v1/environments/" + args[1] + "/services", input, err
	case "create-database":
		if len(args) != 3 {
			return "", "", nil, usageError()
		}
		input, err := parseJSONArgument(args[2], stdin)
		return http.MethodPost, "/v1/environments/" + args[1] + "/databases", input, err
	case "instantiate":
		if len(args) != 3 {
			return "", "", nil, usageError()
		}
		input, err := parseJSONArgument(args[2], stdin)
		return http.MethodPost, "/v1/templates/" + args[1] + "/instantiate", input, err
	case "preview-template":
		if len(args) != 3 {
			return "", "", nil, usageError()
		}
		input, err := parseJSONArgument(args[2], stdin)
		return http.MethodPost, "/v1/templates/" + args[1] + "/preview", input, err
	case "template-versions":
		if err := require(2); err != nil {
			return "", "", nil, err
		}
		return http.MethodGet, "/v1/services/" + args[1] + "/template-versions", nil, nil
	case "upgrade-template":
		if len(args) != 3 {
			return "", "", nil, usageError()
		}
		input, err := parseJSONArgument(args[2], stdin)
		return http.MethodPost, "/v1/services/" + args[1] + "/template-upgrades", input, err
	case "cluster-token":
		if err := require(2); err != nil {
			return "", "", nil, err
		}
		return http.MethodPost, "/v1/clusters/" + args[1] + "/enrollment-tokens", map[string]any{}, nil
	case "agent-upgrade":
		if len(args) != 3 {
			return "", "", nil, usageError()
		}
		return http.MethodPost, "/v1/clusters/" + args[1] + "/agent-upgrades", map[string]string{"image": args[2]}, nil
	case "cluster-command":
		if len(args) != 3 {
			return "", "", nil, usageError()
		}
		return http.MethodGet, "/v1/clusters/" + args[1] + "/commands/" + args[2], nil, nil
	case "cancel-agent-upgrade":
		if len(args) != 3 {
			return "", "", nil, usageError()
		}
		return http.MethodDelete, "/v1/clusters/" + args[1] + "/agent-upgrades/" + args[2], nil, nil
	case "request":
		if len(args) < 3 || len(args) > 4 {
			return "", "", nil, usageError()
		}
		var input any
		var err error
		if len(args) == 4 {
			input, err = parseJSONArgument(args[3], stdin)
		}
		return strings.ToUpper(args[1]), args[2], input, err
	default:
		return "", "", nil, usageError()
	}
}

func jsonCommand(args []string, stdin io.Reader, method, path string, count int) (string, string, any, error) {
	if len(args) != count {
		return "", "", nil, usageError()
	}
	input, err := parseJSONArgument(args[count-1], stdin)
	return method, path, input, err
}

func grantCommand(args []string, stdin io.Reader, collection, method string) (string, string, any, error) {
	count := 3
	if method == http.MethodPut {
		count = 4
	}
	if len(args) != count {
		return "", "", nil, usageError()
	}
	path := "/v1/" + collection + "/" + args[1] + "/grants/" + args[2]
	if method == http.MethodDelete {
		return method, path, nil, nil
	}
	input, err := parseJSONArgument(args[3], stdin)
	return method, path, input, err
}

func scopedJSONCommand(args []string, stdin io.Reader, method, collection, suffix string) (string, string, any, error) {
	if len(args) != 3 {
		return "", "", nil, usageError()
	}
	input, err := parseJSONArgument(args[2], stdin)
	path := "/v1/" + collection + "/" + args[1]
	if suffix != "" {
		path += "/" + suffix
	}
	return method, path, input, err
}

func parseJSONArgument(argument string, stdin io.Reader) (any, error) {
	var reader io.Reader = strings.NewReader(argument)
	if argument == "-" {
		reader = stdin
	}
	var value any
	decoder := json.NewDecoder(io.LimitReader(reader, 4<<20))
	if err := decoder.Decode(&value); err != nil {
		return nil, fmt.Errorf("decode JSON input: %w", err)
	}
	return value, nil
}

func login(_ context.Context, rawURL, organizationID string, args []string, stdin io.Reader, stdout io.Writer, path string) error {
	if len(args) != 1 {
		return errors.New("usage: dockyardctl [flags] login EMAIL < password")
	}
	password, err := io.ReadAll(io.LimitReader(stdin, 4096))
	if err != nil {
		return err
	}
	client, err := apiclient.New(rawURL, "", organizationID)
	if err != nil {
		return err
	}
	var response strings.Builder
	passwordValue := strings.TrimSuffix(strings.TrimSuffix(string(password), "\n"), "\r")
	if err := client.Do(context.Background(), http.MethodPost, "/v1/auth/login", map[string]string{"email": args[0], "password": passwordValue}, &response); err != nil {
		return err
	}
	var envelope struct {
		Token     string `json:"token"`
		Principal struct {
			OrganizationID string `json:"organizationId"`
		} `json:"principal"`
	}
	if err := json.Unmarshal([]byte(response.String()), &envelope); err != nil || envelope.Token == "" {
		return errors.New("login response did not contain a token")
	}
	stored := config{URL: rawURL, Token: envelope.Token, OrganizationID: envelope.Principal.OrganizationID}
	if organizationID != "" {
		stored.OrganizationID = organizationID
	}
	if err := saveConfig(path, stored); err != nil {
		return err
	}
	_, err = fmt.Fprintln(stdout, "Login succeeded; credentials saved to", path)
	return err
}

func loadConfig() (config, string, error) {
	directory, err := os.UserConfigDir()
	if err != nil {
		return config{}, "", err
	}
	path := filepath.Join(directory, "dockyard", "config.json")
	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return config{URL: "http://localhost:8080"}, path, nil
	}
	if err != nil {
		return config{}, path, err
	}
	info, err := os.Stat(path)
	if err != nil {
		return config{}, path, err
	}
	if info.Mode().Perm()&0077 != 0 {
		return config{}, path, errors.New("CLI config permissions are too broad; run chmod 600 " + path)
	}
	var stored config
	if err := json.Unmarshal(data, &stored); err != nil {
		return config{}, path, fmt.Errorf("decode CLI config: %w", err)
	}
	return stored, path, nil
}

func saveConfig(path string, value config) error {
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return err
	}
	if err := os.Chmod(filepath.Dir(path), 0700); err != nil {
		return err
	}
	data, _ := json.MarshalIndent(value, "", "  ")
	temporary := path + ".tmp"
	if err := os.WriteFile(temporary, data, 0600); err != nil {
		return err
	}
	if err := os.Chmod(temporary, 0600); err != nil {
		return err
	}
	return os.Rename(temporary, path)
}

func envOr(name, fallback string) string {
	if value := strings.TrimSpace(os.Getenv(name)); value != "" {
		return value
	}
	return fallback
}

func usageError() error {
	return errors.New("usage: dockyardctl [--url URL] [--token TOKEN] [--org UUID] <me|members|update-member|delete-member|invitations|invitation|create-invitation|revoke-invitation|service-accounts|create-service-account|rotate-service-account|disable-service-account|ai-audit-runs|ai-audit-findings|ai-audit-run-findings|triage-ai-audit-finding|oidc-providers|create-oidc-provider|update-oidc-provider|enable-oidc-provider|disable-oidc-provider|sso-settings|put-sso-settings|scim-tokens|create-scim-token|revoke-scim-token|saml-providers|create-saml-provider|update-saml-provider|enable-saml-provider|disable-saml-provider|rotate-saml-certificate|promote-saml-certificate|cancel-saml-certificate|project-grants|put-project-grant|delete-project-grant|environment-grants|put-environment-grant|delete-environment-grant|policy|put-policy|project-policy|put-project-policy|environment-policy|put-environment-policy|projects|environments|services|deployments|logs|database-engines|backup-destinations|create-backup-destination|update-backup-destination|delete-backup-destination|notification-endpoints|create-notification-endpoint|delete-notification-endpoint|databases|database|backup-policy|put-backup-policy|delete-backup-policy|database-backups|backup-database|database-restores|database-backup|cancel-database-backup|restore-database|database-restore|cancel-database-restore|volumes|volume-policies|put-volume-policy|delete-volume-policy|volume-backups|backup-volume|volume-restores|volume-backup|cancel-volume-backup|restore-volume|volume-restore|cancel-volume-restore|templates|template-repositories|create-template-repository|update-template-repository|sync-template-repository|rotate-template-repository-webhook|disable-template-repository-webhook|delete-template-repository|template-versions|clusters|create-cluster|update-cluster|delete-cluster|deploy|rollback|cancel|create-project|create-environment|create-service|create-database|preview-template|instantiate|upgrade-template|cluster-token|agent-upgrade|cluster-command|cancel-agent-upgrade|request>")
}
