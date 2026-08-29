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
	case "templates":
		return http.MethodGet, "/v1/templates", nil, require(1)
	case "clusters":
		return http.MethodGet, "/v1/clusters", nil, require(1)
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
	return errors.New("usage: dockyardctl [--url URL] [--token TOKEN] [--org UUID] <me|projects|environments|services|deployments|logs|templates|template-versions|clusters|deploy|rollback|cancel|create-project|create-environment|create-service|create-database|instantiate|upgrade-template|cluster-token|agent-upgrade|cluster-command|request>")
}
