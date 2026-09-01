package config

import (
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/GhaziBenDahmane/Orka/internal/agentpki"
	"github.com/GhaziBenDahmane/Orka/internal/netpolicy"
)

type Config struct {
	ListenAddr                 string
	DatabaseURL                string
	RequireDatabaseTLS         bool
	MasterKey                  []byte
	MetricsToken               string
	DockerBin                  string
	WorkerConcurrency          int
	ExpectedControllerReplicas int
	MaxBuildWorkspaceBytes     int64
	SessionTTL                 time.Duration
	TraefikNetwork             string
	EdgeProxyServiceName       string
	EdgeProxyDynamicConfigPath string
	UnsafeWorkloads            bool
	PublicURL                  string
	BackupDirectory            string
	RequireRemoteBackups       bool
	OTLPEndpoint               string
	OTLPInsecure               bool
	ServiceName                string
	SwarmServiceName           string
	AgentCACertificate         []byte
	AgentCAKey                 []byte
	AgentPreviousCACertificate []byte
	AgentCATrustBundle         []byte
	AgentCertificateTTL        time.Duration
	AgentCAExpiresAt           time.Time
	AgentPreviousCAExpiresAt   time.Time
	AgentServerCertExpiresAt   time.Time
	AgentListenAddr            string
	AgentServerCertFile        string
	AgentServerKeyFile         string
	DatabaseDriverDirectory    string
	TrustedProxyCIDRs          []*net.IPNet
	EgressPrivateCIDRs         []netip.Prefix
}

var swarmNetworkName = regexp.MustCompile(`^[a-z0-9][a-z0-9_.-]{0,62}$`)
var publicHostnameLabel = regexp.MustCompile(`^[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?$`)

const maxConfigSecretFileBytes int64 = 1 << 20

func Load() (Config, error) {
	ttl, err := time.ParseDuration(env("DOCKYARD_SESSION_TTL", "24h"))
	if err != nil || ttl < 5*time.Minute || ttl > 30*24*time.Hour {
		return Config{}, errors.New("DOCKYARD_SESSION_TTL must be between 5m and 720h")
	}
	concurrency, err := strconv.Atoi(env("DOCKYARD_WORKER_CONCURRENCY", "2"))
	if err != nil || concurrency < 1 || concurrency > 32 {
		return Config{}, errors.New("DOCKYARD_WORKER_CONCURRENCY must be between 1 and 32")
	}
	expectedControllerReplicas, err := strconv.Atoi(env("DOCKYARD_EXPECTED_CONTROLLER_REPLICAS", "1"))
	if err != nil || expectedControllerReplicas < 1 || expectedControllerReplicas > 99 {
		return Config{}, errors.New("DOCKYARD_EXPECTED_CONTROLLER_REPLICAS must be between 1 and 99")
	}
	maxBuildWorkspaceBytes, err := strconv.ParseInt(env("DOCKYARD_MAX_BUILD_WORKSPACE_BYTES", "2147483648"), 10, 64)
	if err != nil || maxBuildWorkspaceBytes < 64<<20 || maxBuildWorkspaceBytes > 1<<40 {
		return Config{}, errors.New("DOCKYARD_MAX_BUILD_WORKSPACE_BYTES must be between 67108864 and 1099511627776")
	}
	keyValue, err := secretEnv("DOCKYARD_MASTER_KEY")
	if err != nil {
		return Config{}, err
	}
	key, err := base64.StdEncoding.DecodeString(keyValue)
	if err != nil || len(key) != 32 {
		return Config{}, errors.New("DOCKYARD_MASTER_KEY must be a base64-encoded 32-byte key")
	}
	metricsToken, err := secretEnv("DOCKYARD_METRICS_TOKEN")
	if err != nil {
		return Config{}, err
	}
	if len(metricsToken) < 32 || len(metricsToken) > 4096 || strings.ContainsAny(metricsToken, "\r\n") {
		return Config{}, errors.New("DOCKYARD_METRICS_TOKEN must contain between 32 and 4096 bytes without line breaks")
	}
	unsafeWorkloads, err := strconv.ParseBool(env("DOCKYARD_ALLOW_UNSAFE_WORKLOADS", "false"))
	if err != nil {
		return Config{}, fmt.Errorf("parse DOCKYARD_ALLOW_UNSAFE_WORKLOADS: %w", err)
	}
	databaseURL, err := secretEnv("DOCKYARD_DATABASE_URL")
	if err != nil {
		return Config{}, err
	}
	requireDatabaseTLS, err := strconv.ParseBool(env("DOCKYARD_REQUIRE_DATABASE_TLS", "false"))
	if err != nil {
		return Config{}, fmt.Errorf("parse DOCKYARD_REQUIRE_DATABASE_TLS: %w", err)
	}
	if err = ValidateDatabaseURL(databaseURL, requireDatabaseTLS); err != nil {
		return Config{}, err
	}
	backupDirectory := env("DOCKYARD_BACKUP_DIRECTORY", "/var/lib/dockyard/backups")
	if !filepath.IsAbs(backupDirectory) {
		return Config{}, errors.New("DOCKYARD_BACKUP_DIRECTORY must be absolute")
	}
	requireRemoteBackups, err := strconv.ParseBool(env("DOCKYARD_REQUIRE_REMOTE_BACKUPS", "false"))
	if err != nil {
		return Config{}, fmt.Errorf("parse DOCKYARD_REQUIRE_REMOTE_BACKUPS: %w", err)
	}
	if expectedControllerReplicas > 1 && !requireDatabaseTLS {
		return Config{}, errors.New("DOCKYARD_REQUIRE_DATABASE_TLS must be true when DOCKYARD_EXPECTED_CONTROLLER_REPLICAS is greater than one")
	}
	if expectedControllerReplicas > 1 && !requireRemoteBackups {
		return Config{}, errors.New("DOCKYARD_REQUIRE_REMOTE_BACKUPS must be true when DOCKYARD_EXPECTED_CONTROLLER_REPLICAS is greater than one")
	}
	driverDirectory := strings.TrimSpace(os.Getenv("DOCKYARD_DATABASE_DRIVER_DIRECTORY"))
	if driverDirectory != "" && !filepath.IsAbs(driverDirectory) {
		return Config{}, errors.New("DOCKYARD_DATABASE_DRIVER_DIRECTORY must be absolute")
	}
	otlpInsecure, err := strconv.ParseBool(env("DOCKYARD_OTEL_EXPORTER_OTLP_INSECURE", "false"))
	if err != nil {
		return Config{}, fmt.Errorf("parse DOCKYARD_OTEL_EXPORTER_OTLP_INSECURE: %w", err)
	}
	otlpEndpoint := strings.TrimSpace(os.Getenv("DOCKYARD_OTEL_EXPORTER_OTLP_ENDPOINT"))
	if otlpEndpoint == "" {
		otlpEndpoint = strings.TrimSpace(os.Getenv("OTEL_EXPORTER_OTLP_ENDPOINT"))
	}
	publicURL := strings.TrimSpace(env("DOCKYARD_PUBLIC_URL", "http://localhost:8080"))
	parsedPublicURL, err := url.Parse(publicURL)
	if err != nil || (parsedPublicURL.Scheme != "http" && parsedPublicURL.Scheme != "https") || !validPublicURLHost(parsedPublicURL) || parsedPublicURL.User != nil || parsedPublicURL.RawQuery != "" || parsedPublicURL.Fragment != "" || (parsedPublicURL.Path != "" && parsedPublicURL.Path != "/") {
		return Config{}, errors.New("DOCKYARD_PUBLIC_URL must be an HTTP(S) origin without credentials, path, query, or fragment and with a valid host and port")
	}
	if port := parsedPublicURL.Port(); port != "" {
		value, parseErr := strconv.Atoi(port)
		if parseErr != nil || value < 1 || value > 65535 {
			return Config{}, errors.New("DOCKYARD_PUBLIC_URL must be an HTTP(S) origin without credentials, path, query, or fragment and with a valid host and port")
		}
	}
	if parsedPublicURL.Scheme != "https" && !loopbackHostname(parsedPublicURL.Hostname()) {
		return Config{}, errors.New("DOCKYARD_PUBLIC_URL must use HTTPS except for loopback development")
	}
	publicURL = strings.TrimSuffix(publicURL, "/")
	traefikNetwork := strings.TrimSpace(env("DOCKYARD_TRAEFIK_NETWORK", "dockyard-public"))
	if !swarmNetworkName.MatchString(traefikNetwork) {
		return Config{}, errors.New("DOCKYARD_TRAEFIK_NETWORK must be a lowercase Docker network name of at most 63 characters")
	}
	edgeProxyServiceName := strings.TrimSpace(env("DOCKYARD_EDGE_PROXY_SERVICE_NAME", "dockyard_traefik"))
	if !regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$`).MatchString(edgeProxyServiceName) {
		return Config{}, errors.New("DOCKYARD_EDGE_PROXY_SERVICE_NAME must be a valid Swarm service name")
	}
	edgeProxyDynamicConfigPath := strings.TrimSpace(env("DOCKYARD_EDGE_PROXY_DYNAMIC_CONFIG_PATH", "/etc/traefik/dynamic"))
	if !filepath.IsAbs(edgeProxyDynamicConfigPath) || filepath.Clean(edgeProxyDynamicConfigPath) != edgeProxyDynamicConfigPath || edgeProxyDynamicConfigPath == "/" || strings.ContainsAny(edgeProxyDynamicConfigPath, "\x00\r\n,=") {
		return Config{}, errors.New("DOCKYARD_EDGE_PROXY_DYNAMIC_CONFIG_PATH must be a clean absolute container path")
	}
	swarmServiceName := strings.TrimSpace(os.Getenv("DOCKYARD_SWARM_SERVICE_NAME"))
	if swarmServiceName != "" && !regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$`).MatchString(swarmServiceName) {
		return Config{}, errors.New("DOCKYARD_SWARM_SERVICE_NAME must be a valid Swarm service name")
	}
	trustedProxyCIDRs, err := parseTrustedProxyCIDRs(os.Getenv("DOCKYARD_TRUSTED_PROXY_CIDRS"))
	if err != nil {
		return Config{}, err
	}
	egressPrivateCIDRs, err := netpolicy.ParseAllowedCIDRs(os.Getenv("DOCKYARD_EGRESS_PRIVATE_CIDRS"))
	if err != nil {
		return Config{}, fmt.Errorf("DOCKYARD_EGRESS_PRIVATE_CIDRS: %w", err)
	}
	agentCACertificate, err := secretEnv("DOCKYARD_AGENT_CA_CERT")
	if err != nil {
		return Config{}, err
	}
	agentCAKey, err := secretEnv("DOCKYARD_AGENT_CA_KEY")
	if err != nil {
		return Config{}, err
	}
	if (agentCACertificate == "") != (agentCAKey == "") {
		return Config{}, errors.New("DOCKYARD_AGENT_CA_CERT and DOCKYARD_AGENT_CA_KEY must be configured together")
	}
	agentPreviousCACertificate, err := secretEnv("DOCKYARD_AGENT_PREVIOUS_CA_CERT")
	if err != nil {
		return Config{}, err
	}
	if agentPreviousCACertificate != "" && agentCACertificate == "" {
		return Config{}, errors.New("DOCKYARD_AGENT_PREVIOUS_CA_CERT requires an active agent CA certificate and key")
	}
	agentListenAddr := strings.TrimSpace(os.Getenv("DOCKYARD_AGENT_LISTEN_ADDR"))
	agentServerCertFile := strings.TrimSpace(os.Getenv("DOCKYARD_AGENT_SERVER_CERT_FILE"))
	agentServerKeyFile := strings.TrimSpace(os.Getenv("DOCKYARD_AGENT_SERVER_KEY_FILE"))
	if agentListenAddr != "" && (agentCACertificate == "" || agentServerCertFile == "" || agentServerKeyFile == "") {
		return Config{}, errors.New("agent listener requires CA, server certificate, and server key configuration")
	}
	agentCertificateTTL, err := time.ParseDuration(env("DOCKYARD_AGENT_CERTIFICATE_TTL", "168h"))
	if err != nil || agentCertificateTTL < 5*time.Minute || agentCertificateTTL > 30*24*time.Hour {
		return Config{}, errors.New("DOCKYARD_AGENT_CERTIFICATE_TTL must be between 5m and 720h")
	}
	var agentCAExpiresAt, agentPreviousCAExpiresAt, agentServerCertExpiresAt time.Time
	var agentCATrustBundle []byte
	if agentCACertificate != "" {
		authority, validationErr := agentpki.ValidateAuthority([]byte(agentCACertificate), []byte(agentCAKey), time.Now())
		if validationErr != nil {
			return Config{}, fmt.Errorf("validate agent CA: %w", validationErr)
		}
		agentCAExpiresAt = authority.NotAfter
		agentCATrustBundle = append([]byte(agentCACertificate), '\n')
		if agentPreviousCACertificate != "" {
			agentCATrustBundle = append(agentCATrustBundle, []byte(agentPreviousCACertificate)...)
			_, authorities, trustErr := agentpki.ValidateTrustBundle(agentCATrustBundle, time.Now())
			if trustErr != nil {
				return Config{}, fmt.Errorf("validate previous agent CA: %w", trustErr)
			}
			if len(authorities) != 2 {
				return Config{}, errors.New("agent CA rollover trust bundle must contain exactly two authorities")
			}
			if authorities[0].Equal(authorities[1]) {
				return Config{}, errors.New("previous agent CA must differ from the active agent CA")
			}
			agentPreviousCAExpiresAt = authorities[1].NotAfter
		}
	}
	if agentListenAddr != "" {
		serverCertificate, readErr := readStableConfigFile("DOCKYARD_AGENT_SERVER_CERT_FILE", agentServerCertFile, maxConfigSecretFileBytes)
		if readErr != nil {
			return Config{}, readErr
		}
		defer clear(serverCertificate)
		serverKey, readErr := readStableConfigFile("DOCKYARD_AGENT_SERVER_KEY_FILE", agentServerKeyFile, maxConfigSecretFileBytes)
		if readErr != nil {
			return Config{}, readErr
		}
		defer clear(serverKey)
		authority, server, validationErr := agentpki.ValidateServerCredentialsWithTrust([]byte(agentCACertificate), []byte(agentCAKey), agentCATrustBundle, serverCertificate, serverKey, time.Now())
		if validationErr != nil {
			return Config{}, fmt.Errorf("validate agent TLS credentials: %w", validationErr)
		}
		agentCAExpiresAt = authority.NotAfter
		agentServerCertExpiresAt = server.NotAfter
	}
	return Config{
		ListenAddr:                 env("DOCKYARD_LISTEN_ADDR", ":8080"),
		DatabaseURL:                databaseURL,
		RequireDatabaseTLS:         requireDatabaseTLS,
		MasterKey:                  key,
		MetricsToken:               metricsToken,
		DockerBin:                  env("DOCKYARD_DOCKER_BIN", "docker"),
		WorkerConcurrency:          concurrency,
		ExpectedControllerReplicas: expectedControllerReplicas,
		MaxBuildWorkspaceBytes:     maxBuildWorkspaceBytes,
		SessionTTL:                 ttl,
		TraefikNetwork:             traefikNetwork,
		EdgeProxyServiceName:       edgeProxyServiceName,
		EdgeProxyDynamicConfigPath: edgeProxyDynamicConfigPath,
		UnsafeWorkloads:            unsafeWorkloads,
		PublicURL:                  publicURL,
		BackupDirectory:            filepath.Clean(backupDirectory),
		RequireRemoteBackups:       requireRemoteBackups,
		OTLPEndpoint:               otlpEndpoint,
		OTLPInsecure:               otlpInsecure,
		ServiceName:                env("DOCKYARD_OTEL_SERVICE_NAME", "dockyard"),
		SwarmServiceName:           swarmServiceName,
		AgentCACertificate:         []byte(agentCACertificate),
		AgentCAKey:                 []byte(agentCAKey),
		AgentPreviousCACertificate: []byte(agentPreviousCACertificate),
		AgentCATrustBundle:         agentCATrustBundle,
		AgentCertificateTTL:        agentCertificateTTL,
		AgentCAExpiresAt:           agentCAExpiresAt,
		AgentPreviousCAExpiresAt:   agentPreviousCAExpiresAt,
		AgentServerCertExpiresAt:   agentServerCertExpiresAt,
		AgentListenAddr:            agentListenAddr,
		AgentServerCertFile:        agentServerCertFile,
		AgentServerKeyFile:         agentServerKeyFile,
		DatabaseDriverDirectory:    driverDirectory,
		TrustedProxyCIDRs:          trustedProxyCIDRs,
		EgressPrivateCIDRs:         egressPrivateCIDRs,
	}, nil
}

func ValidateDatabaseURL(databaseURL string, requireTLS bool) error {
	parsed, err := url.Parse(databaseURL)
	if err != nil || (parsed.Scheme != "postgres" && parsed.Scheme != "postgresql") || parsed.Hostname() == "" || parsed.Path == "" || parsed.Path == "/" || parsed.Opaque != "" || parsed.Fragment != "" {
		if requireTLS {
			return errors.New("DOCKYARD_DATABASE_URL must use a PostgreSQL URL with a host, database name, and sslmode=verify-full when DOCKYARD_REQUIRE_DATABASE_TLS=true")
		}
		return errors.New("DOCKYARD_DATABASE_URL must be a PostgreSQL URL with a host and database name")
	}
	if port := parsed.Port(); port != "" {
		value, parseErr := strconv.Atoi(port)
		if parseErr != nil || value < 1 || value > 65535 {
			return errors.New("DOCKYARD_DATABASE_URL must use a valid TCP port")
		}
	}
	sslModes := parsed.Query()["sslmode"]
	if len(sslModes) > 1 {
		return errors.New("DOCKYARD_DATABASE_URL must contain at most one sslmode parameter; sslmode=verify-full is required when database TLS is enforced")
	}
	if requireTLS && (len(sslModes) != 1 || sslModes[0] != "verify-full") {
		return errors.New("DOCKYARD_DATABASE_URL must use a PostgreSQL URL with sslmode=verify-full when DOCKYARD_REQUIRE_DATABASE_TLS=true")
	}
	return nil
}

// ValidateBundledDatabaseCredentials verifies the fixed PostgreSQL identity
// used by the single-node Swarm profile and prevents deploying a password
// secret that cannot authenticate the controller URL.
func ValidateBundledDatabaseCredentials(password, databaseURL string) error {
	if len(password) < 16 || len(password) > 4096 || strings.ContainsAny(password, "\x00\r\n") {
		return errors.New("DOCKYARD_DB_PASSWORD_FILE must contain between 16 and 4096 bytes without NUL or line breaks")
	}
	if err := ValidateDatabaseURL(databaseURL, false); err != nil {
		return err
	}
	parsed, _ := url.Parse(databaseURL)
	username, urlPassword, hasPassword := "", "", false
	if parsed.User != nil {
		username = parsed.User.Username()
		urlPassword, hasPassword = parsed.User.Password()
	}
	sslModes := parsed.Query()["sslmode"]
	if username != "dockyard" || !hasPassword || urlPassword != password || !strings.EqualFold(parsed.Hostname(), "postgres") || parsed.Path != "/dockyard" || parsed.Port() != "" && parsed.Port() != "5432" || len(sslModes) != 1 || sslModes[0] != "disable" {
		return errors.New("single-node database URL must use dockyard:<matching password>@postgres[:5432]/dockyard with exactly one sslmode=disable parameter")
	}
	return nil
}

func parseTrustedProxyCIDRs(raw string) ([]*net.IPNet, error) {
	if strings.TrimSpace(raw) == "" {
		return nil, nil
	}
	parts := strings.Split(raw, ",")
	if len(parts) > 32 {
		return nil, errors.New("DOCKYARD_TRUSTED_PROXY_CIDRS may contain at most 32 networks")
	}
	networks := make([]*net.IPNet, 0, len(parts))
	for _, part := range parts {
		value := strings.TrimSpace(part)
		_, network, parseErr := net.ParseCIDR(value)
		if parseErr != nil {
			return nil, fmt.Errorf("DOCKYARD_TRUSTED_PROXY_CIDRS contains invalid CIDR %q", value)
		}
		networks = append(networks, network)
	}
	return networks, nil
}

func loopbackHostname(host string) bool {
	host = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(host)), ".")
	if host == "localhost" || strings.HasSuffix(host, ".localhost") {
		return true
	}
	address := net.ParseIP(host)
	return address != nil && address.IsLoopback()
}

func validPublicURLHost(endpoint *url.URL) bool {
	host := endpoint.Hostname()
	if strings.HasPrefix(endpoint.Host, "[") && net.ParseIP(host) == nil {
		return false
	}
	if net.ParseIP(host) == nil {
		if len(host) == 0 || len(host) > 253 {
			return false
		}
		for _, label := range strings.Split(host, ".") {
			if len(label) == 0 || len(label) > 63 || !publicHostnameLabel.MatchString(label) {
				return false
			}
		}
	}
	return !strings.HasSuffix(endpoint.Host, ":")
}

func secretEnv(key string) (string, error) {
	value, path := os.Getenv(key), os.Getenv(key+"_FILE")
	if value != "" && path != "" {
		return "", fmt.Errorf("%s and %s_FILE cannot both be configured", key, key)
	}
	if value != "" {
		return strings.TrimSpace(value), nil
	}
	if path != "" {
		contents, err := readStableConfigFile(key+"_FILE", path, maxConfigSecretFileBytes)
		if err != nil {
			return "", err
		}
		defer clear(contents)
		return strings.TrimSpace(string(contents)), nil
	}
	return "", nil
}

func readStableConfigFile(name, path string, maximum int64) ([]byte, error) {
	before, err := os.Lstat(path)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", name, err)
	}
	if !before.Mode().IsRegular() {
		return nil, fmt.Errorf("%s must name a regular file, not a symbolic link or directory", name)
	}
	if before.Size() < 1 || before.Size() > maximum {
		return nil, fmt.Errorf("%s must contain between 1 and %d bytes", name, maximum)
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", name, err)
	}
	defer file.Close()
	opened, err := file.Stat()
	if err != nil || !opened.Mode().IsRegular() || !os.SameFile(before, opened) {
		return nil, fmt.Errorf("%s changed while it was opened", name)
	}
	contents, err := io.ReadAll(io.LimitReader(file, maximum+1))
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", name, err)
	}
	after, statErr := file.Stat()
	if statErr != nil || !os.SameFile(opened, after) || opened.Size() != after.Size() || !opened.ModTime().Equal(after.ModTime()) {
		clear(contents)
		return nil, fmt.Errorf("%s changed while it was read", name)
	}
	if int64(len(contents)) > maximum {
		clear(contents)
		return nil, fmt.Errorf("%s exceeds %d bytes", name, maximum)
	}
	return contents, nil
}

func env(key, fallback string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return fallback
}
