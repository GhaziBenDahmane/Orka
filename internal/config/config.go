package config

import (
	"encoding/base64"
	"errors"
	"fmt"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/bendahma/dokploy-go/internal/agentpki"
)

type Config struct {
	ListenAddr                 string
	DatabaseURL                string
	RequireDatabaseTLS         bool
	MasterKey                  []byte
	MetricsToken               string
	DockerBin                  string
	WorkerConcurrency          int
	SessionTTL                 time.Duration
	TraefikNetwork             string
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
}

var swarmNetworkName = regexp.MustCompile(`^[a-z0-9][a-z0-9_.-]{0,62}$`)

func Load() (Config, error) {
	ttl, err := time.ParseDuration(env("DOCKYARD_SESSION_TTL", "24h"))
	if err != nil || ttl < 5*time.Minute || ttl > 30*24*time.Hour {
		return Config{}, errors.New("DOCKYARD_SESSION_TTL must be between 5m and 720h")
	}
	concurrency, err := strconv.Atoi(env("DOCKYARD_WORKER_CONCURRENCY", "2"))
	if err != nil || concurrency < 1 || concurrency > 32 {
		return Config{}, errors.New("DOCKYARD_WORKER_CONCURRENCY must be between 1 and 32")
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
	if databaseURL == "" {
		return Config{}, errors.New("DOCKYARD_DATABASE_URL is required")
	}
	requireDatabaseTLS, err := strconv.ParseBool(env("DOCKYARD_REQUIRE_DATABASE_TLS", "false"))
	if err != nil {
		return Config{}, fmt.Errorf("parse DOCKYARD_REQUIRE_DATABASE_TLS: %w", err)
	}
	if requireDatabaseTLS {
		parsed, parseErr := url.Parse(databaseURL)
		var sslModes []string
		if parseErr == nil {
			sslModes = parsed.Query()["sslmode"]
		}
		if parseErr != nil || (parsed.Scheme != "postgres" && parsed.Scheme != "postgresql") || parsed.Hostname() == "" || len(sslModes) != 1 || sslModes[0] != "verify-full" {
			return Config{}, errors.New("DOCKYARD_DATABASE_URL must use a PostgreSQL URL with sslmode=verify-full when DOCKYARD_REQUIRE_DATABASE_TLS=true")
		}
	}
	backupDirectory := env("DOCKYARD_BACKUP_DIRECTORY", "/var/lib/dockyard/backups")
	if !filepath.IsAbs(backupDirectory) {
		return Config{}, errors.New("DOCKYARD_BACKUP_DIRECTORY must be absolute")
	}
	requireRemoteBackups, err := strconv.ParseBool(env("DOCKYARD_REQUIRE_REMOTE_BACKUPS", "false"))
	if err != nil {
		return Config{}, fmt.Errorf("parse DOCKYARD_REQUIRE_REMOTE_BACKUPS: %w", err)
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
	publicURL := strings.TrimRight(strings.TrimSpace(env("DOCKYARD_PUBLIC_URL", "http://localhost:8080")), "/")
	parsedPublicURL, err := url.Parse(publicURL)
	if err != nil || (parsedPublicURL.Scheme != "http" && parsedPublicURL.Scheme != "https") || parsedPublicURL.Hostname() == "" || parsedPublicURL.User != nil || parsedPublicURL.RawQuery != "" || parsedPublicURL.Fragment != "" || (parsedPublicURL.Path != "" && parsedPublicURL.Path != "/") {
		return Config{}, errors.New("DOCKYARD_PUBLIC_URL must be an HTTP(S) origin without credentials, path, query, or fragment")
	}
	if parsedPublicURL.Scheme != "https" && !loopbackHostname(parsedPublicURL.Hostname()) {
		return Config{}, errors.New("DOCKYARD_PUBLIC_URL must use HTTPS except for loopback development")
	}
	traefikNetwork := strings.TrimSpace(env("DOCKYARD_TRAEFIK_NETWORK", "dockyard-public"))
	if !swarmNetworkName.MatchString(traefikNetwork) {
		return Config{}, errors.New("DOCKYARD_TRAEFIK_NETWORK must be a lowercase Docker network name of at most 63 characters")
	}
	swarmServiceName := strings.TrimSpace(os.Getenv("DOCKYARD_SWARM_SERVICE_NAME"))
	if swarmServiceName != "" && !regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$`).MatchString(swarmServiceName) {
		return Config{}, errors.New("DOCKYARD_SWARM_SERVICE_NAME must be a valid Swarm service name")
	}
	trustedProxyCIDRs, err := parseTrustedProxyCIDRs(os.Getenv("DOCKYARD_TRUSTED_PROXY_CIDRS"))
	if err != nil {
		return Config{}, err
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
		serverCertificate, readErr := os.ReadFile(agentServerCertFile)
		if readErr != nil {
			return Config{}, fmt.Errorf("read DOCKYARD_AGENT_SERVER_CERT_FILE: %w", readErr)
		}
		serverKey, readErr := os.ReadFile(agentServerKeyFile)
		if readErr != nil {
			return Config{}, fmt.Errorf("read DOCKYARD_AGENT_SERVER_KEY_FILE: %w", readErr)
		}
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
		SessionTTL:                 ttl,
		TraefikNetwork:             traefikNetwork,
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
	}, nil
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

func secretEnv(key string) (string, error) {
	value, path := os.Getenv(key), os.Getenv(key+"_FILE")
	if value != "" && path != "" {
		return "", fmt.Errorf("%s and %s_FILE cannot both be configured", key, key)
	}
	if value != "" {
		return strings.TrimSpace(value), nil
	}
	if path != "" {
		value, err := os.ReadFile(path)
		if err != nil {
			return "", fmt.Errorf("read %s_FILE: %w", key, err)
		}
		return strings.TrimSpace(string(value)), nil
	}
	return "", nil
}

func env(key, fallback string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return fallback
}
