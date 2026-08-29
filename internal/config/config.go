package config

import (
	"encoding/base64"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/bendahma/dokploy-go/internal/agentpki"
)

type Config struct {
	ListenAddr               string
	DatabaseURL              string
	RequireDatabaseTLS       bool
	MasterKey                []byte
	DockerBin                string
	WorkerConcurrency        int
	SessionTTL               time.Duration
	TraefikNetwork           string
	UnsafeWorkloads          bool
	PublicURL                string
	BackupDirectory          string
	RequireRemoteBackups     bool
	OTLPEndpoint             string
	OTLPInsecure             bool
	ServiceName              string
	AgentCACertificate       []byte
	AgentCAKey               []byte
	AgentCertificateTTL      time.Duration
	AgentCAExpiresAt         time.Time
	AgentServerCertExpiresAt time.Time
	AgentListenAddr          string
	AgentServerCertFile      string
	AgentServerKeyFile       string
	DatabaseDriverDirectory  string
}

func Load() (Config, error) {
	ttl, err := time.ParseDuration(env("DOCKYARD_SESSION_TTL", "24h"))
	if err != nil {
		return Config{}, fmt.Errorf("parse DOCKYARD_SESSION_TTL: %w", err)
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
		if parseErr != nil || (parsed.Scheme != "postgres" && parsed.Scheme != "postgresql") || parsed.Hostname() == "" || parsed.Query().Get("sslmode") != "verify-full" {
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
	var agentCAExpiresAt, agentServerCertExpiresAt time.Time
	if agentCACertificate != "" {
		authority, validationErr := agentpki.ValidateAuthority([]byte(agentCACertificate), []byte(agentCAKey), time.Now())
		if validationErr != nil {
			return Config{}, fmt.Errorf("validate agent CA: %w", validationErr)
		}
		agentCAExpiresAt = authority.NotAfter
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
		authority, server, validationErr := agentpki.ValidateServerCredentials([]byte(agentCACertificate), []byte(agentCAKey), serverCertificate, serverKey, time.Now())
		if validationErr != nil {
			return Config{}, fmt.Errorf("validate agent TLS credentials: %w", validationErr)
		}
		agentCAExpiresAt = authority.NotAfter
		agentServerCertExpiresAt = server.NotAfter
	}
	return Config{
		ListenAddr:               env("DOCKYARD_LISTEN_ADDR", ":8080"),
		DatabaseURL:              databaseURL,
		RequireDatabaseTLS:       requireDatabaseTLS,
		MasterKey:                key,
		DockerBin:                env("DOCKYARD_DOCKER_BIN", "docker"),
		WorkerConcurrency:        concurrency,
		SessionTTL:               ttl,
		TraefikNetwork:           env("DOCKYARD_TRAEFIK_NETWORK", "dockyard-public"),
		UnsafeWorkloads:          unsafeWorkloads,
		PublicURL:                strings.TrimRight(env("DOCKYARD_PUBLIC_URL", "http://localhost:8080"), "/"),
		BackupDirectory:          filepath.Clean(backupDirectory),
		RequireRemoteBackups:     requireRemoteBackups,
		OTLPEndpoint:             otlpEndpoint,
		OTLPInsecure:             otlpInsecure,
		ServiceName:              env("DOCKYARD_OTEL_SERVICE_NAME", "dockyard"),
		AgentCACertificate:       []byte(agentCACertificate),
		AgentCAKey:               []byte(agentCAKey),
		AgentCertificateTTL:      agentCertificateTTL,
		AgentCAExpiresAt:         agentCAExpiresAt,
		AgentServerCertExpiresAt: agentServerCertExpiresAt,
		AgentListenAddr:          agentListenAddr,
		AgentServerCertFile:      agentServerCertFile,
		AgentServerKeyFile:       agentServerKeyFile,
		DatabaseDriverDirectory:  driverDirectory,
	}, nil
}

func secretEnv(key string) (string, error) {
	if value := os.Getenv(key); value != "" {
		return strings.TrimSpace(value), nil
	}
	if path := os.Getenv(key + "_FILE"); path != "" {
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
