package config

import (
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

type Config struct {
	ListenAddr        string
	DatabaseURL       string
	MasterKey         []byte
	DockerBin         string
	WorkerConcurrency int
	SessionTTL        time.Duration
	TraefikNetwork    string
	UnsafeWorkloads   bool
	PublicURL         string
	BackupDirectory   string
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
	backupDirectory := env("DOCKYARD_BACKUP_DIRECTORY", "/var/lib/dockyard/backups")
	if !filepath.IsAbs(backupDirectory) {
		return Config{}, errors.New("DOCKYARD_BACKUP_DIRECTORY must be absolute")
	}
	return Config{
		ListenAddr:        env("DOCKYARD_LISTEN_ADDR", ":8080"),
		DatabaseURL:       databaseURL,
		MasterKey:         key,
		DockerBin:         env("DOCKYARD_DOCKER_BIN", "docker"),
		WorkerConcurrency: concurrency,
		SessionTTL:        ttl,
		TraefikNetwork:    env("DOCKYARD_TRAEFIK_NETWORK", "dockyard-public"),
		UnsafeWorkloads:   unsafeWorkloads,
		PublicURL:         strings.TrimRight(env("DOCKYARD_PUBLIC_URL", "http://localhost:8080"), "/"),
		BackupDirectory:   filepath.Clean(backupDirectory),
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
