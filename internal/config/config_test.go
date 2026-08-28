package config

import (
	"strings"
	"testing"
)

func TestLoadRequiresRemoteBackupsWhenConfigured(t *testing.T) {
	t.Setenv("DOCKYARD_DATABASE_URL", "postgres://dockyard@example.test/dockyard")
	t.Setenv("DOCKYARD_MASTER_KEY", "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=")
	t.Setenv("DOCKYARD_REQUIRE_REMOTE_BACKUPS", "true")
	cfg, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if !cfg.RequireRemoteBackups {
		t.Fatal("remote backup requirement was not enabled")
	}
}

func TestLoadRejectsInvalidRemoteBackupPolicy(t *testing.T) {
	t.Setenv("DOCKYARD_DATABASE_URL", "postgres://dockyard@example.test/dockyard")
	t.Setenv("DOCKYARD_MASTER_KEY", "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=")
	t.Setenv("DOCKYARD_REQUIRE_REMOTE_BACKUPS", "sometimes")
	_, err := Load()
	if err == nil || !strings.Contains(err.Error(), "DOCKYARD_REQUIRE_REMOTE_BACKUPS") {
		t.Fatalf("error=%v", err)
	}
}

func TestLoadRequiresVerifiedDatabaseTLSWhenConfigured(t *testing.T) {
	t.Setenv("DOCKYARD_MASTER_KEY", "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=")
	t.Setenv("DOCKYARD_REQUIRE_DATABASE_TLS", "true")
	for _, databaseURL := range []string{
		"postgres://dockyard@example.test/dockyard",
		"postgres://dockyard@example.test/dockyard?sslmode=disable",
		"postgres://dockyard@example.test/dockyard?sslmode=require",
		"host=example.test dbname=dockyard sslmode=verify-full",
	} {
		t.Run(databaseURL, func(t *testing.T) {
			t.Setenv("DOCKYARD_DATABASE_URL", databaseURL)
			if _, err := Load(); err == nil || !strings.Contains(err.Error(), "sslmode=verify-full") {
				t.Fatalf("error=%v", err)
			}
		})
	}
	t.Setenv("DOCKYARD_DATABASE_URL", "postgresql://dockyard@example.test/dockyard?sslmode=verify-full")
	cfg, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if !cfg.RequireDatabaseTLS {
		t.Fatal("database TLS requirement was not enabled")
	}
}
