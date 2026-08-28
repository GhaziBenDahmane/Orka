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
