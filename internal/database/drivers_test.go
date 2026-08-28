package database

import (
	"strings"
	"testing"
)

func TestRegistryRendersAllDrivers(t *testing.T) {
	registry := NewRegistry()
	if len(registry.Names()) < 10 {
		t.Fatalf("expected broad driver catalog, got %v", registry.Names())
	}
	for _, engine := range registry.Names() {
		result, err := registry.Render(engine, Request{Name: "data"})
		if err != nil {
			t.Fatalf("%s: %v", engine, err)
		}
		if !strings.Contains(result.ComposeYAML, "services:") || result.InternalURL == "" || result.Version == "" {
			t.Fatalf("%s returned incomplete result", engine)
		}
	}
}

func TestNativeBackupAndRestorePlans(t *testing.T) {
	registry := NewRegistry()
	credentials := map[string]string{"username": "dockyard", "password": "secret", "database": "app"}
	for _, engine := range []string{"postgres", "mysql", "mariadb", "mongo"} {
		extension, ok := registry.BackupExtension(engine)
		if !ok {
			t.Fatalf("%s should support backups", engine)
		}
		filename := "123e4567-e89b-12d3-a456-426614174000." + extension
		backup, err := registry.Backup(engine, "17", "database", credentials, filename)
		if err != nil || backup.Extension != extension || len(backup.Command) == 0 {
			t.Fatalf("%s backup = %#v, err = %v", engine, backup, err)
		}
		restore, err := registry.Restore(engine, "17", "database", credentials, filename)
		if err != nil || restore.Extension != extension || len(restore.Command) == 0 {
			t.Fatalf("%s restore = %#v, err = %v", engine, restore, err)
		}
		joined := strings.Join(append(backup.Command, restore.Command...), " ")
		if strings.Contains(joined, credentials["password"]) {
			t.Fatalf("%s exposes its password in process arguments", engine)
		}
		if engine == "mongo" && !strings.Contains(backup.Files[filename+".config"], "secret") {
			t.Fatal("mongo password config was not generated")
		}
	}
}

func TestNativeBackupPlanRejectsUnsafeInput(t *testing.T) {
	registry := NewRegistry()
	credentials := map[string]string{"username": "user", "password": "secret", "database": "app"}
	if _, err := registry.Backup("mysql", "8;evil", "database", credentials, "id.sql"); err == nil {
		t.Fatal("expected unsafe version rejection")
	}
	if _, err := registry.Backup("mysql", "8", "database", credentials, "../../dump.sql"); err == nil {
		t.Fatal("expected unsafe filename rejection")
	}
}

func TestRegistryUsesImportedCredentialsAndImage(t *testing.T) {
	result, err := NewRegistry().Render("postgres", Request{Name: "data", Version: "16", Config: map[string]any{"username": "legacy", "password": "migrated-secret", "database": "legacy_db", "image": "registry.example.test/postgres:16.4"}})
	if err != nil {
		t.Fatal(err)
	}
	if result.Credentials["username"] != "legacy" || result.Credentials["password"] != "migrated-secret" || result.Credentials["database"] != "legacy_db" {
		t.Fatalf("credentials were not preserved: %#v", result.Credentials)
	}
	for _, expected := range []string{"registry.example.test/postgres:16.4", "POSTGRES_USER=${POSTGRES_USER}", "POSTGRES_PASSWORD=${POSTGRES_PASSWORD}"} {
		if !strings.Contains(result.ComposeYAML, expected) {
			t.Fatalf("compose does not contain %q:\n%s", expected, result.ComposeYAML)
		}
	}
}

func TestStoredConfigRemovesPasswords(t *testing.T) {
	stored := StoredConfig(map[string]any{"username": "legacy", "password": "user-secret", "rootPassword": "root-secret", "image": "postgres:16"})
	if _, ok := stored["password"]; ok {
		t.Fatal("password was retained in stored config")
	}
	if _, ok := stored["rootPassword"]; ok {
		t.Fatal("root password was retained in stored config")
	}
	if stored["username"] != "legacy" || stored["image"] != "postgres:16" {
		t.Fatalf("non-secret config was not retained: %#v", stored)
	}
}
