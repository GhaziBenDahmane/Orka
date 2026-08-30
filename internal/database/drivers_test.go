package database

import (
	"encoding/base64"
	"net/url"
	"strings"
	"testing"
)

func TestLibSQLUsesUsableBasicAuthentication(t *testing.T) {
	result, err := NewRegistry().Render("libsql", Request{Name: "embedded", Config: map[string]any{"username": "libsql-user", "password": "libsql-password"}})
	if err != nil {
		t.Fatal(err)
	}
	wantAuth := "basic:" + base64.StdEncoding.EncodeToString([]byte("libsql-user:libsql-password"))
	if result.Environment["SQLD_HTTP_AUTH"] != wantAuth {
		t.Fatalf("SQLD_HTTP_AUTH = %q, want basic authentication", result.Environment["SQLD_HTTP_AUTH"])
	}
	if _, exists := result.Environment["SQLD_AUTH_JWT_KEY"]; exists {
		t.Fatal("libSQL was configured with a JWT verification key but no signing credential")
	}
	parsed, err := url.Parse(result.InternalURL)
	if err != nil {
		t.Fatal(err)
	}
	password, ok := parsed.User.Password()
	if !ok || parsed.User.Username() != "libsql-user" || password != "libsql-password" {
		t.Fatalf("libSQL internal URL does not contain usable credentials: %q", result.InternalURL)
	}
	if result.Version != "v0.24.33" {
		t.Fatalf("libSQL default version = %q", result.Version)
	}
	if _, err = NewRegistry().Render("libsql", Request{Name: "embedded", Config: map[string]any{"username": "invalid:user"}}); err == nil {
		t.Fatal("libSQL accepted an ambiguous Basic authentication username")
	}
}

func TestClickHouseUsesTestedImageVersion(t *testing.T) {
	result, err := NewRegistry().Render("clickhouse", Request{Name: "analytics", Config: map[string]any{"password": "clickhouse-password"}})
	if err != nil {
		t.Fatal(err)
	}
	if result.Version != "25.8-alpine" || !strings.Contains(result.ComposeYAML, "clickhouse/clickhouse-server:25.8-alpine") {
		t.Fatalf("ClickHouse image is not pinned to the tested release: version=%q compose=%q", result.Version, result.ComposeYAML)
	}
}

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

func TestRegistryEngineMetadataIsSortedAndComplete(t *testing.T) {
	engines := NewRegistry().Engines()
	if len(engines) != len(NewRegistry().Names()) {
		t.Fatalf("metadata count=%d", len(engines))
	}
	for index, engine := range engines {
		if index > 0 && engines[index-1].Name >= engine.Name {
			t.Fatalf("engine metadata is not sorted: %#v", engines)
		}
		if engine.Name == "" || engine.DefaultVersion == "" || engine.Source != "built-in" {
			t.Fatalf("incomplete built-in metadata: %#v", engine)
		}
		if !engine.BackupCapable || engine.BackupExtension == "" {
			t.Fatalf("built-in recovery metadata is incomplete: %#v", engine)
		}
	}
}

func TestNativeBackupAndRestorePlans(t *testing.T) {
	registry := NewRegistry()
	credentials := map[string]string{"username": "dockyard", "password": "secret", "database": "app"}
	for _, engine := range []string{"postgres", "mysql", "mariadb", "mongo", "redis", "valkey", "libsql", "clickhouse", "qdrant", "meilisearch"} {
		extension, ok := registry.BackupExtension(engine)
		if !ok {
			t.Fatalf("%s should support backups", engine)
		}
		filename := "123e4567-e89b-12d3-a456-426614174000." + extension
		backup, err := registry.Backup(engine, "17", "database", credentials, filename)
		if err != nil || backup.Extension != extension || len(backup.Command) == 0 {
			t.Fatalf("%s backup = %#v, err = %v", engine, backup, err)
		}
		if err = ValidateUtilityPlan(backup); err != nil {
			t.Fatalf("%s backup plan validation: %v", engine, err)
		}
		restore, err := registry.Restore(engine, "17", "database", credentials, filename)
		if err != nil || restore.Extension != extension || len(restore.Command) == 0 {
			t.Fatalf("%s restore = %#v, err = %v", engine, restore, err)
		}
		if err = ValidateUtilityPlan(restore); err != nil {
			t.Fatalf("%s restore plan validation: %v", engine, err)
		}
		joined := strings.Join(append(backup.Command, restore.Command...), " ")
		if strings.Contains(joined, credentials["password"]) {
			t.Fatalf("%s exposes its password in process arguments", engine)
		}
		if engine == "mongo" && !strings.Contains(backup.Files[filename+".config"], "secret") {
			t.Fatal("mongo password config was not generated")
		}
		if (engine == "redis" || engine == "valkey") && (backup.Environment["REDISCLI_AUTH"] != credentials["password"] || restore.Environment["REDISCLI_AUTH"] != credentials["password"] || !strings.Contains(restore.Command[3], "REPLICAOF")) {
			t.Fatalf("%s recovery plan is incomplete", engine)
		}
		if engine == "qdrant" && (backup.Environment["DOCKYARD_QDRANT_API_KEY"] != credentials["password"] || !strings.Contains(restore.Command[2], "multipart/form-data")) {
			t.Fatal("qdrant recovery plan is incomplete")
		}
		if engine == "meilisearch" && (backup.Environment["DOCKYARD_MEILI_MASTER_KEY"] != credentials["password"] || !strings.Contains(restore.Command[2], "/indexes/")) {
			t.Fatal("meilisearch recovery plan is incomplete")
		}
		if engine == "libsql" && (backup.Environment["DOCKYARD_LIBSQL_PASSWORD"] != credentials["password"] || !strings.Contains(restore.Command[2], "/v2/pipeline")) {
			t.Fatal("libSQL recovery plan is incomplete")
		}
		if engine == "clickhouse" && (backup.Environment["CLICKHOUSE_PASSWORD"] != credentials["password"] || !strings.Contains(restore.Command[3], "FORMAT Native")) {
			t.Fatal("ClickHouse recovery plan is incomplete")
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

func TestRedisRecoveryPlansRequireOnlyPassword(t *testing.T) {
	registry := NewRegistry()
	credentials := map[string]string{"password": "secret"}
	for _, engine := range []string{"redis", "valkey"} {
		if _, err := registry.Backup(engine, "8", "cache", credentials, "123e4567-e89b-12d3-a456-426614174000.rdb"); err != nil {
			t.Fatalf("%s password-only backup: %v", engine, err)
		}
		if _, err := registry.Restore(engine, "8", "cache", credentials, "123e4567-e89b-12d3-a456-426614174000.rdb"); err != nil {
			t.Fatalf("%s password-only restore: %v", engine, err)
		}
	}
	if _, err := registry.Backup("postgres", "17", "database", credentials, "123e4567-e89b-12d3-a456-426614174000.dump"); err == nil {
		t.Fatal("PostgreSQL backup accepted missing username and database")
	}
}

func TestNativeBackupPlansUseExplicitSourcePorts(t *testing.T) {
	registry := NewRegistry()
	for _, tc := range []struct {
		engine string
		want   string
	}{{"postgres", "--port 15432"}, {"mysql", "--port=13306"}, {"mariadb", "--port=13306"}, {"mongo", "--port 17017"}, {"redis", "-p 16379"}, {"valkey", "-p 16379"}, {"libsql", "DOCKYARD_LIBSQL_PORT=16379"}, {"clickhouse", "DOCKYARD_CLICKHOUSE_PORT=19000"}, {"qdrant", "DOCKYARD_QDRANT_PORT=16379"}, {"meilisearch", "DOCKYARD_MEILI_PORT=16379"}} {
		port := "13306"
		if tc.engine == "postgres" {
			port = "15432"
		} else if tc.engine == "mongo" {
			port = "17017"
		} else if tc.engine == "redis" || tc.engine == "valkey" || tc.engine == "libsql" || tc.engine == "qdrant" || tc.engine == "meilisearch" {
			port = "16379"
		} else if tc.engine == "clickhouse" {
			port = "19000"
		}
		plan, err := registry.Backup(tc.engine, "17", "source.internal", map[string]string{"username": "user", "password": "secret", "database": "app", "port": port}, "123e4567-e89b-12d3-a456-426614174000.dump")
		if err != nil {
			t.Fatalf("%s: %v", tc.engine, err)
		}
		got := strings.Join(plan.Command, " ")
		if tc.engine == "qdrant" {
			got = "DOCKYARD_QDRANT_PORT=" + plan.Environment["DOCKYARD_QDRANT_PORT"]
		} else if tc.engine == "meilisearch" {
			got = "DOCKYARD_MEILI_PORT=" + plan.Environment["DOCKYARD_MEILI_PORT"]
		} else if tc.engine == "libsql" {
			got = "DOCKYARD_LIBSQL_PORT=" + plan.Environment["DOCKYARD_LIBSQL_PORT"]
		} else if tc.engine == "clickhouse" {
			got = "DOCKYARD_CLICKHOUSE_PORT=" + plan.Environment["DOCKYARD_CLICKHOUSE_PORT"]
		}
		if !strings.Contains(got, tc.want) {
			t.Fatalf("%s command %q does not contain %q", tc.engine, got, tc.want)
		}
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

func TestRedisCompatibleDriversUseTheirOwnServerAndPasswordEnvironment(t *testing.T) {
	registry := NewRegistry()
	for _, tc := range []struct {
		engine string
		binary string
	}{{"redis", "redis-server"}, {"valkey", "valkey-server"}} {
		result, err := registry.Render(tc.engine, Request{Name: "cache", Config: map[string]any{"password": "cache-secret"}})
		if err != nil {
			t.Fatalf("%s: %v", tc.engine, err)
		}
		for _, expected := range []string{tc.binary, "DATABASE_PASSWORD=${DATABASE_PASSWORD}", "--requirepass", "redis://:cache-secret@cache:6379/0"} {
			value := result.ComposeYAML
			if strings.HasPrefix(expected, "redis://") {
				value = result.InternalURL
			}
			if !strings.Contains(value, expected) {
				t.Fatalf("%s output does not contain %q: compose=%q url=%q", tc.engine, expected, result.ComposeYAML, result.InternalURL)
			}
		}
	}
}

func TestConnectionURLSafelyEscapesCredentials(t *testing.T) {
	result, err := NewRegistry().Render("postgres", Request{Name: "data", Config: map[string]any{"username": "user@example.test", "password": "p@ss:/?#", "database": "app"}})
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := url.Parse(result.InternalURL)
	if err != nil {
		t.Fatal(err)
	}
	password, ok := parsed.User.Password()
	if !ok || parsed.User.Username() != "user@example.test" || password != "p@ss:/?#" || parsed.Host != "data:5432" || parsed.Path != "/app" {
		t.Fatalf("connection URL did not round-trip safely: %q", result.InternalURL)
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

func TestDatabaseReadinessPlansDoNotExposePasswords(t *testing.T) {
	registry := NewRegistry()
	credentials := map[string]string{"username": "app", "password": "very-secret", "database": "app"}
	for _, engine := range []string{"postgres", "mysql", "mariadb", "mongo", "redis", "valkey", "libsql", "clickhouse", "qdrant", "meilisearch"} {
		plan, err := registry.Readiness(engine, "17", "verify", credentials)
		if err != nil {
			t.Fatalf("%s readiness: %v", engine, err)
		}
		if strings.Contains(strings.Join(plan.Command, " "), credentials["password"]) {
			t.Fatalf("%s readiness command exposes password", engine)
		}
		if engine == "mongo" && plan.Environment["DOCKYARD_MONGO_PASSWORD"] != credentials["password"] {
			t.Fatal("mongo readiness password was not passed through the environment")
		}
	}
}
