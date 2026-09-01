package migrate

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/GhaziBenDahmane/Orka/internal/store"
	"github.com/google/uuid"
)

func TestParseDokployDatabaseTransferManifest(t *testing.T) {
	manifest, err := ParseDokployDatabaseTransferManifest([]byte(`{"version":1,"connections":[{"sourceId":" db-1 ","host":"postgres.internal","port":15432,"username":"legacy","password":"private","database":"app"}]}`))
	if err != nil {
		t.Fatal(err)
	}
	if got := manifest.Connections[0]; got.SourceID != "db-1" || got.Host != "postgres.internal" || got.Port != 15432 {
		t.Fatalf("unexpected normalized connection: %#v", got)
	}
}

func TestParseDokployDatabaseTransferManifestAllowsPasswordOnlyStores(t *testing.T) {
	manifest, err := ParseDokployDatabaseTransferManifest([]byte(`{"version":1,"connections":[{"sourceId":"redis-1","host":"redis.internal","password":"private"}]}`))
	if err != nil {
		t.Fatal(err)
	}
	if got := manifest.Connections[0]; got.Username != "" || got.Database != "" || got.Password != "private" {
		t.Fatalf("unexpected password-only connection: %#v", got)
	}
}

func TestDokployDatabaseTransferSupportsEveryImportedRecoverableEngine(t *testing.T) {
	for _, engine := range []string{"postgres", "timescaledb", "mysql", "mariadb", "mongo", "redis", "valkey", "libsql"} {
		if !dokployTransferCapableEngine(engine) {
			t.Fatalf("%s should support native Dokploy data transfer", engine)
		}
	}
	for _, engine := range []string{"clickhouse", "qdrant", "meilisearch"} {
		if dokployTransferCapableEngine(engine) {
			t.Fatalf("%s is not an imported Dokploy managed-database type", engine)
		}
	}
}

func TestClassifyDokployDatabaseCompatibilityImages(t *testing.T) {
	tests := []struct{ source, image, want string }{
		{"postgres", "timescale/timescaledb:2.29.2-pg17", "timescaledb"},
		{"postgres", "docker.io/timescale/timescaledb@sha256:" + strings.Repeat("a", 64), "timescaledb"},
		{"redis", "valkey/valkey:8", "valkey"},
		{"redis", "registry-1.docker.io/valkey/valkey:8", "valkey"},
		{"postgres", "registry.example.test/timescale/timescaledb:2.29.2-pg17", "postgres"},
		{"redis", "redis:8", "redis"},
	}
	for _, test := range tests {
		if got := classifyDokployDatabaseEngine(test.source, test.image); got != test.want {
			t.Errorf("classify %s image %q = %q, want %q", test.source, test.image, got, test.want)
		}
	}
}

func TestDetectedDatabaseEnginePreservesDokployIdentity(t *testing.T) {
	options := DokployOptions{SourceOrganizationID: "source", TargetOrganizationID: uuid.MustParse("3b7dcb53-c4a5-42cb-998e-1b18a827cb52")}
	legacy := sourceDatabase{id: "database-1", sourceEngine: "postgres", engine: "postgres"}
	detected := sourceDatabase{id: "database-1", sourceEngine: "postgres", engine: "timescaledb"}
	if mappedDokployDatabaseID(options, "database", legacy) != mappedDokployDatabaseID(options, "database", detected) || detected.identity() != "postgres:database-1" {
		t.Fatal("compatible engine detection changed stable Dokploy resource identity")
	}
}

func TestParseDokployDatabaseTransferManifestRejectsInvalidInput(t *testing.T) {
	tests := map[string]string{
		"unknown field":  `{"version":1,"extra":true,"connections":[{"sourceId":"db-1","host":"db","username":"u","password":"p","database":"d"}]}`,
		"duplicate id":   `{"version":1,"connections":[{"sourceId":"db-1","host":"db","username":"u","password":"p","database":"d"},{"sourceId":"db-1","host":"db","username":"u","password":"p","database":"d"}]}`,
		"unsafe host":    `{"version":1,"connections":[{"sourceId":"db-1","host":"db;evil","username":"u","password":"p","database":"d"}]}`,
		"empty password": `{"version":1,"connections":[{"sourceId":"db-1","host":"db","username":"u","database":"d"}]}`,
		"trailing json":  `{"version":1,"connections":[{"sourceId":"db-1","host":"db","username":"u","password":"p","database":"d"}]} {}`,
	}
	for name, input := range tests {
		t.Run(name, func(t *testing.T) {
			if _, err := ParseDokployDatabaseTransferManifest([]byte(input)); err == nil {
				t.Fatal("expected validation error")
			}
		})
	}
}

func TestParseDokployDatabaseTransferManifestRejectsOversizedInput(t *testing.T) {
	if _, err := ParseDokployDatabaseTransferManifest(make([]byte, (1<<20)+1)); err == nil {
		t.Fatal("expected oversized manifest rejection")
	}
}

func TestDatabaseTransferReportDoesNotSerializeSourceSecrets(t *testing.T) {
	manifest, err := ParseDokployDatabaseTransferManifest([]byte(`{"version":1,"connections":[{"sourceId":"db-1","host":"db","username":"legacy-user","password":"legacy-secret","database":"legacy-db"}]}`))
	if err != nil {
		t.Fatal(err)
	}
	if got := strings.Join([]string{manifest.Connections[0].Username, manifest.Connections[0].Password}, ":"); got == "" {
		t.Fatal("fixture was not parsed")
	}
	// DatabaseMigration deliberately exposes only source identity and host;
	// encrypted connection material is excluded by its json tag.
	report := DokployDatabaseTransferReport{Items: []store.DatabaseMigration{{EncryptedSourceConfig: "legacy-secret"}}}
	if strings.Contains(reportJSON(t, report), "legacy-secret") {
		t.Fatal("report exposed source password")
	}
}

func reportJSON(t *testing.T, report DokployDatabaseTransferReport) string {
	t.Helper()
	data, err := json.Marshal(report)
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}
