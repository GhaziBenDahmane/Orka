package templates

import (
	"encoding/json"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/bendahma/dokploy-go/internal/deploy"
	"gopkg.in/yaml.v3"
)

func TestBuiltinCatalogIsSwarmSafe(t *testing.T) {
	report, err := ValidateBuiltinCatalog(deploy.Compiler{PublicNetwork: "dockyard-public"})
	if err != nil {
		t.Fatal(err)
	}
	if report.Imported < 4 || len(report.Failed) > 0 {
		t.Fatalf("report=%#v", report)
	}
}

func TestBuiltinDatabaseTemplateCatalog(t *testing.T) {
	expectedVersions := map[string]string{
		"clickhouse":  "25.8-alpine",
		"libsql":      "v0.24.33",
		"mariadb":     "11.8",
		"meilisearch": "v1.20",
		"mongo":       "8",
		"mysql":       "8.4",
		"postgres":    "17-alpine",
		"qdrant":      "v1.15",
		"redis":       "8-alpine",
		"timescaledb": "2.29.2-pg17",
		"valkey":      "8-alpine",
	}
	entries, err := fs.ReadDir(builtinCatalog, "builtin/blueprints")
	if err != nil {
		t.Fatal(err)
	}
	ids := make([]string, 0, len(entries))
	for _, entry := range entries {
		if entry.IsDir() {
			ids = append(ids, entry.Name())
		}
	}
	sort.Strings(ids)
	expectedIDs := []string{"9router", "barktrace-postgres", "barktrace-sqlite", "clickhouse", "libsql", "mariadb", "meilisearch", "mongo", "mysql", "postgres", "qdrant", "redis", "timescaledb", "valkey"}
	if strings.Join(ids, ",") != strings.Join(expectedIDs, ",") {
		t.Fatalf("built-in template IDs = %v, want %v", ids, expectedIDs)
	}

	for id, version := range expectedVersions {
		t.Run(id, func(t *testing.T) {
			root := "builtin/blueprints/" + id
			metaBytes, err := fs.ReadFile(builtinCatalog, root+"/meta.json")
			if err != nil {
				t.Fatal(err)
			}
			var meta struct {
				ID string `json:"id"`
			}
			if err := json.Unmarshal(metaBytes, &meta); err != nil || meta.ID != id {
				t.Fatalf("invalid metadata ID: id=%q err=%v", meta.ID, err)
			}
			tomlBytes, err := fs.ReadFile(builtinCatalog, root+"/template.toml")
			if err != nil {
				t.Fatal(err)
			}
			definition, err := ParseDokploy(tomlBytes)
			if err != nil {
				t.Fatal(err)
			}
			if !variableHasDefault(definition, version) {
				t.Fatalf("template does not pin expected engine version %q", version)
			}
			for _, descriptor := range DescribeVariables(definition) {
				if strings.Contains(definition.Variables[descriptor.Name], "${password:") && (!descriptor.Generated || !descriptor.Sensitive) {
					t.Fatalf("generated secret %q must be classified generated and sensitive", descriptor.Name)
				}
			}

			composeBytes, err := fs.ReadFile(builtinCatalog, root+"/docker-compose.yml")
			if err != nil {
				t.Fatal(err)
			}
			if strings.Contains(strings.ToLower(string(composeBytes)), ":latest") {
				t.Fatal("database image must not use latest tag")
			}
			var compose struct {
				Volumes map[string]any `yaml:"volumes"`
			}
			if err := yaml.Unmarshal(composeBytes, &compose); err != nil {
				t.Fatal(err)
			}
			if len(compose.Volumes) == 0 {
				t.Fatal("database template must declare a named persistent volume")
			}
		})
	}
}

func variableHasDefault(template DokployTemplate, expected string) bool {
	for _, value := range template.Variables {
		if value == expected {
			return true
		}
	}
	return false
}

func TestTemplateSmokeVerifiesPersistedStateWithoutReseeding(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("..", "..", "scripts", "ci", "smoke-templates.sh"))
	if err != nil {
		t.Fatal(err)
	}
	script := string(raw)
	verifyStart := strings.Index(script, "verify_product_state() {")
	if verifyStart < 0 {
		t.Fatal("template smoke state verifier function is missing")
	}
	verifyEnd := strings.Index(script[verifyStart:], "\n}\n\ncleanup()")
	if verifyEnd < 0 {
		t.Fatal("template smoke state verifier function is missing")
	}
	verifyBody := script[verifyStart : verifyStart+verifyEnd]
	for _, mutation := range []string{"INSERT INTO dockyard_template_smoke", "INSERT OR REPLACE INTO dockyard_template_smoke", " SET dockyard:template:smoke ", "> /data/.dockyard-template-smoke"} {
		if strings.Contains(verifyBody, mutation) {
			t.Fatalf("post-restart verifier mutates persisted state with %q", mutation)
		}
	}
	loopStart := strings.Index(script, `for template_key in "${template_keys[@]}"; do`)
	if loopStart < 0 {
		t.Fatal("template smoke deployment loop is missing")
	}
	loop := script[loopStart:]
	seed := strings.Index(loop, `seed_product_state "$template_key"`)
	force := strings.Index(loop, `docker service update --force`)
	verifyAfterForce := -1
	if force >= 0 {
		verifyAfterForce = strings.Index(loop[force:], `verify_product_state "$template_key"`)
	}
	if seed < 0 || force < 0 || seed > force || verifyAfterForce < 0 {
		t.Fatal("template smoke must seed before and verify without mutation after forced replacement")
	}
	if !strings.Contains(loop, `docker service update --force --detach=false "${stack}_postgres"`) {
		t.Fatal("BarkTrace PostgreSQL smoke must replace its stateful database service")
	}
	if !strings.Contains(loop, `dependency_images="$(jq -cn --arg image "$postgres_image" '[{service:"postgres",image:$image}]')"`) {
		t.Fatal("BarkTrace PostgreSQL smoke must record its resolved database image")
	}
	if !strings.Contains(verifyBody, `stat -c '%d:%i' /data/barktrace.db`) {
		t.Fatal("BarkTrace SQLite smoke must verify the original database file survives replacement")
	}
	if !strings.Contains(script, `libsql_password":"template-smoke-libsql`) || !strings.Contains(verifyBody, `SELECT value FROM dockyard_template_smoke WHERE id=1`) {
		t.Fatal("libSQL template smoke must authenticate and verify persisted application data")
	}
	for _, evidence := range []string{"stateSeededBeforeRestart", "postRestartReadOnly", "dependencyRestartVerified", "sqliteFileIdentityVerified"} {
		if !strings.Contains(loop, evidence) {
			t.Fatalf("template conformance evidence is missing %s", evidence)
		}
	}
	releaseWorkflow, err := os.ReadFile(filepath.Join("..", "..", ".github", "workflows", "release.yml"))
	if err != nil {
		t.Fatal(err)
	}
	for _, evidence := range []string{"stateSeededBeforeRestart", "postRestartReadOnly", "dependencyRestartVerified", "sqliteFileIdentityVerified"} {
		if !strings.Contains(string(releaseWorkflow), evidence) {
			t.Fatalf("release promotion does not require template evidence field %s", evidence)
		}
	}
	if !strings.Contains(string(releaseWorkflow), `.dependencyImages | length == 1 and .[0].service == "postgres"`) {
		t.Fatal("release promotion does not require the BarkTrace PostgreSQL dependency image")
	}
	if !strings.Contains(string(releaseWorkflow), `.productCount == 6`) || !strings.Contains(string(releaseWorkflow), `["9router","barktrace-postgres","barktrace-sqlite","libsql","postgres","redis"]`) {
		t.Fatal("release promotion does not require the authenticated libSQL template smoke evidence")
	}
}

func TestBarkTraceTemplatePinsReleasedImage(t *testing.T) {
	for _, name := range []string{"barktrace-sqlite", "barktrace-postgres"} {
		definition, err := fs.ReadFile(builtinCatalog, "builtin/blueprints/"+name+"/template.toml")
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(string(definition), `barktrace_version = "0.31.0"`) {
			t.Fatalf("%s template must pin the released 0.31.0 image", name)
		}
	}
}

func TestNineRouterTemplatePinsReleasedImages(t *testing.T) {
	definition, err := fs.ReadFile(builtinCatalog, "builtin/blueprints/9router/template.toml")
	if err != nil {
		t.Fatal(err)
	}
	compose, err := fs.ReadFile(builtinCatalog, "builtin/blueprints/9router/docker-compose.yml")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(definition), `router_version = "0.5.59"`) ||
		!strings.Contains(string(definition), `headroom_version = "0.37.0"`) ||
		strings.Contains(string(definition), `"latest"`) {
		t.Fatalf("9Router template must pin released image versions: %s", definition)
	}
	if !strings.Contains(string(compose), "ghcr.io/headroomlabs-ai/headroom:${HEADROOM_VERSION}") {
		t.Fatalf("9Router template uses the wrong Headroom package: %s", compose)
	}
}

func TestExampleTemplateRepositoryIsImportable(t *testing.T) {
	report, err := ValidateDokployCatalog(
		filepath.Join("..", "..", "examples", "template-repository"),
		deploy.Compiler{PublicNetwork: "dockyard-public"},
	)
	if err != nil {
		t.Fatal(err)
	}
	if report.Imported != 1 || len(report.Failed) != 0 {
		t.Fatalf("example repository report=%#v", report)
	}
}

func TestBuiltinAdmissionChecksRoutesAndSafeComposeProfile(t *testing.T) {
	digestImage := "example@sha256:" + strings.Repeat("a", 64)
	tests := map[string]struct {
		toml    string
		compose string
	}{
		"missing route service": {
			toml:    "[variables]\ndomain = \"${domain}\"\n[[config.domains]]\nserviceName = \"missing\"\nport = 8080\nhost = \"${domain}\"\npath = \"/\"\n",
			compose: "services:\n  web:\n    image: " + digestImage + "\n",
		},
		"unsafe privilege": {
			toml:    "[variables]\n",
			compose: "services:\n  web:\n    image: " + digestImage + "\n    privileged: true\n",
		},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			if err := validateBuiltinBlueprint([]byte(test.toml), []byte(test.compose), deploy.Compiler{PublicNetwork: "dockyard-public", AllowUnsafe: true}); err == nil {
				t.Fatal("unsafe or unroutable built-in template passed startup admission")
			}
		})
	}
}
