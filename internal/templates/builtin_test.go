package templates

import (
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/bendahma/dokploy-go/internal/deploy"
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
	for _, mutation := range []string{"INSERT INTO dockyard_template_smoke", " SET dockyard:template:smoke ", "> /data/.dockyard-template-smoke"} {
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
