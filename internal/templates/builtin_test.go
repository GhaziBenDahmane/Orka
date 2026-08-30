package templates

import (
	"io/fs"
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
