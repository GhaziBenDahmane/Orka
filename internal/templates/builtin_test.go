package templates

import (
	"io/fs"
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
