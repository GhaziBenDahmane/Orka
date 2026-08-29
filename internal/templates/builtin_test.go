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
	definition, err := fs.ReadFile(builtinCatalog, "builtin/blueprints/barktrace-sqlite/template.toml")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(definition), `barktrace_version = "sha-071bf79"`) {
		t.Fatal("BarkTrace template must pin the released sha-071bf79 image")
	}
}
