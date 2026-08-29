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
		if !strings.Contains(string(definition), `barktrace_version = "0.13.0"`) {
			t.Fatalf("%s template must pin the released 0.13.0 image", name)
		}
	}
}
