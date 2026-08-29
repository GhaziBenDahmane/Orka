package templates

import (
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
