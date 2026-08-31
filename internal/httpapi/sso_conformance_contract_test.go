package httpapi

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestKeycloakConformanceHarnessRequiresBothFlows(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("..", "..", "scripts", "ci", "test-keycloak-oidc.sh"))
	if err != nil {
		t.Fatal(err)
	}
	script := string(raw)
	for _, testName := range []string{"TestKeycloakOIDCConformance", "TestKeycloakSAMLConformance"} {
		if !strings.Contains(script, "^--- PASS: "+testName+" ") {
			t.Fatalf("Keycloak harness does not require an explicit PASS for %s", testName)
		}
	}
	if !strings.Contains(script, `-test.run='^TestKeycloak(OIDC|SAML)Conformance$'`) {
		t.Fatal("Keycloak harness does not select the exact OIDC and SAML conformance tests")
	}
}
