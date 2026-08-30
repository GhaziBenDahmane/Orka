package httpapi

import (
	"os"
	"regexp"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

func TestOpenAPIContainsEveryRegisteredRoute(t *testing.T) {
	specification, err := os.ReadFile("../../api/openapi.yaml")
	if err != nil {
		t.Fatal(err)
	}
	routePattern := regexp.MustCompile(`"(GET|POST|PUT|PATCH|DELETE) (/[^" ]+)"`)
	for _, file := range []string{"server.go", "clusters.go"} {
		source, err := os.ReadFile(file)
		if err != nil {
			t.Fatal(err)
		}
		for _, match := range routePattern.FindAllSubmatch(source, -1) {
			if string(match[2]) == "/" {
				continue
			}
			pathMarker := "  " + string(match[2]) + ":\n"
			methodMarker := "    " + strings.ToLower(string(match[1])) + ":\n"
			pathIndex := strings.Index(string(specification), pathMarker)
			if pathIndex < 0 || !strings.Contains(string(specification)[pathIndex:], methodMarker) {
				t.Errorf("OpenAPI is missing %s %s", match[1], match[2])
			}
		}
	}
}

func TestOpenAPI31SecurityClassification(t *testing.T) {
	specification, err := os.ReadFile("../../api/openapi.yaml")
	if err != nil {
		t.Fatal(err)
	}
	type operation struct {
		Security *[]map[string][]string `yaml:"security"`
	}
	var document struct {
		OpenAPI  string                          `yaml:"openapi"`
		Security []map[string][]string           `yaml:"security"`
		Paths    map[string]map[string]operation `yaml:"paths"`
	}
	if err := yaml.Unmarshal(specification, &document); err != nil {
		t.Fatalf("parse OpenAPI: %v", err)
	}
	if document.OpenAPI != "3.1.0" {
		t.Fatalf("OpenAPI version=%q, want 3.1.0", document.OpenAPI)
	}
	if len(document.Security) != 1 || document.Security[0]["bearerAuth"] == nil {
		t.Fatalf("global bearer security is missing: %#v", document.Security)
	}
	public := func(path string) bool {
		if path == "/healthz" || path == "/readyz" || path == "/v1/auth/bootstrap" || path == "/v1/auth/login" || path == "/v1/invitations/accept" || path == "/v1/agent/enroll" {
			return true
		}
		return strings.HasPrefix(path, "/v1/auth/sso/") || strings.HasPrefix(path, "/v1/auth/saml/") || strings.HasPrefix(path, "/v1/hooks/")
	}
	for path, methods := range document.Paths {
		for method, op := range methods {
			if public(path) {
				if op.Security == nil || len(*op.Security) != 0 {
					t.Errorf("%s %s must explicitly disable global authentication", strings.ToUpper(method), path)
				}
				continue
			}
			if strings.HasPrefix(path, "/v1/agent/") {
				if op.Security == nil || len(*op.Security) != 1 || (*op.Security)[0]["mutualTLS"] == nil {
					t.Errorf("%s %s must require mutual TLS", strings.ToUpper(method), path)
				}
				continue
			}
			if path == "/metrics" {
				if op.Security == nil || len(*op.Security) != 1 || (*op.Security)[0]["metricsBearer"] == nil {
					t.Errorf("%s %s must require the dedicated metrics bearer token", strings.ToUpper(method), path)
				}
				continue
			}
			if op.Security != nil {
				t.Errorf("%s %s should inherit global bearer authentication", strings.ToUpper(method), path)
			}
		}
	}
}

func TestOpenAPIDocumentsStructuredDatabaseEngineResponse(t *testing.T) {
	specification, err := os.ReadFile("../../api/openapi.yaml")
	if err != nil {
		t.Fatal(err)
	}
	text := string(specification)
	for _, expected := range []string{"#/components/schemas/DatabaseEngineList", "required: [name, defaultVersion, source, backupCapable, backupExtension]", "enum: [built-in, external]", "artifactDigest: {type: string, pattern: '^sha256:[a-f0-9]{64}$'}"} {
		if !strings.Contains(text, expected) {
			t.Errorf("OpenAPI is missing %q", expected)
		}
	}
}
