package httpapi

import (
	"os"
	"regexp"
	"strings"
	"testing"
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
			pathMarker := "  " + string(match[2]) + ":\n"
			methodMarker := "    " + strings.ToLower(string(match[1])) + ":\n"
			pathIndex := strings.Index(string(specification), pathMarker)
			if pathIndex < 0 || !strings.Contains(string(specification)[pathIndex:], methodMarker) {
				t.Errorf("OpenAPI is missing %s %s", match[1], match[2])
			}
		}
	}
}
