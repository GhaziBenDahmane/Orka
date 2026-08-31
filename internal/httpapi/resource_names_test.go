package httpapi

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestResourceCreationRejectsInvalidNamesBeforeDependencies(t *testing.T) {
	server := &Server{}
	tests := []struct {
		name string
		path string
		body map[string]any
		call func(http.ResponseWriter, *http.Request)
	}{
		{name: "project", path: "/v1/projects", body: map[string]any{"slug": "project"}, call: server.createProject},
		{name: "environment", path: "/v1/projects/project/environments", body: map[string]any{"slug": "environment"}, call: server.createEnvironment},
		{name: "service", path: "/v1/environments/environment/services", body: map[string]any{"slug": "service", "composeYaml": "services: {}"}, call: server.createService},
		{name: "database", path: "/v1/environments/environment/databases", body: map[string]any{"slug": "database", "engine": "postgres"}, call: server.createDatabase},
	}
	invalidNames := []string{"", "resource\nname", "resource\u0085name", strings.Repeat("n", 121)}
	for _, test := range tests {
		for index, invalidName := range invalidNames {
			t.Run(fmt.Sprintf("%s/invalid-%d", test.name, index), func(t *testing.T) {
				body := make(map[string]any, len(test.body)+1)
				for key, value := range test.body {
					body[key] = value
				}
				body["name"] = invalidName
				encoded, err := json.Marshal(body)
				if err != nil {
					t.Fatal(err)
				}
				recorder := httptest.NewRecorder()
				request := httptest.NewRequest(http.MethodPost, test.path, strings.NewReader(string(encoded)))
				request.Header.Set("Content-Type", "application/json")
				if test.name == "environment" {
					request.SetPathValue("projectID", "f47ac10b-58cc-4372-a567-0e02b2c3d479")
				} else if test.name == "service" || test.name == "database" {
					request.SetPathValue("environmentID", "f47ac10b-58cc-4372-a567-0e02b2c3d479")
				}
				test.call(recorder, request)
				if recorder.Code != http.StatusBadRequest || !strings.Contains(recorder.Body.String(), `"code":"invalid_name"`) {
					t.Fatalf("status=%d body=%s", recorder.Code, recorder.Body.String())
				}
			})
		}
	}
}

func TestNormalizeResourceNameTrimsSafeWhitespace(t *testing.T) {
	name, err := normalizeResourceName("  Production API  ")
	if err != nil || name != "Production API" {
		t.Fatalf("name=%q err=%v", name, err)
	}
}
