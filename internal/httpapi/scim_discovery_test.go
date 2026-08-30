package httpapi

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestSCIMDiscoveryEndpoints(t *testing.T) {
	server := httptest.NewServer((&Server{PublicURL: "https://dockyard.example.test"}).Handler())
	t.Cleanup(server.Close)

	for _, path := range []string{
		"/scim/v2/ServiceProviderConfig",
		"/scim/v2/Schemas",
		"/scim/v2/Schemas/" + scimUserSchema,
		"/scim/v2/Schemas/" + scimGroupSchema,
		"/scim/v2/ResourceTypes",
		"/scim/v2/ResourceTypes/User",
		"/scim/v2/ResourceTypes/Group",
	} {
		response, err := http.Get(server.URL + path)
		if err != nil {
			t.Fatal(err)
		}
		if response.StatusCode != http.StatusOK {
			response.Body.Close()
			t.Errorf("GET %s status=%d", path, response.StatusCode)
			continue
		}
		if contentType := response.Header.Get("Content-Type"); !strings.HasPrefix(contentType, "application/scim+json") {
			response.Body.Close()
			t.Errorf("GET %s Content-Type=%q", path, contentType)
			continue
		}
		var payload map[string]any
		if err = json.NewDecoder(response.Body).Decode(&payload); err != nil {
			response.Body.Close()
			t.Errorf("GET %s invalid JSON: %v", path, err)
			continue
		}
		response.Body.Close()
		if len(payload["schemas"].([]any)) == 0 {
			t.Errorf("GET %s omitted schemas", path)
		}
		if path == "/scim/v2/ServiceProviderConfig" && payload["etag"].(map[string]any)["supported"] != true {
			t.Errorf("GET %s did not advertise ETag support: %#v", path, payload["etag"])
		}
	}

	for _, path := range []string{"/scim/v2/Schemas/unknown", "/scim/v2/ResourceTypes/unknown"} {
		response, err := http.Get(server.URL + path)
		if err != nil {
			t.Fatal(err)
		}
		response.Body.Close()
		if response.StatusCode != http.StatusNotFound {
			t.Errorf("GET %s status=%d, want 404", path, response.StatusCode)
		}
	}
}

func TestSCIMDiscoveryMetadataIsComplete(t *testing.T) {
	s := &Server{PublicURL: "https://dockyard.example.test/"}
	schemas := s.scimSchemaResources()
	resourceTypes := s.scimResourceTypeResources()
	if len(schemas) != 2 || len(resourceTypes) != 2 {
		t.Fatalf("schemas=%d resourceTypes=%d", len(schemas), len(resourceTypes))
	}
	for _, resource := range resourceTypes {
		if resource["id"] == "" || resource["endpoint"] == "" || resource["schema"] == "" || resource["meta"] == nil {
			t.Errorf("incomplete resource type: %#v", resource)
		}
	}
}
