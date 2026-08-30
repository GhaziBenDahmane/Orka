package httpapi

import (
	"net/http"
	"strings"
)

const (
	scimListResponseSchema = "urn:ietf:params:scim:api:messages:2.0:ListResponse"
	scimResourceTypeSchema = "urn:ietf:params:scim:schemas:core:2.0:ResourceType"
	scimSchemaSchema       = "urn:ietf:params:scim:schemas:core:2.0:Schema"
)

func (s *Server) scimSchemas(w http.ResponseWriter, _ *http.Request) {
	resources := s.scimSchemaResources()
	scimJSON(w, http.StatusOK, map[string]any{
		"schemas": []string{scimListResponseSchema}, "totalResults": len(resources),
		"startIndex": 1, "itemsPerPage": len(resources), "Resources": resources,
	})
}

func (s *Server) scimSchema(w http.ResponseWriter, r *http.Request) {
	wanted := r.PathValue("schemaID")
	for _, resource := range s.scimSchemaResources() {
		if resource["id"] == wanted {
			scimJSON(w, http.StatusOK, resource)
			return
		}
	}
	scimError(w, http.StatusNotFound, "schema not found")
}

func (s *Server) scimResourceTypes(w http.ResponseWriter, _ *http.Request) {
	resources := s.scimResourceTypeResources()
	scimJSON(w, http.StatusOK, map[string]any{
		"schemas": []string{scimListResponseSchema}, "totalResults": len(resources),
		"startIndex": 1, "itemsPerPage": len(resources), "Resources": resources,
	})
}

func (s *Server) scimResourceType(w http.ResponseWriter, r *http.Request) {
	wanted := r.PathValue("resourceTypeID")
	for _, resource := range s.scimResourceTypeResources() {
		if resource["id"] == wanted {
			scimJSON(w, http.StatusOK, resource)
			return
		}
	}
	scimError(w, http.StatusNotFound, "resource type not found")
}

func (s *Server) scimSchemaResources() []map[string]any {
	baseURL := strings.TrimRight(s.PublicURL, "/")
	return []map[string]any{
		{
			"schemas": []string{scimSchemaSchema}, "id": scimUserSchema, "name": "User", "description": "Dockyard user account",
			"attributes": []map[string]any{
				{"name": "userName", "type": "string", "multiValued": false, "required": true, "caseExact": false, "mutability": "readWrite", "returned": "default", "uniqueness": "server"},
				{"name": "externalId", "type": "string", "multiValued": false, "required": false, "caseExact": true, "mutability": "readWrite", "returned": "default", "uniqueness": "none"},
				{"name": "displayName", "type": "string", "multiValued": false, "required": false, "caseExact": false, "mutability": "readWrite", "returned": "default", "uniqueness": "none"},
				{"name": "active", "type": "boolean", "multiValued": false, "required": false, "mutability": "readWrite", "returned": "default"},
			},
			"meta": map[string]string{"resourceType": "Schema", "location": baseURL + "/scim/v2/Schemas/" + scimUserSchema},
		},
		{
			"schemas": []string{scimSchemaSchema}, "id": scimGroupSchema, "name": "Group", "description": "Dockyard role-mapping group",
			"attributes": []map[string]any{
				{"name": "displayName", "type": "string", "multiValued": false, "required": true, "caseExact": false, "mutability": "readWrite", "returned": "default", "uniqueness": "server"},
				{"name": "externalId", "type": "string", "multiValued": false, "required": false, "caseExact": true, "mutability": "readWrite", "returned": "default", "uniqueness": "none"},
				{"name": "members", "type": "complex", "multiValued": true, "required": false, "mutability": "readWrite", "returned": "default"},
			},
			"meta": map[string]string{"resourceType": "Schema", "location": baseURL + "/scim/v2/Schemas/" + scimGroupSchema},
		},
	}
}

func (s *Server) scimResourceTypeResources() []map[string]any {
	baseURL := strings.TrimRight(s.PublicURL, "/")
	return []map[string]any{
		{"schemas": []string{scimResourceTypeSchema}, "id": "User", "name": "User", "endpoint": "/Users", "schema": scimUserSchema, "meta": map[string]string{"resourceType": "ResourceType", "location": baseURL + "/scim/v2/ResourceTypes/User"}},
		{"schemas": []string{scimResourceTypeSchema}, "id": "Group", "name": "Group", "endpoint": "/Groups", "schema": scimGroupSchema, "meta": map[string]string{"resourceType": "ResourceType", "location": baseURL + "/scim/v2/ResourceTypes/Group"}},
	}
}
