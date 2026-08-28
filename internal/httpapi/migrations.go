package httpapi

import (
	"net/http"
	"strings"
)

func (s *Server) listMigrationResources(w http.ResponseWriter, r *http.Request) {
	sourceOrganizationID := strings.TrimSpace(r.URL.Query().Get("sourceOrganizationId"))
	if len(sourceOrganizationID) > 255 {
		writeError(w, http.StatusBadRequest, "invalid_source_organization", "sourceOrganizationId is too long")
		return
	}
	items, err := s.Store.ListMigrationResources(r.Context(), principal(r).OrganizationID, sourceOrganizationID)
	if err != nil {
		writeStoreError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": items})
}
