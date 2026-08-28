package httpapi

import (
	"net/http"

	"github.com/google/uuid"
)

func (s *Server) listDatabaseBackups(w http.ResponseWriter, r *http.Request) {
	databaseID, err := uuid.Parse(r.PathValue("databaseID"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid_id", "invalid database id")
		return
	}
	items, err := s.Store.ListDatabaseBackups(r.Context(), principal(r).OrganizationID, databaseID)
	if err != nil {
		writeStoreError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": items})
}

func (s *Server) listDatabaseRestores(w http.ResponseWriter, r *http.Request) {
	databaseID, err := uuid.Parse(r.PathValue("databaseID"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid_id", "invalid database id")
		return
	}
	items, err := s.Store.ListDatabaseRestores(r.Context(), principal(r).OrganizationID, databaseID)
	if err != nil {
		writeStoreError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": items})
}
