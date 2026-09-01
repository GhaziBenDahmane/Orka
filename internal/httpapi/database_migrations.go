package httpapi

import (
	"errors"
	"net/http"

	"github.com/GhaziBenDahmane/Orka/internal/store"
	"github.com/google/uuid"
)

func (s *Server) listDatabaseMigrations(w http.ResponseWriter, r *http.Request) {
	databaseID, err := uuid.Parse(r.PathValue("databaseID"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid_id", "invalid database id")
		return
	}
	items, err := s.Store.ListDatabaseMigrations(r.Context(), principal(r).OrganizationID, databaseID)
	if err != nil {
		writeStoreError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": items})
}

func (s *Server) getDatabaseMigration(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(r.PathValue("migrationID"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid_id", "invalid database migration id")
		return
	}
	item, err := s.Store.GetDatabaseMigration(r.Context(), principal(r).OrganizationID, id)
	if err != nil {
		writeStoreError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, item)
}

func (s *Server) cancelDatabaseMigration(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(r.PathValue("migrationID"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid_id", "invalid database migration id")
		return
	}
	p := principal(r)
	if err = s.Store.CancelDatabaseMigrationWithAudit(r.Context(), p, id, r.RemoteAddr); err != nil {
		if errors.Is(err, store.ErrNotCancellable) {
			writeError(w, http.StatusConflict, "not_cancellable", err.Error())
			return
		}
		writeStoreError(w, err)
		return
	}
	writeJSON(w, http.StatusAccepted, map[string]string{"status": "cancellation_requested"})
}
