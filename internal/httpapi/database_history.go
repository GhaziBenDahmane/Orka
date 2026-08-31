package httpapi

import (
	"errors"
	"net/http"

	"github.com/bendahma/dokploy-go/internal/store"
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

func (s *Server) cancelDatabaseBackup(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(r.PathValue("backupID"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid_id", "invalid database backup id")
		return
	}
	p := principal(r)
	if err = s.Store.CancelDatabaseBackupWithAudit(r.Context(), p, id, r.RemoteAddr); err != nil {
		if errors.Is(err, store.ErrNotCancellable) {
			writeError(w, http.StatusConflict, "not_cancellable", err.Error())
			return
		}
		writeStoreError(w, err)
		return
	}
	writeJSON(w, http.StatusAccepted, map[string]string{"status": "cancellation_requested"})
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

func (s *Server) cancelDatabaseRestore(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(r.PathValue("restoreID"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid_id", "invalid database restore id")
		return
	}
	p := principal(r)
	if err = s.Store.CancelDatabaseRestoreWithAudit(r.Context(), p, id, r.RemoteAddr); err != nil {
		if errors.Is(err, store.ErrNotCancellable) {
			writeError(w, http.StatusConflict, "not_cancellable", err.Error())
			return
		}
		writeStoreError(w, err)
		return
	}
	writeJSON(w, http.StatusAccepted, map[string]string{"status": "cancellation_requested"})
}
