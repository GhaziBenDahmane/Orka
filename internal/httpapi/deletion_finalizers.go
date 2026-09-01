package httpapi

import (
	"errors"
	"net/http"
	"strconv"
	"strings"

	"github.com/GhaziBenDahmane/Orka/internal/store"
	"github.com/google/uuid"
)

func (s *Server) listDeletionFinalizers(w http.ResponseWriter, r *http.Request) {
	resourceType := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("resourceType")))
	status := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("status")))
	if resourceType != "" && !store.ValidDeletionFinalizerResourceType(resourceType) {
		writeError(w, http.StatusBadRequest, "invalid_resource_type", "resourceType must be project, environment, service, database, cluster, or network")
		return
	}
	if status != "" && !contains([]string{"missing", "pending", "running", "succeeded", "failed", "cancelled"}, status) {
		writeError(w, http.StatusBadRequest, "invalid_status", "status must be missing, pending, running, succeeded, failed, or cancelled")
		return
	}
	limit := 100
	if raw := strings.TrimSpace(r.URL.Query().Get("limit")); raw != "" {
		parsed, err := strconv.Atoi(raw)
		if err != nil || parsed < 1 || parsed > 200 {
			writeError(w, http.StatusBadRequest, "invalid_limit", "limit must be between 1 and 200")
			return
		}
		limit = parsed
	}
	items, err := s.Store.ListDeletionFinalizers(r.Context(), principal(r).OrganizationID, store.DeletionFinalizerFilter{ResourceType: resourceType, Status: status, Limit: limit})
	if err != nil {
		writeStoreError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": items})
}

func (s *Server) retryDeletionFinalizer(w http.ResponseWriter, r *http.Request) {
	resourceType := strings.ToLower(strings.TrimSpace(r.PathValue("resourceType")))
	if !store.ValidDeletionFinalizerResourceType(resourceType) {
		writeError(w, http.StatusBadRequest, "invalid_resource_type", "invalid deletion finalizer resource type")
		return
	}
	resourceID, err := uuid.Parse(r.PathValue("resourceID"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid_id", "invalid deletion finalizer resource id")
		return
	}
	item, err := s.Store.RetryDeletionFinalizerWithAudit(r.Context(), principal(r), resourceType, resourceID, r.RemoteAddr)
	if errors.Is(err, store.ErrBusy) {
		writeError(w, http.StatusConflict, "finalizer_in_progress", "deletion finalizer still has an active attempt")
		return
	}
	if err != nil {
		writeStoreError(w, err)
		return
	}
	writeJSON(w, http.StatusAccepted, item)
}
