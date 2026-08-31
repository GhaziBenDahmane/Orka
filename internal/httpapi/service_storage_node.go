package httpapi

import (
	"errors"
	"net/http"

	"github.com/bendahma/dokploy-go/internal/store"
	"github.com/google/uuid"
)

func (s *Server) rebindServiceStorageNode(w http.ResponseWriter, r *http.Request) {
	serviceID, err := uuid.Parse(r.PathValue("serviceID"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid_id", "invalid service id")
		return
	}
	_, volumes, ok := s.serviceNamedVolumes(w, r)
	if !ok {
		return
	}
	if len(volumes) == 0 {
		writeError(w, http.StatusBadRequest, "no_named_volumes", "service has no named volumes to relocate")
		return
	}
	var input struct {
		NodeID  string `json:"nodeId"`
		Confirm string `json:"confirm"`
	}
	if !decode(w, r, &input) {
		return
	}
	item, err := s.Store.RebindComposeServiceStorageNode(r.Context(), principal(r), serviceID, input.NodeID, input.Confirm, r.RemoteAddr)
	if err != nil {
		switch {
		case errors.Is(err, store.ErrInvalidStorageNode):
			writeError(w, http.StatusBadRequest, "invalid_storage_node", err.Error())
		case errors.Is(err, store.ErrStorageNodeConfirmation):
			writeError(w, http.StatusBadRequest, "confirmation_mismatch", err.Error())
		case errors.Is(err, store.ErrStorageNodeUnassigned):
			writeError(w, http.StatusConflict, "storage_node_unassigned", err.Error())
		case errors.Is(err, store.ErrStorageNodeRebindRequiresStopped):
			writeError(w, http.StatusConflict, "service_must_be_stopped", err.Error())
		case errors.Is(err, store.ErrBusy):
			writeError(w, http.StatusConflict, "service_busy", "wait for active service and data operations before rebinding storage")
		default:
			writeStoreError(w, err)
		}
		return
	}
	writeJSON(w, http.StatusOK, item)
}
