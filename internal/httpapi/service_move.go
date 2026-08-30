package httpapi

import (
	"errors"
	"net/http"

	"github.com/bendahma/dokploy-go/internal/store"
	"github.com/google/uuid"
)

func (s *Server) moveService(w http.ResponseWriter, r *http.Request) {
	serviceID, err := uuid.Parse(r.PathValue("serviceID"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid_id", "invalid service id")
		return
	}
	var input struct {
		EnvironmentID uuid.UUID `json:"environmentId"`
	}
	if !decode(w, r, &input) {
		return
	}
	if input.EnvironmentID == uuid.Nil {
		writeError(w, http.StatusBadRequest, "invalid_environment", "environmentId must be a non-zero UUID")
		return
	}
	p := principal(r)
	role, err := s.Store.EffectiveResourceRole(r.Context(), p, "environment", input.EnvironmentID)
	if err != nil {
		writeStoreError(w, err)
		return
	}
	if roleRank(role) < roleRank("developer") {
		writeError(w, http.StatusForbidden, "forbidden", "developer access to the target environment is required")
		return
	}
	item, err := s.Store.MoveComposeService(r.Context(), p.OrganizationID, serviceID, input.EnvironmentID)
	if err != nil {
		if errors.Is(err, store.ErrBusy) {
			writeError(w, http.StatusConflict, "service_busy", "service has an operation in progress")
			return
		}
		writeStoreError(w, err)
		return
	}
	s.Store.Audit(r.Context(), &p, "service.move", "compose_service", serviceID.String(), r.RemoteAddr, map[string]any{"environmentId": input.EnvironmentID})
	writeJSON(w, http.StatusOK, item)
}
