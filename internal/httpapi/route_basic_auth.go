package httpapi

import (
	"net/http"

	"github.com/google/uuid"
)

type routeBasicAuthInput struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

func (s *Server) listRouteBasicAuthUsers(w http.ResponseWriter, r *http.Request) {
	serviceID, err := uuid.Parse(r.PathValue("serviceID"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid_id", "invalid service id")
		return
	}
	items, err := s.Store.ListRouteBasicAuthUsers(r.Context(), principal(r).OrganizationID, serviceID)
	if err != nil {
		writeStoreError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": items})
}

func (s *Server) createRouteBasicAuthUser(w http.ResponseWriter, r *http.Request) {
	serviceID, err := uuid.Parse(r.PathValue("serviceID"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid_id", "invalid service id")
		return
	}
	var input routeBasicAuthInput
	if !decode(w, r, &input) {
		return
	}
	p := principal(r)
	item, err := s.Store.CreateRouteBasicAuthUserWithAudit(r.Context(), p, serviceID, input.Username, input.Password, r.RemoteAddr)
	if err != nil {
		writeStoreError(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, item)
}

func (s *Server) updateRouteBasicAuthUser(w http.ResponseWriter, r *http.Request) {
	serviceID, serviceErr := uuid.Parse(r.PathValue("serviceID"))
	userID, userErr := uuid.Parse(r.PathValue("userID"))
	if serviceErr != nil || userErr != nil {
		writeError(w, http.StatusBadRequest, "invalid_id", "invalid service or basic-auth user id")
		return
	}
	var input routeBasicAuthInput
	if !decode(w, r, &input) {
		return
	}
	p := principal(r)
	item, err := s.Store.UpdateRouteBasicAuthUserWithAudit(r.Context(), p, serviceID, userID, input.Username, input.Password, r.RemoteAddr)
	if err != nil {
		writeStoreError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, item)
}

func (s *Server) deleteRouteBasicAuthUser(w http.ResponseWriter, r *http.Request) {
	serviceID, serviceErr := uuid.Parse(r.PathValue("serviceID"))
	userID, userErr := uuid.Parse(r.PathValue("userID"))
	if serviceErr != nil || userErr != nil {
		writeError(w, http.StatusBadRequest, "invalid_id", "invalid service or basic-auth user id")
		return
	}
	p := principal(r)
	if err := s.Store.DeleteRouteBasicAuthUserWithAudit(r.Context(), p, serviceID, userID, r.RemoteAddr); err != nil {
		writeStoreError(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
