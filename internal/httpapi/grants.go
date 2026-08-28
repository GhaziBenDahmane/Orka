package httpapi

import (
	"net/http"

	"github.com/bendahma/dokploy-go/internal/store"
	"github.com/google/uuid"
)

func (s *Server) listProjectGrants(w http.ResponseWriter, r *http.Request) {
	s.listResourceGrants(w, r, "project", "projectID")
}
func (s *Server) putProjectGrant(w http.ResponseWriter, r *http.Request) {
	s.putResourceGrant(w, r, "project", "projectID")
}
func (s *Server) deleteProjectGrant(w http.ResponseWriter, r *http.Request) {
	s.deleteResourceGrant(w, r, "project", "projectID")
}
func (s *Server) listEnvironmentGrants(w http.ResponseWriter, r *http.Request) {
	s.listResourceGrants(w, r, "environment", "environmentID")
}
func (s *Server) putEnvironmentGrant(w http.ResponseWriter, r *http.Request) {
	s.putResourceGrant(w, r, "environment", "environmentID")
}
func (s *Server) deleteEnvironmentGrant(w http.ResponseWriter, r *http.Request) {
	s.deleteResourceGrant(w, r, "environment", "environmentID")
}

func (s *Server) listResourceGrants(w http.ResponseWriter, r *http.Request, scopeType, parameter string) {
	scopeID, err := uuid.Parse(r.PathValue(parameter))
	if err != nil {
		writeError(w, 400, "invalid_id", "invalid scope id")
		return
	}
	items, err := s.Store.ListResourceGrants(r.Context(), principal(r).OrganizationID, scopeType, scopeID)
	if err != nil {
		writeStoreError(w, err)
		return
	}
	writeJSON(w, 200, map[string]any{"items": items})
}

func (s *Server) putResourceGrant(w http.ResponseWriter, r *http.Request, scopeType, parameter string) {
	scopeID, scopeErr := uuid.Parse(r.PathValue(parameter))
	userID, userErr := uuid.Parse(r.PathValue("userID"))
	if scopeErr != nil || userErr != nil {
		writeError(w, 400, "invalid_id", "invalid scope or user id")
		return
	}
	var in struct {
		Role string `json:"role"`
	}
	if !decode(w, r, &in) {
		return
	}
	if !store.ValidScopedRole(in.Role) {
		writeError(w, 400, "invalid_role", "role must be admin, developer, or viewer")
		return
	}
	p := principal(r)
	item, err := s.Store.UpsertResourceGrant(r.Context(), p.OrganizationID, scopeType, scopeID, userID, in.Role)
	if err != nil {
		writeStoreError(w, err)
		return
	}
	s.Store.Audit(r.Context(), &p, "grant.update", scopeType, scopeID.String(), r.RemoteAddr, map[string]any{"userId": userID, "role": in.Role})
	writeJSON(w, 200, item)
}

func (s *Server) deleteResourceGrant(w http.ResponseWriter, r *http.Request, scopeType, parameter string) {
	scopeID, scopeErr := uuid.Parse(r.PathValue(parameter))
	userID, userErr := uuid.Parse(r.PathValue("userID"))
	if scopeErr != nil || userErr != nil {
		writeError(w, 400, "invalid_id", "invalid scope or user id")
		return
	}
	p := principal(r)
	if err := s.Store.DeleteResourceGrant(r.Context(), p.OrganizationID, scopeType, scopeID, userID); err != nil {
		writeStoreError(w, err)
		return
	}
	s.Store.Audit(r.Context(), &p, "grant.delete", scopeType, scopeID.String(), r.RemoteAddr, map[string]any{"userId": userID})
	w.WriteHeader(http.StatusNoContent)
}
