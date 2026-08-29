package httpapi

import (
	"net/http"
	"strings"

	"github.com/google/uuid"
)

func (s *Server) listOrganizationMembers(w http.ResponseWriter, r *http.Request) {
	items, err := s.Store.ListOrganizationMembers(r.Context(), principal(r).OrganizationID)
	if err != nil {
		writeStoreError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": items})
}

func (s *Server) updateOrganizationMember(w http.ResponseWriter, r *http.Request) {
	userID, err := uuid.Parse(r.PathValue("userID"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid_id", "invalid user id")
		return
	}
	var input struct {
		Role string `json:"role"`
	}
	if !decode(w, r, &input) {
		return
	}
	input.Role = strings.ToLower(strings.TrimSpace(input.Role))
	if roleRank(input.Role) < 1 {
		writeError(w, http.StatusBadRequest, "invalid_role", "role must be owner, admin, developer, or viewer")
		return
	}
	p := principal(r)
	item, err := s.Store.UpdateOrganizationMemberRole(r.Context(), p.OrganizationID, userID, input.Role, p.Role)
	if err != nil {
		writeStoreError(w, err)
		return
	}
	s.Store.Audit(r.Context(), &p, "membership.role.update", "user", userID.String(), r.RemoteAddr, map[string]string{"role": item.Role})
	writeJSON(w, http.StatusOK, item)
}

func (s *Server) deleteOrganizationMember(w http.ResponseWriter, r *http.Request) {
	userID, err := uuid.Parse(r.PathValue("userID"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid_id", "invalid user id")
		return
	}
	p := principal(r)
	if err = s.Store.DeleteOrganizationMember(r.Context(), p.OrganizationID, userID, p.Role); err != nil {
		writeStoreError(w, err)
		return
	}
	s.Store.Audit(r.Context(), &p, "membership.remove", "user", userID.String(), r.RemoteAddr, nil)
	w.WriteHeader(http.StatusNoContent)
}
