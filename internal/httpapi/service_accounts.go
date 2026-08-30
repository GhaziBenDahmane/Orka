package httpapi

import (
	"net/http"
	"strings"
	"time"

	"github.com/bendahma/dokploy-go/internal/auth"
	"github.com/bendahma/dokploy-go/internal/cryptox"
	"github.com/google/uuid"
)

func (s *Server) createServiceAccount(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Name          string `json:"name"`
		Role          string `json:"role"`
		ExpiresInDays int    `json:"expiresInDays"`
	}
	if !decode(w, r, &in) {
		return
	}
	in.Name = strings.TrimSpace(in.Name)
	if in.ExpiresInDays == 0 {
		in.ExpiresInDays = 90
	}
	if in.Name == "" || (roleRank(in.Role) < 1 && in.Role != "auditor") || in.Role == "owner" || in.ExpiresInDays < 1 || in.ExpiresInDays > 365 {
		writeError(w, 400, "invalid_service_account", "name, admin/developer/viewer/auditor role, and expiry from 1 to 365 days are required")
		return
	}
	token, err := auth.NewToken()
	if err != nil {
		s.writeInternalError(w, r, 500, "token_failed", "service-account token could not be generated", err)
		return
	}
	token = "dky_" + token
	p := principal(r)
	expiresAt := time.Now().Add(time.Duration(in.ExpiresInDays) * 24 * time.Hour)
	item, err := s.Store.CreateServiceAccount(r.Context(), p.OrganizationID, p.UserID, in.Name, in.Role, cryptox.Digest(token), expiresAt)
	if err != nil {
		writeStoreError(w, err)
		return
	}
	s.Store.Audit(r.Context(), &p, "service_account.create", "service_account", item.ID.String(), r.RemoteAddr, map[string]any{"role": item.Role, "expiresAt": expiresAt})
	writeJSON(w, http.StatusCreated, map[string]any{"serviceAccount": item, "token": token})
}

func (s *Server) listServiceAccounts(w http.ResponseWriter, r *http.Request) {
	items, err := s.Store.ListServiceAccounts(r.Context(), principal(r).OrganizationID)
	if err != nil {
		writeStoreError(w, err)
		return
	}
	writeJSON(w, 200, map[string]any{"items": items})
}

func (s *Server) rotateServiceAccountToken(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(r.PathValue("accountID"))
	if err != nil {
		writeError(w, 400, "invalid_id", "invalid service account id")
		return
	}
	var in struct {
		ExpiresInDays int `json:"expiresInDays"`
	}
	if !decode(w, r, &in) {
		return
	}
	if in.ExpiresInDays == 0 {
		in.ExpiresInDays = 90
	}
	if in.ExpiresInDays < 1 || in.ExpiresInDays > 365 {
		writeError(w, 400, "invalid_expiry", "expiry must be from 1 to 365 days")
		return
	}
	token, err := auth.NewToken()
	if err != nil {
		s.writeInternalError(w, r, 500, "token_failed", "service-account token could not be generated", err)
		return
	}
	token = "dky_" + token
	p := principal(r)
	expiresAt := time.Now().Add(time.Duration(in.ExpiresInDays) * 24 * time.Hour)
	if err = s.Store.RotateServiceAccountToken(r.Context(), p.OrganizationID, id, cryptox.Digest(token), expiresAt); err != nil {
		writeStoreError(w, err)
		return
	}
	s.Store.Audit(r.Context(), &p, "service_account.rotate", "service_account", id.String(), r.RemoteAddr, map[string]any{"expiresAt": expiresAt})
	writeJSON(w, 200, map[string]any{"token": token, "expiresAt": expiresAt})
}

func (s *Server) deleteServiceAccount(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(r.PathValue("accountID"))
	if err != nil {
		writeError(w, 400, "invalid_id", "invalid service account id")
		return
	}
	p := principal(r)
	if err = s.Store.DisableServiceAccount(r.Context(), p.OrganizationID, id); err != nil {
		writeStoreError(w, err)
		return
	}
	s.Store.Audit(r.Context(), &p, "service_account.disable", "service_account", id.String(), r.RemoteAddr, nil)
	w.WriteHeader(http.StatusNoContent)
}
