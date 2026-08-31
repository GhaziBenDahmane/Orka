package httpapi

import (
	"errors"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/bendahma/dokploy-go/internal/auth"
	"github.com/bendahma/dokploy-go/internal/cryptox"
	"github.com/bendahma/dokploy-go/internal/store"
	"github.com/google/uuid"
)

func (s *Server) createOrganizationInvitation(w http.ResponseWriter, r *http.Request) {
	var input struct {
		Email         string `json:"email"`
		Role          string `json:"role"`
		ExpiresInDays int    `json:"expiresInDays"`
	}
	if !decode(w, r, &input) {
		return
	}
	email, _, validEmail := canonicalEmail(input.Email)
	if !validEmail {
		writeError(w, http.StatusBadRequest, "invalid_email", "a plain email address is required")
		return
	}
	input.Email = email
	input.Role = strings.ToLower(strings.TrimSpace(input.Role))
	if !store.ValidOrganizationRole(input.Role) {
		writeError(w, http.StatusBadRequest, "invalid_role", "role must be owner, admin, developer, or viewer")
		return
	}
	if input.ExpiresInDays == 0 {
		input.ExpiresInDays = 7
	}
	if input.ExpiresInDays < 1 || input.ExpiresInDays > 30 {
		writeError(w, http.StatusBadRequest, "invalid_expiry", "expiry must be from 1 to 30 days")
		return
	}
	token, err := auth.NewToken()
	if err != nil {
		s.writeInternalError(w, r, http.StatusInternalServerError, "token_failed", "invitation token could not be generated", err)
		return
	}
	token = "dky_inv_" + token
	p := principal(r)
	item, err := s.Store.CreateOrganizationInvitationWithAudit(r.Context(), p, input.Email, input.Role, cryptox.Digest(token), time.Now().Add(time.Duration(input.ExpiresInDays)*24*time.Hour), r.RemoteAddr)
	if err != nil {
		writeStoreError(w, err)
		return
	}
	acceptURL := strings.TrimRight(s.PublicURL, "/") + "/#invitation=" + url.QueryEscape(token)
	if s.PublicURL == "" {
		acceptURL = "/#invitation=" + url.QueryEscape(token)
	}
	writeJSON(w, http.StatusCreated, map[string]any{"invitation": item, "token": token, "acceptUrl": acceptURL})
}

func (s *Server) listOrganizationInvitations(w http.ResponseWriter, r *http.Request) {
	items, err := s.Store.ListOrganizationInvitations(r.Context(), principal(r).OrganizationID)
	if err != nil {
		writeStoreError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": items})
}

func (s *Server) getOrganizationInvitation(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(r.PathValue("invitationID"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid_id", "invalid invitation id")
		return
	}
	item, err := s.Store.GetOrganizationInvitation(r.Context(), principal(r).OrganizationID, id)
	if err != nil {
		writeStoreError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, item)
}

func (s *Server) revokeOrganizationInvitation(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(r.PathValue("invitationID"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid_id", "invalid invitation id")
		return
	}
	p := principal(r)
	if err = s.Store.RevokeOrganizationInvitationWithAudit(r.Context(), p, id, r.RemoteAddr); err != nil {
		writeStoreError(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) acceptOrganizationInvitation(w http.ResponseWriter, r *http.Request) {
	var input struct {
		Token       string `json:"token"`
		DisplayName string `json:"displayName"`
		Password    string `json:"password"`
	}
	if !decode(w, r, &input) {
		return
	}
	input.Token = strings.TrimSpace(input.Token)
	if !strings.HasPrefix(input.Token, "dky_inv_") || len(input.Token) < 40 || len(input.Token) > 128 {
		writeError(w, http.StatusNotFound, "invalid_invitation", "invitation is invalid or expired")
		return
	}
	displayName, validDisplayName := canonicalDisplayName(input.DisplayName)
	if !validDisplayName || len(input.Password) > 1024 {
		writeError(w, http.StatusBadRequest, "invalid_invitation_profile", "display name or password is too long")
		return
	}
	input.DisplayName = displayName
	if !s.allowAuthenticationAttempt(w, r, "invitation-client", authenticationClientKey(r), 300) || !s.allowAuthenticationAttempt(w, r, "invitation", cryptox.Digest(input.Token), 20) {
		return
	}
	passwordHash := ""
	var err error
	if input.Password != "" {
		passwordHash, err = auth.HashPassword(input.Password)
		if err != nil {
			writeError(w, http.StatusBadRequest, "invalid_password", err.Error())
			return
		}
	}
	accepted, err := s.Store.AcceptOrganizationInvitationWithAudit(r.Context(), cryptox.Digest(input.Token), input.DisplayName, passwordHash, r.RemoteAddr)
	if errors.Is(err, store.ErrNotFound) {
		writeError(w, http.StatusNotFound, "invalid_invitation", "invitation is invalid or expired")
		return
	}
	if err != nil {
		writeStoreError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, accepted)
}
