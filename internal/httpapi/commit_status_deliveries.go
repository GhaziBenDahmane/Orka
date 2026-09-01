package httpapi

import (
	"errors"
	"net/http"
	"strconv"
	"strings"

	"github.com/GhaziBenDahmane/Orka/internal/store"
	"github.com/google/uuid"
)

var commitStatusProviders = []string{"github", "gitlab", "gitea", "bitbucket"}
var commitStatusStates = []string{"pending", "success", "failure", "error"}

func (s *Server) listCommitStatusDeliveries(w http.ResponseWriter, r *http.Request) {
	status := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("status")))
	provider := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("provider")))
	state := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("state")))
	if status != "" && !contains([]string{"pending", "running", "succeeded", "failed"}, status) {
		writeError(w, http.StatusBadRequest, "invalid_status", "status must be pending, running, succeeded, or failed")
		return
	}
	if provider != "" && !contains(commitStatusProviders, provider) {
		writeError(w, http.StatusBadRequest, "invalid_provider", "provider must be github, gitlab, gitea, or bitbucket")
		return
	}
	if state != "" && !contains(commitStatusStates, state) {
		writeError(w, http.StatusBadRequest, "invalid_state", "state must be pending, success, failure, or error")
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
	items, err := s.Store.ListCommitStatusDeliveries(r.Context(), principal(r).OrganizationID, store.CommitStatusDeliveryFilter{Status: status, Provider: provider, State: state, Limit: limit})
	if err != nil {
		writeStoreError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": items})
}

func (s *Server) retryCommitStatusDelivery(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(r.PathValue("deliveryID"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid_id", "invalid commit status delivery id")
		return
	}
	item, err := s.Store.RetryCommitStatusDeliveryWithAudit(r.Context(), principal(r), id, r.RemoteAddr)
	if errors.Is(err, store.ErrBusy) {
		writeError(w, http.StatusConflict, "delivery_in_progress", "commit status delivery still has an active attempt")
		return
	}
	if errors.Is(err, store.ErrCommitStatusDeliveryNotRetryable) {
		writeError(w, http.StatusConflict, "delivery_not_retryable", err.Error())
		return
	}
	if err != nil {
		writeStoreError(w, err)
		return
	}
	writeJSON(w, http.StatusAccepted, item)
}
