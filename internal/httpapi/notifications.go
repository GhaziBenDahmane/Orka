package httpapi

import (
	"net/http"
	"net/url"
	"strings"

	"github.com/bendahma/dokploy-go/internal/auth"
	"github.com/bendahma/dokploy-go/internal/store"
	"github.com/google/uuid"
)

var notificationEvents = []string{"deployment.failed", "backup.failed", "restore.failed"}

func (s *Server) createNotificationEndpoint(w http.ResponseWriter, r *http.Request) {
	var input struct {
		Name   string   `json:"name"`
		Kind   string   `json:"kind"`
		URL    string   `json:"url"`
		Events []string `json:"events"`
	}
	if !decode(w, r, &input) {
		return
	}
	input.Name = strings.TrimSpace(input.Name)
	input.Kind = strings.ToLower(strings.TrimSpace(input.Kind))
	parsed, err := url.Parse(input.URL)
	if err != nil || parsed.Scheme != "https" || parsed.Host == "" || parsed.User != nil || parsed.Fragment != "" || input.Name == "" || !contains([]string{"webhook", "slack"}, input.Kind) {
		writeError(w, 400, "invalid_notification_endpoint", "name, supported kind, and an HTTPS URL without user information are required")
		return
	}
	if len(input.Events) == 0 {
		input.Events = append([]string(nil), notificationEvents...)
	}
	seen := map[string]bool{}
	for _, event := range input.Events {
		if !contains(notificationEvents, event) || seen[event] {
			writeError(w, 400, "invalid_notification_events", "events must be unique supported failure events")
			return
		}
		seen[event] = true
	}
	secret, err := auth.NewToken()
	if err != nil {
		writeError(w, 500, "token_failed", err.Error())
		return
	}
	id := uuid.New()
	encryptedURL, err := s.Box.Encrypt([]byte(parsed.String()), "notification-url:"+id.String())
	if err != nil {
		writeError(w, 500, "encryption_failed", err.Error())
		return
	}
	encryptedSecret, err := s.Box.Encrypt([]byte(secret), "notification-secret:"+id.String())
	if err != nil {
		writeError(w, 500, "encryption_failed", err.Error())
		return
	}
	p := principal(r)
	item, err := s.Store.CreateNotificationEndpoint(r.Context(), store.NotificationEndpoint{ID: id, OrganizationID: p.OrganizationID, Name: input.Name, Kind: input.Kind, EncryptedURL: encryptedURL, EncryptedSecret: encryptedSecret, Events: input.Events, Enabled: true})
	if err != nil {
		writeStoreError(w, err)
		return
	}
	s.Store.Audit(r.Context(), &p, "notification_endpoint.create", "notification_endpoint", item.ID.String(), r.RemoteAddr, map[string]any{"kind": item.Kind, "events": item.Events})
	writeJSON(w, 201, map[string]any{"endpoint": item, "signingSecret": secret})
}

func (s *Server) listNotificationEndpoints(w http.ResponseWriter, r *http.Request) {
	items, err := s.Store.ListNotificationEndpoints(r.Context(), principal(r).OrganizationID)
	if err != nil {
		writeStoreError(w, err)
		return
	}
	writeJSON(w, 200, map[string]any{"items": items})
}

func (s *Server) deleteNotificationEndpoint(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(r.PathValue("endpointID"))
	if err != nil {
		writeError(w, 400, "invalid_id", "invalid notification endpoint id")
		return
	}
	p := principal(r)
	if err = s.Store.DeleteNotificationEndpoint(r.Context(), p.OrganizationID, id); err != nil {
		writeStoreError(w, err)
		return
	}
	s.Store.Audit(r.Context(), &p, "notification_endpoint.delete", "notification_endpoint", id.String(), r.RemoteAddr, nil)
	w.WriteHeader(http.StatusNoContent)
}
