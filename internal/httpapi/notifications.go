package httpapi

import (
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"net/mail"
	"net/url"
	"strconv"
	"strings"

	"github.com/bendahma/dokploy-go/internal/auth"
	"github.com/bendahma/dokploy-go/internal/store"
	"github.com/google/uuid"
)

var notificationEvents = []string{"deployment.failed", "backup.failed", "restore.failed"}

func (s *Server) createNotificationEndpoint(w http.ResponseWriter, r *http.Request) {
	var input struct {
		Name                    string   `json:"name"`
		Kind                    string   `json:"kind"`
		URL                     string   `json:"url"`
		Events                  []string `json:"events"`
		PagerDutyIntegrationKey string   `json:"pagerDutyIntegrationKey"`
		OpsgenieAPIKey          string   `json:"opsgenieApiKey"`
		OpsgenieRegion          string   `json:"opsgenieRegion"`
		SMTPHost                string   `json:"smtpHost"`
		SMTPPort                int      `json:"smtpPort"`
		SMTPMode                string   `json:"smtpMode"`
		SMTPUsername            string   `json:"smtpUsername"`
		SMTPPassword            string   `json:"smtpPassword"`
		From                    string   `json:"from"`
		To                      []string `json:"to"`
	}
	if !decode(w, r, &input) {
		return
	}
	input.Name = strings.TrimSpace(input.Name)
	input.Kind = strings.ToLower(strings.TrimSpace(input.Kind))
	if input.Name == "" || !contains([]string{"webhook", "slack", "smtp", "pagerduty", "opsgenie"}, input.Kind) {
		writeError(w, 400, "invalid_notification_endpoint", "name and a supported notification kind are required")
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
	endpointURL, secret, revealSecret, err := notificationEndpointMaterial(input.Kind, input.URL, input.PagerDutyIntegrationKey, input.OpsgenieAPIKey, input.OpsgenieRegion, input.SMTPHost, input.SMTPPort, input.SMTPMode, input.SMTPUsername, input.SMTPPassword, input.From, input.To)
	if err != nil {
		writeError(w, 400, "invalid_notification_endpoint", err.Error())
		return
	}
	id := uuid.New()
	encryptedURL, err := s.Box.Encrypt([]byte(endpointURL), "notification-url:"+id.String())
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
	response := map[string]any{"endpoint": item}
	if revealSecret {
		response["signingSecret"] = secret
	}
	writeJSON(w, 201, response)
}

func notificationEndpointMaterial(kind, rawURL, pagerDutyKey, opsgenieKey, opsgenieRegion, smtpHost string, smtpPort int, smtpMode, smtpUsername, smtpPassword, from string, to []string) (string, string, bool, error) {
	opsgenieRegion = strings.ToLower(strings.TrimSpace(opsgenieRegion))
	smtpMode = strings.ToLower(strings.TrimSpace(smtpMode))
	switch kind {
	case "webhook", "slack":
		parsed, err := url.Parse(rawURL)
		if err != nil || parsed.Scheme != "https" || parsed.Host == "" || parsed.User != nil || parsed.Fragment != "" {
			return "", "", false, errors.New("an HTTPS URL without user information is required")
		}
		secret, err := auth.NewToken()
		return parsed.String(), secret, true, err
	case "pagerduty":
		if strings.TrimSpace(pagerDutyKey) == "" || len(pagerDutyKey) > 4096 || strings.ContainsAny(pagerDutyKey, "\r\n") {
			return "", "", false, errors.New("pagerDutyIntegrationKey is required")
		}
		return "https://events.pagerduty.com/v2/enqueue", strings.TrimSpace(pagerDutyKey), false, nil
	case "opsgenie":
		if strings.TrimSpace(opsgenieKey) == "" || len(opsgenieKey) > 4096 || strings.ContainsAny(opsgenieKey, "\r\n") || (opsgenieRegion != "" && opsgenieRegion != "us" && opsgenieRegion != "eu") {
			return "", "", false, errors.New("opsgenieApiKey and an optional us or eu region are required")
		}
		host := "api.opsgenie.com"
		if opsgenieRegion == "eu" {
			host = "api.eu.opsgenie.com"
		}
		return "https://" + host + "/v2/alerts", strings.TrimSpace(opsgenieKey), false, nil
	case "smtp":
		smtpHost = strings.TrimSpace(smtpHost)
		if smtpPort == 0 {
			smtpPort = 587
		}
		if smtpMode == "" {
			smtpMode = "starttls"
		}
		if smtpHost == "" || strings.ContainsAny(smtpHost, "/@ \t\r\n") || (strings.Contains(smtpHost, ":") && net.ParseIP(smtpHost) == nil) || smtpPort < 1 || smtpPort > 65535 || (smtpMode != "starttls" && smtpMode != "tls") || (smtpUsername == "") != (smtpPassword == "") || len(to) == 0 || len(to) > 100 {
			return "", "", false, errors.New("valid SMTP host, port, TLS mode, optional credential pair, sender, and recipients are required")
		}
		if _, err := mail.ParseAddress(from); err != nil {
			return "", "", false, errors.New("invalid SMTP sender")
		}
		for _, recipient := range to {
			if _, err := mail.ParseAddress(recipient); err != nil {
				return "", "", false, errors.New("invalid SMTP recipient")
			}
		}
		material, _ := json.Marshal(map[string]any{"username": smtpUsername, "password": smtpPassword, "from": from, "to": to})
		return "smtp+" + smtpMode + "://" + net.JoinHostPort(smtpHost, strconv.Itoa(smtpPort)), string(material), false, nil
	default:
		return "", "", false, errors.New("unsupported notification kind")
	}
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
