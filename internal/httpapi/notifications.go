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

	"github.com/GhaziBenDahmane/Orka/internal/auth"
	"github.com/GhaziBenDahmane/Orka/internal/store"
	"github.com/google/uuid"
)

var notificationEvents = []string{"deployment.failed", "service.stop.failed", "service.schedule.failed", "backup.failed", "restore.failed", "restore.drill.failed", "database.migration.failed", "commit.status.failed", "network.provision.failed", "network.delete.failed", "resource.delete.failed", "edge.certificate.reconcile.failed", "template.sync.failed", "agent.upgrade.failed", "audit.archive.failed", "ai.audit.failed", "ai.finding.critical"}

const (
	maxNotificationNameBytes     = 120
	maxNotificationURLBytes      = 16 << 10
	maxSMTPUsernameBytes         = 4 << 10
	maxSMTPPasswordBytes         = 16 << 10
	maxSMTPAddressBytes          = 1024
	maxSMTPRecipientAddressBytes = 1024
)

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
	name, nameErr := normalizeResourceName(input.Name)
	input.Name = name
	input.Kind = strings.ToLower(strings.TrimSpace(input.Kind))
	if nameErr != nil || !validNotificationEndpointName(input.Name) || !contains([]string{"webhook", "slack", "smtp", "pagerduty", "opsgenie"}, input.Kind) {
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
		s.writeInternalError(w, r, 500, "encryption_failed", "notification endpoint could not be encrypted", err)
		return
	}
	encryptedSecret, err := s.Box.Encrypt([]byte(secret), "notification-secret:"+id.String())
	if err != nil {
		s.writeInternalError(w, r, 500, "encryption_failed", "notification secret could not be encrypted", err)
		return
	}
	p := principal(r)
	item, err := s.Store.CreateNotificationEndpointWithAudit(r.Context(), p, store.NotificationEndpoint{ID: id, Name: input.Name, Kind: input.Kind, EncryptedURL: encryptedURL, EncryptedSecret: encryptedSecret, Events: input.Events, Enabled: true}, r.RemoteAddr)
	if err != nil {
		writeStoreError(w, err)
		return
	}
	response := map[string]any{"endpoint": item}
	if revealSecret {
		response["signingSecret"] = secret
	}
	writeJSON(w, 201, response)
}

func validNotificationEndpointName(name string) bool {
	return validDisplayLabel(name, maxNotificationNameBytes)
}

func notificationEndpointMaterial(kind, rawURL, pagerDutyKey, opsgenieKey, opsgenieRegion, smtpHost string, smtpPort int, smtpMode, smtpUsername, smtpPassword, from string, to []string) (string, string, bool, error) {
	opsgenieRegion = strings.ToLower(strings.TrimSpace(opsgenieRegion))
	smtpMode = strings.ToLower(strings.TrimSpace(smtpMode))
	switch kind {
	case "webhook", "slack":
		trimmedURL := strings.TrimSpace(rawURL)
		parsed, err := url.Parse(trimmedURL)
		if err != nil || rawURL != trimmedURL || len(rawURL) > maxNotificationURLBytes || parsed.Scheme != "https" || !validEndpointURLHost(parsed) || parsed.User != nil || parsed.Fragment != "" || parsed.Opaque != "" {
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
		if !validEndpointHostname(smtpHost) || smtpPort < 1 || smtpPort > 65535 || (smtpMode != "starttls" && smtpMode != "tls") || (smtpUsername == "") != (smtpPassword == "") || len(smtpUsername) > maxSMTPUsernameBytes || len(smtpPassword) > maxSMTPPasswordBytes || strings.ContainsAny(smtpUsername, "\x00\r\n") || strings.ContainsAny(smtpPassword, "\x00\r\n") || len(from) == 0 || len(from) > maxSMTPAddressBytes || len(to) == 0 || len(to) > 100 {
			return "", "", false, errors.New("valid SMTP host, port, TLS mode, optional credential pair, sender, and recipients are required")
		}
		if _, err := mail.ParseAddress(from); err != nil {
			return "", "", false, errors.New("invalid SMTP sender")
		}
		for _, recipient := range to {
			if len(recipient) == 0 || len(recipient) > maxSMTPRecipientAddressBytes {
				return "", "", false, errors.New("invalid SMTP recipient")
			}
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

func (s *Server) listNotificationDeliveries(w http.ResponseWriter, r *http.Request) {
	status := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("status")))
	eventType := strings.TrimSpace(r.URL.Query().Get("event"))
	if status != "" && !contains([]string{"pending", "running", "succeeded", "failed"}, status) {
		writeError(w, http.StatusBadRequest, "invalid_status", "status must be pending, running, succeeded, or failed")
		return
	}
	if eventType != "" && !contains(notificationEvents, eventType) {
		writeError(w, http.StatusBadRequest, "invalid_event", "event must be a supported notification event")
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
	items, err := s.Store.ListNotificationDeliveries(r.Context(), principal(r).OrganizationID, store.NotificationDeliveryFilter{Status: status, EventType: eventType, Limit: limit})
	if err != nil {
		writeStoreError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": items})
}

func (s *Server) retryNotificationDelivery(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(r.PathValue("deliveryID"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid_id", "invalid notification delivery id")
		return
	}
	item, err := s.Store.RetryNotificationDeliveryWithAudit(r.Context(), principal(r), id, r.RemoteAddr)
	if errors.Is(err, store.ErrBusy) {
		writeError(w, http.StatusConflict, "delivery_in_progress", "notification delivery still has an active attempt")
		return
	}
	if errors.Is(err, store.ErrNotificationDeliveryNotRetryable) {
		writeError(w, http.StatusConflict, "delivery_not_retryable", err.Error())
		return
	}
	if errors.Is(err, store.ErrNotificationEndpointDisabled) {
		writeError(w, http.StatusConflict, "notification_endpoint_disabled", err.Error())
		return
	}
	if err != nil {
		writeStoreError(w, err)
		return
	}
	writeJSON(w, http.StatusAccepted, item)
}

func (s *Server) deleteNotificationEndpoint(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(r.PathValue("endpointID"))
	if err != nil {
		writeError(w, 400, "invalid_id", "invalid notification endpoint id")
		return
	}
	p := principal(r)
	if err = s.Store.DeleteNotificationEndpointWithAudit(r.Context(), p, id, r.RemoteAddr); err != nil {
		writeStoreError(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
