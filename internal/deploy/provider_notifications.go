package deploy

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/mail"
	"net/smtp"
	"net/url"
	"strings"
	"time"

	"github.com/bendahma/dokploy-go/internal/store"
)

type notificationPayload struct {
	Event        string `json:"event"`
	ResourceType string `json:"resourceType"`
	ResourceID   string `json:"resourceId"`
	Error        string `json:"error"`
	Text         string `json:"text"`
}

func sendIncidentNotification(ctx context.Context, client *http.Client, kind, endpoint, secret string, delivery store.NotificationDelivery) (int, error) {
	var original notificationPayload
	if err := json.Unmarshal(delivery.Payload, &original); err != nil {
		return 0, err
	}
	if original.Text == "" {
		original.Text = "Dockyard " + delivery.EventType + " for " + delivery.ResourceType + " " + delivery.ResourceID
	}
	var payload any
	switch kind {
	case "pagerduty":
		payload = map[string]any{
			"routing_key":  secret,
			"event_action": "trigger",
			"dedup_key":    "dockyard:" + delivery.ResourceType + ":" + delivery.ResourceID,
			"payload":      map[string]any{"summary": original.Text, "source": "dockyard", "severity": "error", "component": delivery.ResourceType, "custom_details": map[string]string{"event": delivery.EventType, "resourceId": delivery.ResourceID, "error": original.Error}},
		}
	case "opsgenie":
		payload = map[string]any{"message": original.Text, "alias": "dockyard:" + delivery.ResourceType + ":" + delivery.ResourceID, "description": original.Error, "priority": "P1", "details": map[string]string{"event": delivery.EventType, "resourceType": delivery.ResourceType, "resourceId": delivery.ResourceID}}
	default:
		return 0, errors.New("unsupported incident notification provider")
	}
	body, _ := json.Marshal(payload)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		return 0, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "Dockyard-Notifications/1.0")
	if kind == "opsgenie" {
		req.Header.Set("Authorization", "GenieKey "+secret)
	}
	response, err := client.Do(req)
	code := 0
	if response != nil {
		code = response.StatusCode
		_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, 64<<10))
		_ = response.Body.Close()
	}
	if err == nil && (code < 200 || code >= 300) {
		err = fmt.Errorf("%s endpoint returned HTTP %d", kind, code)
	}
	return code, err
}

type smtpMaterial struct {
	Username string   `json:"username"`
	Password string   `json:"password"`
	From     string   `json:"from"`
	To       []string `json:"to"`
}

func sendSMTPNotification(ctx context.Context, endpoint string, encryptedMaterial []byte, delivery store.NotificationDelivery) (int, error) {
	parsed, err := url.Parse(endpoint)
	if err != nil || (parsed.Scheme != "smtp+tls" && parsed.Scheme != "smtp+starttls") || parsed.Hostname() == "" || parsed.Port() == "" || parsed.User != nil || parsed.Path != "" {
		return 0, errors.New("invalid SMTP endpoint")
	}
	var material smtpMaterial
	if err = json.Unmarshal(encryptedMaterial, &material); err != nil {
		return 0, err
	}
	message, sender, recipients, err := smtpMessage(delivery, material)
	if err != nil {
		return 0, err
	}
	dialer := &net.Dialer{Timeout: 15 * time.Second}
	tlsConfig := &tls.Config{MinVersion: tls.VersionTLS12, ServerName: parsed.Hostname()}
	deadline := time.Now().Add(15 * time.Second)
	if contextDeadline, ok := ctx.Deadline(); ok && contextDeadline.Before(deadline) {
		deadline = contextDeadline
	}
	var client *smtp.Client
	if parsed.Scheme == "smtp+tls" {
		connection, dialErr := (&tls.Dialer{NetDialer: dialer, Config: tlsConfig}).DialContext(ctx, "tcp", parsed.Host)
		if dialErr != nil {
			return 0, dialErr
		}
		_ = connection.SetDeadline(deadline)
		client, err = smtp.NewClient(connection, parsed.Hostname())
		if err != nil {
			_ = connection.Close()
			return 0, err
		}
	} else {
		connection, dialErr := dialer.DialContext(ctx, "tcp", parsed.Host)
		if dialErr != nil {
			return 0, dialErr
		}
		_ = connection.SetDeadline(deadline)
		client, err = smtp.NewClient(connection, parsed.Hostname())
		if err != nil {
			_ = connection.Close()
			return 0, err
		}
		if err = client.StartTLS(tlsConfig); err != nil {
			_ = client.Close()
			return 0, err
		}
	}
	defer client.Close()
	if material.Username != "" {
		if err = client.Auth(smtp.PlainAuth("", material.Username, material.Password, parsed.Hostname())); err != nil {
			return 0, err
		}
	}
	if err = client.Mail(sender); err != nil {
		return 0, err
	}
	for _, recipient := range recipients {
		if err = client.Rcpt(recipient); err != nil {
			return 0, err
		}
	}
	writer, err := client.Data()
	if err != nil {
		return 0, err
	}
	if _, err = writer.Write(message); err == nil {
		err = writer.Close()
	} else {
		_ = writer.Close()
	}
	if err != nil {
		return 0, err
	}
	if err = client.Quit(); err != nil {
		return 0, err
	}
	return 250, nil
}

func smtpMessage(delivery store.NotificationDelivery, material smtpMaterial) ([]byte, string, []string, error) {
	from, err := mail.ParseAddress(material.From)
	if err != nil {
		return nil, "", nil, err
	}
	recipients := make([]string, 0, len(material.To))
	toHeaders := make([]string, 0, len(material.To))
	for _, value := range material.To {
		address, parseErr := mail.ParseAddress(value)
		if parseErr != nil {
			return nil, "", nil, parseErr
		}
		recipients = append(recipients, address.Address)
		toHeaders = append(toHeaders, address.String())
	}
	if len(recipients) == 0 {
		return nil, "", nil, errors.New("SMTP notification has no recipients")
	}
	var payload notificationPayload
	_ = json.Unmarshal(delivery.Payload, &payload)
	subject := "[Dockyard] " + delivery.EventType
	body := payload.Text
	if body == "" {
		body = subject
	}
	if payload.Error != "" {
		body += "\r\n\r\n" + payload.Error
	}
	message := strings.Join([]string{
		"From: " + from.String(),
		"To: " + strings.Join(toHeaders, ", "),
		"Date: " + time.Now().UTC().Format(time.RFC1123Z),
		"Message-ID: <" + delivery.ID.String() + "@dockyard.local>",
		"Subject: " + subject,
		"MIME-Version: 1.0",
		"Content-Type: text/plain; charset=UTF-8",
		"Content-Transfer-Encoding: 8bit",
		"",
		strings.ReplaceAll(body, "\n", "\r\n"),
		"",
	}, "\r\n")
	return []byte(message), from.Address, recipients, nil
}
