package httpapi

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestNotificationEndpointMaterial(t *testing.T) {
	endpoint, secret, reveal, err := notificationEndpointMaterial("pagerduty", "", "routing-key", "", "", "", 0, "", "", "", "", nil)
	if err != nil || endpoint != "https://events.pagerduty.com/v2/enqueue" || secret != "routing-key" || reveal {
		t.Fatalf("pagerduty material = %q/%q/%t, err=%v", endpoint, secret, reveal, err)
	}
	endpoint, secret, reveal, err = notificationEndpointMaterial("opsgenie", "", "", "api-key", "EU", "", 0, "", "", "", "", nil)
	if err != nil || endpoint != "https://api.eu.opsgenie.com/v2/alerts" || secret != "api-key" || reveal {
		t.Fatalf("opsgenie material = %q/%q/%t, err=%v", endpoint, secret, reveal, err)
	}
	endpoint, secret, reveal, err = notificationEndpointMaterial("smtp", "", "", "", "", "smtp.example.test", 465, "tls", "mailer", "password", "Dockyard <dockyard@example.test>", []string{"Ops <ops@example.test>"})
	if err != nil || endpoint != "smtp+tls://smtp.example.test:465" || reveal {
		t.Fatalf("smtp material = %q/%t, err=%v", endpoint, reveal, err)
	}
	var config map[string]any
	if json.Unmarshal([]byte(secret), &config) != nil || config["password"] != "password" {
		t.Fatalf("SMTP encrypted material is malformed: %q", secret)
	}
	if _, _, _, err = notificationEndpointMaterial("smtp", "", "", "", "", "smtp.example.test", 25, "plain", "u", "p", "bad", []string{"also bad"}); err == nil {
		t.Fatal("insecure or malformed SMTP configuration was accepted")
	}
	if _, _, _, err = notificationEndpointMaterial("webhook", "http://example.test/hook", "", "", "", "", 0, "", "", "", "", nil); err == nil || !strings.Contains(err.Error(), "HTTPS") {
		t.Fatalf("insecure webhook error = %v", err)
	}
}
