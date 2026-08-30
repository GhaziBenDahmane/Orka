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

func TestNotificationEndpointMaterialRejectsUnsafeWebhookURLs(t *testing.T) {
	for _, endpoint := range []string{
		" https://hooks.example.test/notify",
		"https://user@hooks.example.test/notify",
		"https://bad_label.example.test/notify",
		"https://-bad.example.test/notify",
		"https://hooks.example.test:/notify",
		"https://hooks.example.test:0/notify",
		"https://hooks.example.test:65536/notify",
		"https://[not-an-ip]/notify",
		"https://hooks.example.test/notify#secret",
		strings.Repeat("https://hooks.example.test/", 700),
	} {
		if _, _, _, err := notificationEndpointMaterial("webhook", endpoint, "", "", "", "", 0, "", "", "", "", nil); err == nil {
			t.Errorf("unsafe webhook URL %q was accepted", endpoint)
		}
	}
	for _, endpoint := range []string{
		"https://hooks.example.test/notify?tenant=one",
		"https://hooks.example.test:9443/notify",
		"https://127.0.0.1/notify",
		"https://[2001:db8::1]:9443/notify",
	} {
		if _, _, _, err := notificationEndpointMaterial("webhook", endpoint, "", "", "", "", 0, "", "", "", "", nil); err != nil {
			t.Errorf("valid webhook URL %q was rejected: %v", endpoint, err)
		}
	}
}

func TestNotificationEndpointMaterialBoundsSMTPFields(t *testing.T) {
	tests := []struct {
		host, username, password, from string
		to                             []string
	}{
		{host: "bad_label.example.test", from: "dockyard@example.test", to: []string{"ops@example.test"}},
		{host: "smtp.example.test.", from: "dockyard@example.test", to: []string{"ops@example.test"}},
		{host: strings.Repeat("a", 64) + ".example.test", from: "dockyard@example.test", to: []string{"ops@example.test"}},
		{host: "smtp.example.test", username: strings.Repeat("u", maxSMTPUsernameBytes+1), password: "secret", from: "dockyard@example.test", to: []string{"ops@example.test"}},
		{host: "smtp.example.test", username: "mailer", password: strings.Repeat("p", maxSMTPPasswordBytes+1), from: "dockyard@example.test", to: []string{"ops@example.test"}},
		{host: "smtp.example.test", username: "mailer\nadmin", password: "secret", from: "dockyard@example.test", to: []string{"ops@example.test"}},
		{host: "smtp.example.test", username: "mailer", password: "secret\nvalue", from: "dockyard@example.test", to: []string{"ops@example.test"}},
		{host: "smtp.example.test", from: strings.Repeat("a", maxSMTPAddressBytes+1), to: []string{"ops@example.test"}},
		{host: "smtp.example.test", from: "dockyard@example.test", to: []string{strings.Repeat("a", maxSMTPRecipientAddressBytes+1)}},
	}
	for i, test := range tests {
		if _, _, _, err := notificationEndpointMaterial("smtp", "", "", "", "", test.host, 587, "starttls", test.username, test.password, test.from, test.to); err == nil {
			t.Errorf("unsafe SMTP configuration %d was accepted", i)
		}
	}
}

func TestNotificationEndpointNameIsBoundedAndSingleLine(t *testing.T) {
	for _, name := range []string{"", "line\nbreak", "nul\x00byte", strings.Repeat("n", maxNotificationNameBytes+1)} {
		if validNotificationEndpointName(name) {
			t.Errorf("invalid notification endpoint name %q was accepted", name)
		}
	}
	if !validNotificationEndpointName(strings.Repeat("n", maxNotificationNameBytes)) {
		t.Fatal("maximum-length notification endpoint name was rejected")
	}
}
