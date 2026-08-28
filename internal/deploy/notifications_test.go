package deploy

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/bendahma/dokploy-go/internal/store"
	"github.com/google/uuid"
)

func TestSendNotificationSignsExactBody(t *testing.T) {
	secret := []byte("test-signing-secret")
	payload := []byte(`{"event":"deployment.failed","text":"failed"}`)
	deliveryID := uuid.New()
	received := make(chan error, 1)
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			received <- err
			return
		}
		timestamp := r.Header.Get("X-Dockyard-Timestamp")
		mac := hmac.New(sha256.New, secret)
		_, _ = mac.Write([]byte(timestamp + "."))
		_, _ = mac.Write(body)
		expected := "sha256=" + hex.EncodeToString(mac.Sum(nil))
		if !hmac.Equal([]byte(expected), []byte(r.Header.Get("X-Dockyard-Signature-256"))) || r.Header.Get("X-Dockyard-Delivery") != deliveryID.String() || !strings.EqualFold(r.Header.Get("Content-Type"), "application/json") {
			received <- io.ErrUnexpectedEOF
			return
		}
		received <- nil
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()
	delivery := store.NotificationDelivery{ID: deliveryID, EventType: "deployment.failed", Payload: payload}
	code, err := sendNotification(context.Background(), server.Client(), server.URL, secret, delivery)
	if err != nil || code != http.StatusNoContent {
		t.Fatalf("code=%d err=%v", code, err)
	}
	if err := <-received; err != nil {
		t.Fatal("request signature or headers did not match")
	}
}

func TestSendIncidentNotifications(t *testing.T) {
	for _, kind := range []string{"pagerduty", "opsgenie"} {
		t.Run(kind, func(t *testing.T) {
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				body, _ := io.ReadAll(r.Body)
				if !json.Valid(body) || !bytes.Contains(body, []byte("deployment.failed")) {
					http.Error(w, "bad payload", http.StatusBadRequest)
					return
				}
				if kind == "opsgenie" && r.Header.Get("Authorization") != "GenieKey provider-secret" {
					http.Error(w, "bad auth", http.StatusUnauthorized)
					return
				}
				w.WriteHeader(http.StatusAccepted)
			}))
			defer server.Close()
			delivery := store.NotificationDelivery{ID: uuid.New(), EventType: "deployment.failed", ResourceType: "deployment", ResourceID: "d1", Payload: []byte(`{"event":"deployment.failed","resourceType":"deployment","resourceId":"d1","error":"boom","text":"deploy failed"}`)}
			code, err := sendIncidentNotification(context.Background(), server.Client(), kind, server.URL, "provider-secret", delivery)
			if err != nil || code != http.StatusAccepted {
				t.Fatalf("code=%d err=%v", code, err)
			}
		})
	}
}

func TestSMTPMessageUsesEnvelopeAddresses(t *testing.T) {
	delivery := store.NotificationDelivery{ID: uuid.New(), EventType: "backup.failed", Payload: []byte(`{"text":"Backup failed","error":"disk full"}`)}
	message, sender, recipients, err := smtpMessage(delivery, smtpMaterial{From: "Dockyard <dockyard@example.test>", To: []string{"Ops <ops@example.test>"}})
	if err != nil || sender != "dockyard@example.test" || len(recipients) != 1 || recipients[0] != "ops@example.test" {
		t.Fatalf("sender=%q recipients=%v err=%v", sender, recipients, err)
	}
	if !bytes.Contains(message, []byte("Subject: [Dockyard] backup.failed\r\n")) || !bytes.Contains(message, []byte("disk full")) {
		t.Fatalf("unexpected message: %s", message)
	}
}

func TestSendNotificationRejectsNonSuccess(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { http.Error(w, "no", http.StatusBadGateway) }))
	defer server.Close()
	code, err := sendNotification(context.Background(), server.Client(), server.URL, []byte("secret"), store.NotificationDelivery{ID: uuid.New(), Payload: []byte(`{}`)})
	if code != http.StatusBadGateway || err == nil {
		t.Fatalf("code=%d err=%v", code, err)
	}
}
