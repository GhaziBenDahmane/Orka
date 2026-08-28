package deploy

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
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

func TestSendNotificationRejectsNonSuccess(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { http.Error(w, "no", http.StatusBadGateway) }))
	defer server.Close()
	code, err := sendNotification(context.Background(), server.Client(), server.URL, []byte("secret"), store.NotificationDelivery{ID: uuid.New(), Payload: []byte(`{}`)})
	if code != http.StatusBadGateway || err == nil {
		t.Fatalf("code=%d err=%v", code, err)
	}
}
