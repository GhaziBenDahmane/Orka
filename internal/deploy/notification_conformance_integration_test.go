package deploy

import (
	"bufio"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"testing"

	"github.com/bendahma/dokploy-go/internal/cryptox"
	"github.com/bendahma/dokploy-go/internal/store"
	"github.com/google/uuid"
)

func TestNotificationProviderConformance(t *testing.T) {
	if os.Getenv("DOCKYARD_NOTIFICATION_CONFORMANCE") != "1" {
		t.Skip("DOCKYARD_NOTIFICATION_CONFORMANCE is not set")
	}
	db, ctx := recoveryTestStore(t)
	key := sha256.Sum256([]byte("notification-conformance-key"))
	box, err := cryptox.New(key[:])
	if err != nil {
		t.Fatal(err)
	}

	type requestState struct {
		sync.Mutex
		attempts map[string]int
		errors   []string
	}
	requests := &requestState{attempts: map[string]int{}}
	providerSecret := map[string]string{
		"retry": "webhook-signing-secret", "slack": "slack-signing-secret",
		"pagerduty": "pagerduty-routing-key", "opsgenie": "opsgenie-api-key",
	}
	httpServer := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, readErr := io.ReadAll(r.Body)
		kind := strings.TrimPrefix(r.URL.Path, "/")
		requests.Lock()
		defer requests.Unlock()
		requests.attempts[kind]++
		if readErr != nil {
			requests.errors = append(requests.errors, readErr.Error())
			http.Error(w, "read failed", http.StatusBadRequest)
			return
		}
		switch kind {
		case "retry", "slack":
			timestamp := r.Header.Get("X-Dockyard-Timestamp")
			mac := hmac.New(sha256.New, []byte(providerSecret[kind]))
			_, _ = mac.Write([]byte(timestamp + "."))
			_, _ = mac.Write(body)
			expected := "sha256=" + hex.EncodeToString(mac.Sum(nil))
			if timestamp == "" || !hmac.Equal([]byte(expected), []byte(r.Header.Get("X-Dockyard-Signature-256"))) || r.Header.Get("X-Dockyard-Delivery") == "" {
				requests.errors = append(requests.errors, kind+": invalid signature headers")
				http.Error(w, "invalid signature", http.StatusUnauthorized)
				return
			}
		case "pagerduty":
			var payload struct {
				RoutingKey string `json:"routing_key"`
				Action     string `json:"event_action"`
			}
			if json.Unmarshal(body, &payload) != nil || payload.RoutingKey != providerSecret[kind] || payload.Action != "trigger" {
				requests.errors = append(requests.errors, "pagerduty: invalid body")
				http.Error(w, "invalid body", http.StatusBadRequest)
				return
			}
		case "opsgenie":
			if r.Header.Get("Authorization") != "GenieKey "+providerSecret[kind] || !json.Valid(body) {
				requests.errors = append(requests.errors, "opsgenie: invalid authorization or body")
				http.Error(w, "invalid request", http.StatusUnauthorized)
				return
			}
		default:
			requests.errors = append(requests.errors, "unexpected HTTP provider "+kind)
			http.NotFound(w, r)
			return
		}
		if kind == "retry" && requests.attempts[kind] == 1 {
			http.Error(w, "retry", http.StatusServiceUnavailable)
			return
		}
		w.WriteHeader(http.StatusAccepted)
	}))
	defer httpServer.Close()

	smtpEndpoint, smtpTLS, smtpMessages := startNotificationSMTPServer(t)
	organizationID, otherOrganizationID := uuid.New(), uuid.New()
	projectID, environmentID, serviceID, deploymentID := uuid.New(), uuid.New(), uuid.New(), uuid.New()
	for _, statement := range []struct {
		query string
		args  []any
	}{
		{`INSERT INTO organizations(id,name,slug) VALUES($1,'Notifications',$2),($3,'Other',$4)`, []any{organizationID, "notifications-" + organizationID.String(), otherOrganizationID, "other-" + otherOrganizationID.String()}},
		{`INSERT INTO projects(id,organization_id,name,slug) VALUES($1,$2,'Project','project')`, []any{projectID, organizationID}},
		{`INSERT INTO environments(id,project_id,name,slug) VALUES($1,$2,'Production','production')`, []any{environmentID, projectID}},
		{`INSERT INTO compose_services(id,environment_id,name,slug,stack_name,compose_yaml) VALUES($1,$2,'App','app',$3,'services: {}')`, []any{serviceID, environmentID, "notify-" + serviceID.String()}},
		{`INSERT INTO deployments(id,compose_service_id,revision,compose_snapshot,status,trigger) VALUES($1,$2,1,'services: {}','failed','manual')`, []any{deploymentID, serviceID}},
	} {
		if _, err = db.Pool.Exec(ctx, statement.query, statement.args...); err != nil {
			t.Fatal(err)
		}
	}

	type provider struct{ name, kind, url, secret string }
	smtpMaterial, _ := json.Marshal(smtpMaterial{Username: "mailer", Password: "smtp-password", From: "Dockyard <dockyard@example.test>", To: []string{"Ops <ops@example.test>"}})
	providers := []provider{
		{"retry", "webhook", httpServer.URL + "/retry", providerSecret["retry"]},
		{"slack", "slack", httpServer.URL + "/slack", providerSecret["slack"]},
		{"pagerduty", "pagerduty", httpServer.URL + "/pagerduty", providerSecret["pagerduty"]},
		{"opsgenie", "opsgenie", httpServer.URL + "/opsgenie", providerSecret["opsgenie"]},
		{"smtp", "smtp", smtpEndpoint, string(smtpMaterial)},
	}
	for _, provider := range providers {
		endpointID := uuid.New()
		encryptedURL, encryptErr := box.Encrypt([]byte(provider.url), "notification-url:"+endpointID.String())
		if encryptErr != nil {
			t.Fatal(encryptErr)
		}
		encryptedSecret, encryptErr := box.Encrypt([]byte(provider.secret), "notification-secret:"+endpointID.String())
		if encryptErr != nil {
			t.Fatal(encryptErr)
		}
		_, err = db.CreateNotificationEndpoint(ctx, store.NotificationEndpoint{ID: endpointID, OrganizationID: organizationID, Name: provider.name, Kind: provider.kind, EncryptedURL: encryptedURL, EncryptedSecret: encryptedSecret, Events: []string{"deployment.failed"}, Enabled: true})
		if err != nil {
			t.Fatal(err)
		}
		if encryptedURL == provider.url || encryptedSecret == provider.secret {
			t.Fatal("provider material was stored in plaintext")
		}
	}
	otherEndpointID := uuid.New()
	otherURL, _ := box.Encrypt([]byte(httpServer.URL+"/other"), "notification-url:"+otherEndpointID.String())
	otherSecret, _ := box.Encrypt([]byte("other-secret"), "notification-secret:"+otherEndpointID.String())
	if _, err = db.CreateNotificationEndpoint(ctx, store.NotificationEndpoint{ID: otherEndpointID, OrganizationID: otherOrganizationID, Name: "other", Kind: "webhook", EncryptedURL: otherURL, EncryptedSecret: otherSecret, Events: []string{"deployment.failed"}, Enabled: true}); err != nil {
		t.Fatal(err)
	}

	jobPayload, _ := json.Marshal(map[string]string{"deploymentId": deploymentID.String()})
	for range 2 {
		if err = db.QueueFailureNotifications(ctx, "deploy.compose", jobPayload, fmt.Errorf("deployment failed with private value")); err != nil {
			t.Fatal(err)
		}
	}
	worker := &Worker{Store: db, Box: box, ID: "notification-conformance", NotificationClient: httpServer.Client(), notificationTLS: smtpTLS}
	for processed := 0; processed < 6; processed++ {
		claimed, claimErr := worker.claim(ctx)
		if claimErr != nil {
			t.Fatalf("claim notification job %d: %v", processed+1, claimErr)
		}
		deliveryErr := worker.execute(ctx, claimed)
		if err = worker.finish(ctx, claimed, deliveryErr); err != nil {
			t.Fatal(err)
		}
		if deliveryErr != nil {
			if _, err = db.Pool.Exec(ctx, `UPDATE jobs SET run_after=now() WHERE id=$1 AND status='pending'`, claimed.ID); err != nil {
				t.Fatal(err)
			}
		}
	}

	var deliveries, succeeded, jobs, succeededJobs, attempts, otherDeliveries int
	if err = db.Pool.QueryRow(ctx, `SELECT count(*),count(*) FILTER (WHERE status='succeeded') FROM notification_deliveries WHERE endpoint_id IN (SELECT id FROM notification_endpoints WHERE organization_id=$1)`, organizationID).Scan(&deliveries, &succeeded); err != nil {
		t.Fatal(err)
	}
	if err = db.Pool.QueryRow(ctx, `SELECT count(*),count(*) FILTER (WHERE status='succeeded'),sum(attempts) FROM jobs WHERE kind='notify.webhook' AND payload->>'deliveryId' IN (SELECT d.id::text FROM notification_deliveries d JOIN notification_endpoints e ON e.id=d.endpoint_id WHERE e.organization_id=$1)`, organizationID).Scan(&jobs, &succeededJobs, &attempts); err != nil {
		t.Fatal(err)
	}
	if err = db.Pool.QueryRow(ctx, `SELECT count(*) FROM notification_deliveries WHERE endpoint_id=$1`, otherEndpointID).Scan(&otherDeliveries); err != nil {
		t.Fatal(err)
	}
	requests.Lock()
	httpAttempts := map[string]int{}
	for key, value := range requests.attempts {
		httpAttempts[key] = value
	}
	requestErrors := append([]string(nil), requests.errors...)
	requests.Unlock()
	if deliveries != 5 || succeeded != 5 || jobs != 5 || succeededJobs != 5 || attempts != 6 || otherDeliveries != 0 || len(requestErrors) != 0 {
		t.Fatalf("deliveries=%d succeeded=%d jobs=%d succeeded_jobs=%d attempts=%d other=%d provider_errors=%v", deliveries, succeeded, jobs, succeededJobs, attempts, otherDeliveries, requestErrors)
	}
	if httpAttempts["retry"] != 2 || httpAttempts["slack"] != 1 || httpAttempts["pagerduty"] != 1 || httpAttempts["opsgenie"] != 1 {
		t.Fatalf("unexpected HTTP attempts: %#v", httpAttempts)
	}
	message := <-smtpMessages
	if !strings.Contains(message, "Subject: [Dockyard] deployment.failed") || !strings.Contains(message, "deployment failed with private value") {
		t.Fatalf("unexpected SMTP message: %s", message)
	}
	evidence, _ := json.Marshal(map[string]any{
		"status": "passed", "durableWorkerPath": true, "signedWebhook": true,
		"slackCompatible": true, "pagerDuty": true, "opsgenie": true,
		"authenticatedImplicitTLSSMTP": true, "retryRecovered": true,
		"tenantIsolation": true, "deduplicated": true, "secretsEncrypted": true,
		"deliveries": deliveries, "jobAttempts": attempts,
	})
	fmt.Printf("NOTIFICATION_EVIDENCE %s\n", evidence)
}

func startNotificationSMTPServer(t *testing.T) (string, *tls.Config, <-chan string) {
	t.Helper()
	seed := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	certificate := seed.TLS.Certificates[0]
	leaf := seed.Certificate()
	seed.Close()
	roots := x509.NewCertPool()
	roots.AddCert(leaf)
	listener, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{certificate}, MinVersion: tls.VersionTLS12})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	messages := make(chan string, 1)
	serverErrors := make(chan error, 1)
	go func() {
		connection, acceptErr := listener.Accept()
		if acceptErr != nil {
			serverErrors <- acceptErr
			return
		}
		defer connection.Close()
		reader := bufio.NewReader(connection)
		writer := bufio.NewWriter(connection)
		write := func(value string) error {
			_, writeErr := writer.WriteString(value)
			if writeErr == nil {
				writeErr = writer.Flush()
			}
			return writeErr
		}
		if acceptErr = write("220 smtp.example.test ESMTP\r\n"); acceptErr != nil {
			serverErrors <- acceptErr
			return
		}
		authenticated := false
		for {
			line, readErr := reader.ReadString('\n')
			if readErr != nil {
				serverErrors <- readErr
				return
			}
			command := strings.TrimSpace(line)
			switch {
			case strings.HasPrefix(command, "EHLO "):
				readErr = write("250-smtp.example.test\r\n250-AUTH PLAIN\r\n250 OK\r\n")
			case strings.HasPrefix(command, "AUTH PLAIN "):
				decoded, decodeErr := base64.StdEncoding.DecodeString(strings.TrimPrefix(command, "AUTH PLAIN "))
				if decodeErr != nil || string(decoded) != "\x00mailer\x00smtp-password" {
					serverErrors <- fmt.Errorf("invalid SMTP credentials")
					return
				}
				authenticated = true
				readErr = write("235 2.7.0 authenticated\r\n")
			case strings.HasPrefix(command, "MAIL FROM:") || strings.HasPrefix(command, "RCPT TO:"):
				if !authenticated {
					serverErrors <- fmt.Errorf("SMTP envelope before authentication")
					return
				}
				readErr = write("250 2.1.0 ok\r\n")
			case command == "DATA":
				if readErr = write("354 end with dot\r\n"); readErr != nil {
					serverErrors <- readErr
					return
				}
				var body strings.Builder
				for {
					dataLine, dataErr := reader.ReadString('\n')
					if dataErr != nil {
						serverErrors <- dataErr
						return
					}
					if dataLine == ".\r\n" {
						break
					}
					body.WriteString(dataLine)
				}
				messages <- body.String()
				readErr = write("250 2.0.0 queued\r\n")
			case command == "QUIT":
				if readErr = write("221 2.0.0 bye\r\n"); readErr != nil {
					serverErrors <- readErr
				}
				return
			default:
				serverErrors <- fmt.Errorf("unexpected SMTP command %q", command)
				return
			}
			if readErr != nil {
				serverErrors <- readErr
				return
			}
		}
	}()
	t.Cleanup(func() {
		select {
		case err := <-serverErrors:
			if err != nil && !strings.Contains(err.Error(), "closed network connection") {
				t.Errorf("SMTP server: %v", err)
			}
		default:
		}
	})
	clientTLS := &tls.Config{RootCAs: roots, ServerName: "example.com", MinVersion: tls.VersionTLS12}
	return "smtp+tls://" + listener.Addr().String(), clientTLS, messages
}
