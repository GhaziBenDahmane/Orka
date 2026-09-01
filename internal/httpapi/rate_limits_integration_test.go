package httpapi

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/GhaziBenDahmane/Orka/internal/cryptox"
	"github.com/GhaziBenDahmane/Orka/internal/store"
	"github.com/google/uuid"
)

func TestBootstrapRateLimitReturnsRetryAfter(t *testing.T) {
	databaseURL := os.Getenv("DOCKYARD_TEST_DATABASE_URL")
	if databaseURL == "" {
		t.Skip("DOCKYARD_TEST_DATABASE_URL is not set")
	}
	db, err := store.Open(context.Background(), databaseURL)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Pool.Close()
	if _, err := db.Pool.Exec(context.Background(), `DELETE FROM auth_rate_limits WHERE bucket='bootstrap'`); err != nil {
		t.Fatal(err)
	}
	server := (&Server{Store: db}).Handler()

	for attempt := 1; attempt <= 6; attempt++ {
		recorder := httptest.NewRecorder()
		request := httptest.NewRequest(http.MethodPost, "/v1/auth/bootstrap", bytes.NewBufferString(`{"email":"invalid","password":"long-enough-password","organization":"Test"}`))
		request.Header.Set("Content-Type", "application/json")
		server.ServeHTTP(recorder, request)
		if attempt <= 5 && recorder.Code != http.StatusBadRequest {
			t.Fatalf("attempt %d: status=%d body=%q", attempt, recorder.Code, recorder.Body.String())
		}
		if attempt == 6 && (recorder.Code != http.StatusTooManyRequests || recorder.Header().Get("Retry-After") == "") {
			t.Fatalf("limited attempt: status=%d retry-after=%q body=%q", recorder.Code, recorder.Header().Get("Retry-After"), recorder.Body.String())
		}
	}
}

func TestLoginDatabaseFailureIsNotReportedAsBadCredentials(t *testing.T) {
	databaseURL := os.Getenv("DOCKYARD_TEST_DATABASE_URL")
	if databaseURL == "" {
		t.Skip("DOCKYARD_TEST_DATABASE_URL is not set")
	}
	db, err := store.Open(context.Background(), databaseURL)
	if err != nil {
		t.Fatal(err)
	}
	server := (&Server{Store: db}).Handler()
	db.Pool.Close()

	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodPost, "/v1/auth/login", bytes.NewBufferString(`{"email":"user@example.test","password":"wrong-password"}`))
	request.Header.Set("Content-Type", "application/json")
	server.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusInternalServerError || !bytes.Contains(recorder.Body.Bytes(), []byte(`"code":"internal_error"`)) {
		t.Fatalf("status=%d body=%q", recorder.Code, recorder.Body.String())
	}
	if bytes.Contains(recorder.Body.Bytes(), []byte("closed pool")) {
		t.Fatalf("database detail leaked: %q", recorder.Body.String())
	}
}

func TestMissingLoginAccountUsesIdentifierRateLimit(t *testing.T) {
	databaseURL := os.Getenv("DOCKYARD_TEST_DATABASE_URL")
	if databaseURL == "" {
		t.Skip("DOCKYARD_TEST_DATABASE_URL is not set")
	}
	db, err := store.Open(context.Background(), databaseURL)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(db.Pool.Close)
	email := "missing-" + uuid.NewString() + "@example.test"
	if _, err = db.Pool.Exec(context.Background(), `INSERT INTO auth_rate_limits(bucket,key_hash,window_started_at,attempts) VALUES('login',$1,now(),10) ON CONFLICT(bucket,key_hash) DO UPDATE SET window_started_at=now(),attempts=10`, cryptox.Digest(email)); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = db.Pool.Exec(context.Background(), `DELETE FROM auth_rate_limits WHERE bucket='login' AND key_hash=$1`, cryptox.Digest(email))
	})

	request := httptest.NewRequest(http.MethodPost, "/v1/auth/login", bytes.NewBufferString(`{"email":"`+email+`","password":"wrong-password"}`))
	request.Header.Set("Content-Type", "application/json")
	response := httptest.NewRecorder()
	(&Server{Store: db}).Handler().ServeHTTP(response, request)
	if response.Code != http.StatusTooManyRequests || response.Header().Get("Retry-After") == "" {
		t.Fatalf("missing-account limit status=%d body=%q", response.Code, response.Body.String())
	}
}

func TestPublicIdentityEndpointsAreRateLimitedBeforeExpensiveWork(t *testing.T) {
	databaseURL := os.Getenv("DOCKYARD_TEST_DATABASE_URL")
	if databaseURL == "" {
		t.Skip("DOCKYARD_TEST_DATABASE_URL is not set")
	}
	db, err := store.Open(context.Background(), databaseURL)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(db.Pool.Close)
	clientKey := cryptox.Digest("192.0.2.1")
	if _, err = db.Pool.Exec(context.Background(), `DELETE FROM auth_rate_limits WHERE bucket IN ('login-client','invitation-client','sso-discovery-client','sso-start-client','sso-callback-client','sso-metadata-client','agent-enroll-client','webhook-client','scim-client')`); err != nil {
		t.Fatal(err)
	}
	for bucket, attempts := range map[string]int{
		"login-client":         300,
		"invitation-client":    300,
		"sso-discovery-client": 300,
		"sso-start-client":     300,
		"sso-callback-client":  300,
		"sso-metadata-client":  300,
		"agent-enroll-client":  120,
		"webhook-client":       600,
		"scim-client":          1200,
	} {
		if _, err = db.Pool.Exec(context.Background(), `INSERT INTO auth_rate_limits(bucket,key_hash,window_started_at,attempts) VALUES($1,$2,now(),$3) ON CONFLICT(bucket,key_hash) DO UPDATE SET window_started_at=now(),attempts=excluded.attempts`, bucket, clientKey, attempts); err != nil {
			t.Fatal(err)
		}
	}
	t.Cleanup(func() {
		_, _ = db.Pool.Exec(context.Background(), `DELETE FROM auth_rate_limits WHERE bucket IN ('login-client','invitation-client','sso-discovery-client','sso-start-client','sso-callback-client','sso-metadata-client','agent-enroll-client','webhook-client','scim-client')`)
	})
	server := (&Server{Store: db, AgentCACertificate: []byte("configured"), AgentCAKey: []byte("configured")}).Handler()
	requests := []*http.Request{
		httptest.NewRequest(http.MethodPost, "/v1/auth/login", bytes.NewBufferString(`{"email":"user@example.test","password":"wrong-password"}`)),
		httptest.NewRequest(http.MethodPost, "/v1/invitations/accept", bytes.NewBufferString(`{"token":"dky_inv_0000000000000000000000000000000000000000","displayName":"User","password":"long-enough-password"}`)),
		httptest.NewRequest(http.MethodGet, "/v1/auth/sso/discover?email=user@example.test", nil),
		httptest.NewRequest(http.MethodGet, "/v1/auth/sso/"+uuid.NewString()+"/start", nil),
		httptest.NewRequest(http.MethodGet, "/v1/auth/sso/callback?state=state&code=code", nil),
		httptest.NewRequest(http.MethodGet, "/v1/auth/saml/discover?email=user@example.test", nil),
		httptest.NewRequest(http.MethodGet, "/v1/auth/saml/"+uuid.NewString()+"/metadata", nil),
		httptest.NewRequest(http.MethodGet, "/v1/auth/saml/"+uuid.NewString()+"/start", nil),
		httptest.NewRequest(http.MethodPost, "/v1/auth/saml/"+uuid.NewString()+"/acs", strings.NewReader("SAMLResponse=value")),
		httptest.NewRequest(http.MethodPost, "/v1/agent/enroll", bytes.NewBufferString(`{"token":"dky_agent_invalid","csr":"invalid"}`)),
		httptest.NewRequest(http.MethodPost, "/v1/hooks/deploy/missing-token", nil),
		httptest.NewRequest(http.MethodPost, "/v1/hooks/provider/invalid-id", nil),
		httptest.NewRequest(http.MethodPost, "/v1/hooks/template-repositories/invalid-id", nil),
		httptest.NewRequest(http.MethodGet, "/scim/v2/Users", nil),
	}
	for index, request := range requests {
		request.Header.Set("Content-Type", "application/json")
		if strings.Contains(request.URL.Path, "/acs") {
			request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		}
		recorder := httptest.NewRecorder()
		server.ServeHTTP(recorder, request)
		if recorder.Code != http.StatusTooManyRequests || recorder.Header().Get("Retry-After") == "" {
			t.Fatalf("request %d %s: status=%d retry-after=%q body=%q", index, request.URL.Path, recorder.Code, recorder.Header().Get("Retry-After"), recorder.Body.String())
		}
	}

	otherClient := httptest.NewRequest(http.MethodGet, "/v1/auth/sso/discover?email=user@example.test", nil)
	otherClient.RemoteAddr = "198.51.100.8:4321"
	otherResponse := httptest.NewRecorder()
	server.ServeHTTP(otherResponse, otherClient)
	if otherResponse.Code == http.StatusTooManyRequests {
		t.Fatalf("one client exhausted another client's authentication allowance: body=%q", otherResponse.Body.String())
	}
}

func TestSCIMCredentialRateLimitUsesProtocolError(t *testing.T) {
	databaseURL := os.Getenv("DOCKYARD_TEST_DATABASE_URL")
	if databaseURL == "" {
		t.Skip("DOCKYARD_TEST_DATABASE_URL is not set")
	}
	db, err := store.Open(context.Background(), databaseURL)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(db.Pool.Close)
	token := "missing-scim-token-" + uuid.NewString()
	key := cryptox.Digest(token)
	if _, err = db.Pool.Exec(context.Background(), `INSERT INTO auth_rate_limits(bucket,key_hash,window_started_at,attempts) VALUES('scim-credential',$1,now(),600) ON CONFLICT(bucket,key_hash) DO UPDATE SET window_started_at=now(),attempts=600`, key); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = db.Pool.Exec(context.Background(), `DELETE FROM auth_rate_limits WHERE bucket='scim-credential' AND key_hash=$1`, key)
	})

	request := httptest.NewRequest(http.MethodGet, "/scim/v2/Users", nil)
	request.RemoteAddr = "203.0.113.29:4321"
	request.Header.Set("Authorization", "Bearer "+token)
	response := httptest.NewRecorder()
	(&Server{Store: db}).Handler().ServeHTTP(response, request)
	if response.Code != http.StatusTooManyRequests || response.Header().Get("Retry-After") == "" || response.Header().Get("Content-Type") != "application/scim+json" {
		t.Fatalf("status=%d retry-after=%q content-type=%q body=%q", response.Code, response.Header().Get("Retry-After"), response.Header().Get("Content-Type"), response.Body.String())
	}
}

func TestPublicWebhookTargetsAreRateLimitedBeforeCredentialLookup(t *testing.T) {
	databaseURL := os.Getenv("DOCKYARD_TEST_DATABASE_URL")
	if databaseURL == "" {
		t.Skip("DOCKYARD_TEST_DATABASE_URL is not set")
	}
	db, err := store.Open(context.Background(), databaseURL)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(db.Pool.Close)

	targets := []struct {
		kind       string
		identifier string
		path       string
	}{
		{kind: "deploy", identifier: "missing-token", path: "/v1/hooks/deploy/missing-token"},
		{kind: "provider", identifier: "invalid-id", path: "/v1/hooks/provider/invalid-id"},
		{kind: "template-repository", identifier: "invalid-id", path: "/v1/hooks/template-repositories/invalid-id"},
	}
	for _, target := range targets {
		key := cryptox.Digest(target.kind + ":" + target.identifier)
		if _, err = db.Pool.Exec(context.Background(), `INSERT INTO auth_rate_limits(bucket,key_hash,window_started_at,attempts) VALUES('webhook-target',$1,now(),300) ON CONFLICT(bucket,key_hash) DO UPDATE SET window_started_at=now(),attempts=300`, key); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() {
			_, _ = db.Pool.Exec(context.Background(), `DELETE FROM auth_rate_limits WHERE bucket='webhook-target' AND key_hash=$1`, key)
		})

		request := httptest.NewRequest(http.MethodPost, target.path, nil)
		request.RemoteAddr = "198.51.100.19:4321"
		response := httptest.NewRecorder()
		(&Server{Store: db}).Handler().ServeHTTP(response, request)
		if response.Code != http.StatusTooManyRequests || response.Header().Get("Retry-After") == "" {
			t.Fatalf("%s: status=%d retry-after=%q body=%q", target.kind, response.Code, response.Header().Get("Retry-After"), response.Body.String())
		}
	}
}
