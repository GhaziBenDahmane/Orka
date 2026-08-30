package httpapi

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/bendahma/dokploy-go/internal/cryptox"
	"github.com/bendahma/dokploy-go/internal/store"
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
	if _, err = db.Pool.Exec(context.Background(), `DELETE FROM auth_rate_limits WHERE bucket IN ('sso-discovery-global','sso-start-global','sso-callback-global','sso-metadata-global','agent-enroll-global')`); err != nil {
		t.Fatal(err)
	}
	for bucket, attempts := range map[string]int{
		"sso-discovery-global": 300,
		"sso-start-global":     300,
		"sso-callback-global":  300,
		"sso-metadata-global":  300,
		"agent-enroll-global":  120,
	} {
		if _, err = db.Pool.Exec(context.Background(), `INSERT INTO auth_rate_limits(bucket,key_hash,window_started_at,attempts) VALUES($1,$2,now(),$3) ON CONFLICT(bucket,key_hash) DO UPDATE SET window_started_at=now(),attempts=excluded.attempts`, bucket, cryptox.Digest("instance"), attempts); err != nil {
			t.Fatal(err)
		}
	}
	t.Cleanup(func() {
		_, _ = db.Pool.Exec(context.Background(), `DELETE FROM auth_rate_limits WHERE bucket IN ('sso-discovery-global','sso-start-global','sso-callback-global','sso-metadata-global','agent-enroll-global')`)
	})
	server := (&Server{Store: db, AgentCACertificate: []byte("configured"), AgentCAKey: []byte("configured")}).Handler()
	requests := []*http.Request{
		httptest.NewRequest(http.MethodGet, "/v1/auth/sso/discover?email=user@example.test", nil),
		httptest.NewRequest(http.MethodGet, "/v1/auth/sso/"+uuid.NewString()+"/start", nil),
		httptest.NewRequest(http.MethodGet, "/v1/auth/sso/callback?state=state&code=code", nil),
		httptest.NewRequest(http.MethodGet, "/v1/auth/saml/discover?email=user@example.test", nil),
		httptest.NewRequest(http.MethodGet, "/v1/auth/saml/"+uuid.NewString()+"/metadata", nil),
		httptest.NewRequest(http.MethodGet, "/v1/auth/saml/"+uuid.NewString()+"/start", nil),
		httptest.NewRequest(http.MethodPost, "/v1/auth/saml/"+uuid.NewString()+"/acs", strings.NewReader("SAMLResponse=value")),
		httptest.NewRequest(http.MethodPost, "/v1/agent/enroll", bytes.NewBufferString(`{"token":"dky_agent_invalid","csr":"invalid"}`)),
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
}
