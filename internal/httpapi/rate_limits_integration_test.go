package httpapi

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/bendahma/dokploy-go/internal/store"
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
