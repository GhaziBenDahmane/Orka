package httpapi

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/bendahma/dokploy-go/internal/store"
)

func TestHealthIsIndependentOfDependencies(t *testing.T) {
	called := false
	server := (&Server{ReadinessCheck: func(context.Context) error {
		called = true
		return errors.New("database credentials: secret-value")
	}}).Handler()
	recorder := httptest.NewRecorder()
	server.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/healthz", nil))

	if recorder.Code != http.StatusOK || recorder.Body.String() != "{\"status\":\"ok\"}\n" {
		t.Fatalf("unexpected liveness response: status=%d body=%q", recorder.Code, recorder.Body.String())
	}
	if recorder.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("liveness response is cacheable: %q", recorder.Header().Get("Cache-Control"))
	}
	if called {
		t.Fatal("liveness endpoint must not check dependencies")
	}
}

func TestReadyChecksDatabaseWithoutLeakingError(t *testing.T) {
	server := (&Server{ReadinessCheck: func(context.Context) error {
		return errors.New("password=secret-value")
	}}).Handler()
	recorder := httptest.NewRecorder()
	server.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/readyz", nil))

	if recorder.Code != http.StatusServiceUnavailable {
		t.Fatalf("status=%d body=%q", recorder.Code, recorder.Body.String())
	}
	if recorder.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("readiness response is cacheable: %q", recorder.Header().Get("Cache-Control"))
	}
	if body := recorder.Body.String(); !strings.Contains(body, `"code":"database_unavailable"`) || strings.Contains(body, "secret-value") {
		t.Fatalf("unexpected readiness response: %q", body)
	}
}

func TestReadyReportsHealthyDatabase(t *testing.T) {
	server := (&Server{ReadinessCheck: func(context.Context) error { return nil }}).Handler()
	recorder := httptest.NewRecorder()
	server.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/readyz", nil))

	if recorder.Code != http.StatusOK || recorder.Body.String() != "{\"status\":\"ready\"}\n" {
		t.Fatalf("unexpected readiness response: status=%d body=%q", recorder.Code, recorder.Body.String())
	}
}

func TestReadyHonorsRequestCancellation(t *testing.T) {
	server := (&Server{ReadinessCheck: func(ctx context.Context) error {
		<-ctx.Done()
		return ctx.Err()
	}}).Handler()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
	defer cancel()
	recorder := httptest.NewRecorder()
	server.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/readyz", nil).WithContext(ctx))

	if recorder.Code != http.StatusServiceUnavailable {
		t.Fatalf("status=%d body=%q", recorder.Code, recorder.Body.String())
	}
}

func TestReadyTracksPostgresAvailability(t *testing.T) {
	databaseURL := os.Getenv("DOCKYARD_TEST_DATABASE_URL")
	if databaseURL == "" {
		t.Skip("DOCKYARD_TEST_DATABASE_URL is not set")
	}
	database, err := store.Open(context.Background(), databaseURL)
	if err != nil {
		t.Fatal(err)
	}
	server := (&Server{Store: database}).Handler()

	request := func() *httptest.ResponseRecorder {
		recorder := httptest.NewRecorder()
		server.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/readyz", nil))
		return recorder
	}
	if recorder := request(); recorder.Code != http.StatusOK {
		database.Pool.Close()
		t.Fatalf("healthy database: status=%d body=%q", recorder.Code, recorder.Body.String())
	}

	database.Pool.Close()
	if recorder := request(); recorder.Code != http.StatusServiceUnavailable {
		t.Fatalf("closed database: status=%d body=%q", recorder.Code, recorder.Body.String())
	}
}
