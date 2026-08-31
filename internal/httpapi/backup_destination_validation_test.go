package httpapi

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/bendahma/dokploy-go/internal/store"
)

func TestNormalizedBackupDestinationName(t *testing.T) {
	if name, ok := normalizedBackupDestinationName("  production backups  "); !ok || name != "production backups" {
		t.Fatalf("name=%q valid=%t", name, ok)
	}
	for _, value := range []string{"", "  ", "line\nbreak", strings.Repeat("n", maxBackupDestinationNameBytes+1)} {
		if name, ok := normalizedBackupDestinationName(value); ok {
			t.Errorf("invalid name %q normalized to %q", value, name)
		}
	}
}

func TestRequiredRemoteBackupRejectsPlaintextBeforeConnectivityCheck(t *testing.T) {
	server := &Server{Store: &store.Store{RequireRemoteBackups: true}}
	body := []byte(`{"name":"remote","endpoint":"http://objects.example.test","bucket":"backups","accessKey":"access","secretKey":"secret","useTls":false}`)
	request := httptest.NewRequest(http.MethodPost, "/v1/backup-destinations", bytes.NewReader(body))
	request.Header.Set("Content-Type", "application/json")
	response := httptest.NewRecorder()

	server.createBackupDestination(response, request)
	if response.Code != http.StatusBadRequest || !strings.Contains(response.Body.String(), `"code":"remote_backup_tls_required"`) {
		t.Fatalf("status=%d body=%q", response.Code, response.Body.String())
	}
}
