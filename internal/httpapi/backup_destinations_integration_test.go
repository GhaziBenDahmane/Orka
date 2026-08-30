package httpapi

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/bendahma/dokploy-go/internal/cryptox"
	"github.com/bendahma/dokploy-go/internal/store"
	"github.com/google/uuid"
)

func TestBackupDestinationCredentialRotation(t *testing.T) {
	databaseURL := os.Getenv("DOCKYARD_TEST_DATABASE_URL")
	if databaseURL == "" {
		t.Skip("DOCKYARD_TEST_DATABASE_URL is not set")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	db, err := store.Open(ctx, databaseURL)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(db.Pool.Close)
	box, err := cryptox.New(bytes.Repeat([]byte{7}, 32))
	if err != nil {
		t.Fatal(err)
	}
	organizationID, userID := uuid.New(), uuid.New()
	token := "backup-destination-" + uuid.NewString()
	for _, statement := range []struct {
		query string
		args  []any
	}{
		{`INSERT INTO organizations(id,name,slug) VALUES($1,'Backup destination',$2)`, []any{organizationID, "backup-destination-" + organizationID.String()}},
		{`INSERT INTO users(id,email,password_hash) VALUES($1,$2,'!test')`, []any{userID, userID.String() + "@example.test"}},
		{`INSERT INTO memberships(organization_id,user_id,role) VALUES($1,$2,'owner')`, []any{organizationID, userID}},
		{`INSERT INTO sessions(id,user_id,token_hash,expires_at) VALUES($1,$2,$3,now()+interval '5 minutes')`, []any{uuid.New(), userID, cryptox.Digest(token)}},
	} {
		if _, err = db.Pool.Exec(ctx, statement.query, statement.args...); err != nil {
			t.Fatal(err)
		}
	}
	t.Cleanup(func() {
		_, _ = db.Pool.Exec(context.Background(), `DELETE FROM organizations WHERE id=$1`, organizationID)
		_, _ = db.Pool.Exec(context.Background(), `DELETE FROM users WHERE id=$1`, userID)
	})

	seenNewCredential := false
	objectStore := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.Header.Get("Authorization"), "Credential=new-access/") {
			seenNewCredential = true
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer objectStore.Close()
	api := httptest.NewServer((&Server{Store: db, Box: box, Logger: slog.New(slog.NewTextHandler(io.Discard, nil))}).Handler())
	defer api.Close()
	do := func(method, path string, body map[string]any) (*http.Response, []byte) {
		encoded, _ := json.Marshal(body)
		request, requestErr := http.NewRequest(method, api.URL+path, bytes.NewReader(encoded))
		if requestErr != nil {
			t.Fatal(requestErr)
		}
		request.Header.Set("Authorization", "Bearer "+token)
		request.Header.Set("X-Organization-ID", organizationID.String())
		request.Header.Set("Content-Type", "application/json")
		response, requestErr := http.DefaultClient.Do(request)
		if requestErr != nil {
			t.Fatal(requestErr)
		}
		data, _ := io.ReadAll(response.Body)
		response.Body.Close()
		return response, data
	}
	base := map[string]any{"name": "archive", "endpoint": objectStore.URL, "region": "us-east-1", "bucket": "backups", "prefix": "initial", "useTls": false, "accessKey": "old-access", "secretKey": "old-secret"}
	response, data := do(http.MethodPost, "/v1/backup-destinations", base)
	if response.StatusCode != http.StatusCreated {
		t.Fatalf("create status=%d body=%s", response.StatusCode, data)
	}
	var created store.BackupDestination
	if err = json.Unmarshal(data, &created); err != nil {
		t.Fatal(err)
	}
	base["name"], base["prefix"], base["accessKey"], base["secretKey"] = "rotated", "current", "new-access", "new-secret"
	response, data = do(http.MethodPut, "/v1/backup-destinations/"+created.ID.String(), base)
	if response.StatusCode != http.StatusOK || !seenNewCredential || bytes.Contains(data, []byte("new-secret")) {
		t.Fatalf("update status=%d usedNewCredential=%v body=%s", response.StatusCode, seenNewCredential, data)
	}
	stored, err := db.GetBackupDestination(ctx, organizationID, created.ID)
	if err != nil || stored.Name != "rotated" || stored.Prefix != "current" {
		t.Fatalf("stored destination=%#v err=%v", stored, err)
	}
	plain, err := box.DecryptResource(stored.EncryptedCredentials, "backup-destination", created.ID.String(), "backup-destination")
	if err != nil || !bytes.Contains(plain, []byte("new-access")) || !bytes.Contains(plain, []byte("new-secret")) || bytes.Contains(plain, []byte("old-secret")) {
		t.Fatalf("rotated credentials were not persisted safely: %v", err)
	}
}
