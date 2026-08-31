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
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/bendahma/dokploy-go/internal/cryptox"
	"github.com/bendahma/dokploy-go/internal/database"
	"github.com/bendahma/dokploy-go/internal/deploy"
	"github.com/bendahma/dokploy-go/internal/store"
	"github.com/google/uuid"
)

func TestExternalDatabaseConfigPersistenceAllowlist(t *testing.T) {
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

	organizationID, userID := uuid.New(), uuid.New()
	projectID, environmentID := uuid.New(), uuid.New()
	token := "external-database-config-" + uuid.NewString()
	for _, statement := range []struct {
		query string
		args  []any
	}{
		{`INSERT INTO organizations(id,name,slug) VALUES($1,'External database config',$2)`, []any{organizationID, "external-database-config-" + organizationID.String()}},
		{`INSERT INTO users(id,email,password_hash) VALUES($1,$2,'!test')`, []any{userID, userID.String() + "@example.test"}},
		{`INSERT INTO memberships(organization_id,user_id,role) VALUES($1,$2,'owner')`, []any{organizationID, userID}},
		{`INSERT INTO sessions(id,user_id,token_hash,expires_at) VALUES($1,$2,$3,now()+interval '5 minutes')`, []any{uuid.New(), userID, cryptox.Digest(token)}},
		{`INSERT INTO projects(id,organization_id,name,slug) VALUES($1,$2,'Project','project')`, []any{projectID, organizationID}},
		{`INSERT INTO environments(id,project_id,name,slug) VALUES($1,$2,'Production','production')`, []any{environmentID, projectID}},
	} {
		if _, err = db.Pool.Exec(ctx, statement.query, statement.args...); err != nil {
			t.Fatal(err)
		}
	}
	t.Cleanup(func() {
		_, _ = db.Pool.Exec(context.Background(), `DELETE FROM organizations WHERE id=$1`, organizationID)
		_, _ = db.Pool.Exec(context.Background(), `DELETE FROM users WHERE id=$1`, userID)
	})

	driverDirectory := t.TempDir()
	driver := `#!/bin/sh
case "$(cat)" in
  *'"operation":"describe"'*) echo '{"protocolVersion":2,"description":{"name":"external-safe","defaultVersion":"1","capabilities":[],"persistentConfigKeys":["region"]}}' ;;
  *) echo '{"protocolVersion":2,"result":{"composeYaml":"services:\\n  data:\\n    image: postgres:17\\n","environment":{},"credentials":{"password":"generated-secret"},"internalUrl":"postgres://data:5432/app","version":"1"}}' ;;
esac
`
	if err = os.WriteFile(filepath.Join(driverDirectory, "external-safe"), []byte(driver), 0700); err != nil {
		t.Fatal(err)
	}
	registry := database.NewRegistry()
	if err = registry.LoadExternal(driverDirectory); err != nil {
		t.Fatal(err)
	}
	box, err := cryptox.New(bytes.Repeat([]byte{7}, 32))
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer((&Server{
		Store: db, Box: box, Databases: registry,
		Compiler:  deploy.Compiler{PublicNetwork: "traefik-public"},
		PublicURL: "https://dockyard.example.test", SessionTTL: time.Hour,
		Logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
	}).Handler())
	defer server.Close()

	secret := "must-not-be-persisted-" + uuid.NewString()
	body := []byte(`{"name":"External","slug":"data","engine":"external-safe","version":"1","config":{"region":"eu-west","apiKey":"` + secret + `"}}`)
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, server.URL+"/v1/environments/"+environmentID.String()+"/databases", bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Authorization", "Bearer "+token)
	request.Header.Set("X-Organization-ID", organizationID.String())
	request.Header.Set("Content-Type", "application/json")
	response, err := http.DefaultClient.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	responseBody, _ := io.ReadAll(response.Body)
	response.Body.Close()
	if response.StatusCode != http.StatusCreated {
		t.Fatalf("create external database status=%d body=%s", response.StatusCode, responseBody)
	}
	if bytes.Contains(responseBody, []byte(secret)) {
		t.Fatal("external render-only secret leaked in API response")
	}
	var created struct {
		Database store.DatabaseInstance `json:"database"`
	}
	if err = json.Unmarshal(responseBody, &created); err != nil {
		t.Fatal(err)
	}
	if len(created.Database.Config) != 1 || created.Database.Config["region"] != "eu-west" {
		t.Fatalf("created database config=%#v", created.Database.Config)
	}
	var persisted string
	if err = db.Pool.QueryRow(ctx, `SELECT config::text FROM database_instances WHERE id=$1`, created.Database.ID).Scan(&persisted); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(persisted, secret) || strings.Contains(persisted, "apiKey") || !strings.Contains(persisted, "eu-west") {
		t.Fatalf("unexpected persisted external config: %s", persisted)
	}
}
