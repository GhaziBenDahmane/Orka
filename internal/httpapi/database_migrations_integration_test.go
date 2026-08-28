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
	"testing"
	"time"

	"github.com/bendahma/dokploy-go/internal/cryptox"
	"github.com/bendahma/dokploy-go/internal/store"
	"github.com/google/uuid"
)

func TestDatabaseMigrationHistoryAndCancellationAPI(t *testing.T) {
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
	organizationID, userID, projectID, environmentID, serviceID, databaseID := uuid.New(), uuid.New(), uuid.New(), uuid.New(), uuid.New(), uuid.New()
	token := "database-migration-" + uuid.NewString()
	statements := []struct {
		query string
		args  []any
	}{
		{`INSERT INTO organizations(id,name,slug) VALUES($1,'Migration API',$2)`, []any{organizationID, "migration-api-" + organizationID.String()}},
		{`INSERT INTO users(id,email,password_hash) VALUES($1,$2,'!test')`, []any{userID, userID.String() + "@example.test"}},
		{`INSERT INTO memberships(organization_id,user_id,role) VALUES($1,$2,'owner')`, []any{organizationID, userID}},
		{`INSERT INTO sessions(id,user_id,token_hash,expires_at) VALUES($1,$2,$3,now()+interval '5 minutes')`, []any{uuid.New(), userID, cryptox.Digest(token)}},
		{`INSERT INTO projects(id,organization_id,name,slug) VALUES($1,$2,'Project','project')`, []any{projectID, organizationID}},
		{`INSERT INTO environments(id,project_id,name,slug) VALUES($1,$2,'Production','production')`, []any{environmentID, projectID}},
		{`INSERT INTO compose_services(id,environment_id,name,slug,stack_name,compose_yaml) VALUES($1,$2,'Database','database',$3,'services: {}')`, []any{serviceID, environmentID, "migration-api-" + serviceID.String()}},
		{`INSERT INTO database_instances(id,environment_id,name,slug,engine,version,compose_service_id,encrypted_credentials,status) VALUES($1,$2,'Database','database','postgres','17',$3,'encrypted','running')`, []any{databaseID, environmentID, serviceID}},
	}
	for _, statement := range statements {
		if _, err = db.Pool.Exec(ctx, statement.query, statement.args...); err != nil {
			t.Fatal(err)
		}
	}
	t.Cleanup(func() {
		_, _ = db.Pool.Exec(context.Background(), `DELETE FROM organizations WHERE id=$1`, organizationID)
		_, _ = db.Pool.Exec(context.Background(), `DELETE FROM users WHERE id=$1`, userID)
	})
	migration, err := db.QueueDatabaseMigration(ctx, organizationID, store.DatabaseMigration{DatabaseInstanceID: databaseID, SourceKind: "dokploy", SourceID: "legacy-id", SourceEngine: "postgres", SourceVersion: "16", SourceHost: "legacy.internal", EncryptedSourceConfig: "encrypted-secret"})
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer((&Server{Store: db, Logger: slog.New(slog.NewTextHandler(io.Discard, nil))}).Handler())
	defer server.Close()

	status, body := scopedAPIRequest(t, server.URL+"/v1/databases/"+databaseID.String()+"/migrations", token, organizationID, http.MethodGet, nil)
	var history struct {
		Items []store.DatabaseMigration `json:"items"`
	}
	if err = json.Unmarshal(body, &history); status != http.StatusOK || err != nil || len(history.Items) != 1 || history.Items[0].ID != migration.ID {
		t.Fatalf("history status=%d body=%s err=%v", status, body, err)
	}
	if len(body) == 0 || bytes.Contains(body, []byte("encrypted-secret")) {
		t.Fatalf("history exposed encrypted connection material: %s", body)
	}
	status, body = scopedAPIRequest(t, server.URL+"/v1/database-migrations/"+migration.ID.String()+"/cancel", token, organizationID, http.MethodPost, map[string]any{})
	if status != http.StatusAccepted {
		t.Fatalf("cancel status=%d body=%s", status, body)
	}
	var auditCount int
	if err = db.Pool.QueryRow(ctx, `SELECT count(*) FROM audit_events WHERE organization_id=$1 AND action='database_migration.cancel' AND resource_id=$2`, organizationID, migration.ID.String()).Scan(&auditCount); err != nil || auditCount != 1 {
		t.Fatalf("cancellation audit count=%d err=%v", auditCount, err)
	}
}
