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
	"github.com/bendahma/dokploy-go/internal/database"
	"github.com/bendahma/dokploy-go/internal/store"
	"github.com/google/uuid"
)

func TestLinkedDatabaseCreateRotateAndDeletionSafetyAPI(t *testing.T) {
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
	box, err := cryptox.New([]byte("0123456789abcdef0123456789abcdef"))
	if err != nil {
		t.Fatal(err)
	}
	organizationID, otherOrganizationID, userID := uuid.New(), uuid.New(), uuid.New()
	projectID, environmentID, serviceID := uuid.New(), uuid.New(), uuid.New()
	token := "linked-database-api-" + uuid.NewString()
	for _, statement := range []struct {
		query string
		args  []any
	}{
		{`INSERT INTO organizations(id,name,slug) VALUES($1,'Linked API',$2),($3,'Other',$4)`, []any{organizationID, "linked-api-" + organizationID.String(), otherOrganizationID, "linked-api-other-" + otherOrganizationID.String()}},
		{`INSERT INTO users(id,email,password_hash) VALUES($1,$2,'!test')`, []any{userID, userID.String() + "@example.test"}},
		{`INSERT INTO memberships(organization_id,user_id,role) VALUES($1,$2,'owner'),($3,$2,'owner')`, []any{organizationID, userID, otherOrganizationID}},
		{`INSERT INTO sessions(id,user_id,token_hash,expires_at) VALUES($1,$2,$3,now()+interval '5 minutes')`, []any{uuid.New(), userID, cryptox.Digest(token)}},
		{`INSERT INTO projects(id,organization_id,name,slug) VALUES($1,$2,'Project','project')`, []any{projectID, organizationID}},
		{`INSERT INTO environments(id,project_id,name,slug) VALUES($1,$2,'Production','production')`, []any{environmentID, projectID}},
		{`INSERT INTO compose_services(id,environment_id,name,slug,stack_name,compose_yaml) VALUES($1,$2,'Application','application',$3,'services: {db: {image: postgres:17}, web: {image: nginx}}')`, []any{serviceID, environmentID, "linked-api-" + serviceID.String()}},
		{`INSERT INTO deployments(id,compose_service_id,revision,compose_snapshot,status,trigger,finished_at) VALUES($1,$2,1,'services: {}','succeeded','test',now())`, []any{uuid.New(), serviceID}},
	} {
		if _, err = db.Pool.Exec(ctx, statement.query, statement.args...); err != nil {
			t.Fatal(err)
		}
	}
	t.Cleanup(func() {
		_, _ = db.Pool.Exec(context.Background(), `DELETE FROM jobs WHERE resource_key LIKE 'database:%'`)
		_, _ = db.Pool.Exec(context.Background(), `DELETE FROM organizations WHERE id=ANY($1)`, []uuid.UUID{organizationID, otherOrganizationID})
		_, _ = db.Pool.Exec(context.Background(), `DELETE FROM users WHERE id=$1`, userID)
	})

	server := httptest.NewServer((&Server{Store: db, Box: box, Databases: database.NewRegistry(), Logger: slog.New(slog.NewTextHandler(io.Discard, nil))}).Handler())
	defer server.Close()
	createURL := server.URL + "/v1/services/" + serviceID.String() + "/databases"
	body := map[string]any{"name": "Application PostgreSQL", "engine": "postgres", "version": "17", "connectionServiceName": "db", "database": "app", "username": "app", "password": "initial-secret", "port": 5432}
	status, response := scopedAPIRequest(t, createURL, token, organizationID, http.MethodPost, body)
	var linked store.DatabaseInstance
	if err = json.Unmarshal(response, &linked); err != nil || status != http.StatusCreated || linked.ManagementKind != "compose" || linked.ConnectionServiceName != "db" || linked.Status != "running" {
		t.Fatalf("create linked database status=%d body=%s item=%#v err=%v", status, response, linked, err)
	}
	if status, response = scopedAPIRequest(t, createURL, token, organizationID, http.MethodPost, map[string]any{"name": "Missing", "engine": "postgres", "connectionServiceName": "missing", "database": "app", "username": "app", "password": "secret"}); status != http.StatusBadRequest || !bytes.Contains(response, []byte(`"code":"invalid_compose_database"`)) {
		t.Fatalf("missing Compose service status=%d body=%s", status, response)
	}
	if status, response = scopedAPIRequest(t, server.URL+"/v1/databases/"+linked.ID.String()+"/credentials", token, organizationID, http.MethodPut, map[string]any{"engine": "ignored", "version": "17", "connectionServiceName": "db", "database": "app", "username": "app", "password": "rotated-secret", "port": 5432}); status != http.StatusOK {
		t.Fatalf("rotate linked credentials status=%d body=%s", status, response)
	}
	var encrypted string
	if err = db.Pool.QueryRow(ctx, `SELECT encrypted_credentials FROM database_instances WHERE id=$1`, linked.ID).Scan(&encrypted); err != nil {
		t.Fatal(err)
	}
	plain, err := box.Decrypt(encrypted, cryptox.ResourceContext("database-credentials", linked.ID.String()))
	if err != nil || !bytes.Contains(plain, []byte(`"password":"rotated-secret"`)) || bytes.Contains(plain, []byte("initial-secret")) {
		t.Fatalf("rotated credentials=%s err=%v", plain, err)
	}
	if status, response = scopedAPIRequest(t, server.URL+"/v1/databases/"+linked.ID.String()+"/backups", token, organizationID, http.MethodPost, nil); status != http.StatusAccepted {
		t.Fatalf("queue linked backup status=%d body=%s", status, response)
	}
	if status, response = scopedAPIRequest(t, server.URL+"/v1/databases/"+linked.ID.String()+"/credentials", token, organizationID, http.MethodPut, map[string]any{"version": "17", "connectionServiceName": "db", "database": "app", "username": "app", "password": "racing-secret"}); status != http.StatusConflict || !bytes.Contains(response, []byte(`"code":"database_busy"`)) {
		t.Fatalf("rotation during backup status=%d body=%s", status, response)
	}
	if status, response = scopedAPIRequest(t, server.URL+"/v1/databases/"+linked.ID.String(), token, organizationID, http.MethodDelete, nil); status != http.StatusConflict || !bytes.Contains(response, []byte(`"code":"compose_database_owned"`)) {
		t.Fatalf("linked database delete status=%d body=%s", status, response)
	}
	if status, response = scopedAPIRequest(t, server.URL+"/v1/databases/"+linked.ID.String()+"/link", token, organizationID, http.MethodDelete, nil); status != http.StatusConflict || !bytes.Contains(response, []byte(`"code":"database_busy"`)) {
		t.Fatalf("linked database unlink during backup status=%d body=%s", status, response)
	}
	if _, err = db.Pool.Exec(ctx, `UPDATE jobs SET status='cancelled',finished_at=now() WHERE resource_key=$1`, "database:"+linked.ID.String()); err != nil {
		t.Fatal(err)
	}
	if _, err = db.Pool.Exec(ctx, `UPDATE database_backups SET status='cancelled',finished_at=now() WHERE database_instance_id=$1 AND status='queued'`, linked.ID); err != nil {
		t.Fatal(err)
	}
	if status, response = scopedAPIRequest(t, server.URL+"/v1/databases/"+linked.ID.String()+"/link", token, organizationID, http.MethodDelete, nil); status != http.StatusAccepted || !bytes.Contains(response, []byte(`"status":"unlink_queued"`)) {
		t.Fatalf("linked database unlink status=%d body=%s", status, response)
	}
	var unlinkQueued, unlinkMarked bool
	if err = db.Pool.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM jobs WHERE kind='delete.database-link' AND payload->>'databaseId'=$1 AND status='pending'),EXISTS(SELECT 1 FROM database_instances WHERE id=$2 AND deletion_requested_at IS NOT NULL)`, linked.ID.String(), linked.ID).Scan(&unlinkQueued, &unlinkMarked); err != nil || !unlinkQueued || !unlinkMarked {
		t.Fatalf("linked database unlink not durable: queued=%v marked=%v err=%v", unlinkQueued, unlinkMarked, err)
	}
	var serviceExists bool
	if err = db.Pool.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM compose_services WHERE id=$1)`, serviceID).Scan(&serviceExists); err != nil || !serviceExists {
		t.Fatalf("linked database deletion affected service: exists=%v err=%v", serviceExists, err)
	}
}
