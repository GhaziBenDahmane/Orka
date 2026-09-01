package httpapi

import (
	"bytes"
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/GhaziBenDahmane/Orka/internal/cryptox"
	"github.com/GhaziBenDahmane/Orka/internal/store"
	"github.com/google/uuid"
)

func TestMoveServiceRequiresAccessToSourceAndTarget(t *testing.T) {
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
	organizationID, otherOrganizationID, userID := uuid.New(), uuid.New(), uuid.New()
	sourceProjectID, targetProjectID := uuid.New(), uuid.New()
	sourceEnvironmentID, targetEnvironmentID, otherEnvironmentID, serviceID := uuid.New(), uuid.New(), uuid.New(), uuid.New()
	token := "move-" + uuid.NewString()
	for _, statement := range []struct {
		query string
		args  []any
	}{
		{`INSERT INTO organizations(id,name,slug) VALUES($1,'Move API',$2),($3,'Other',$4)`, []any{organizationID, "move-api-" + organizationID.String(), otherOrganizationID, "move-api-" + otherOrganizationID.String()}},
		{`INSERT INTO users(id,email,password_hash) VALUES($1,$2,'x')`, []any{userID, userID.String() + "@example.test"}},
		{`INSERT INTO memberships(organization_id,user_id,role) VALUES($1,$2,'viewer')`, []any{organizationID, userID}},
		{`INSERT INTO sessions(id,user_id,token_hash,expires_at) VALUES($1,$2,$3,now()+interval '5 minutes')`, []any{uuid.New(), userID, cryptox.Digest(token)}},
		{`INSERT INTO projects(id,organization_id,name,slug) VALUES($1,$2,'Source','source'),($3,$2,'Target','target')`, []any{sourceProjectID, organizationID, targetProjectID}},
		{`INSERT INTO projects(id,organization_id,name,slug) VALUES($1,$2,'Other','other')`, []any{uuid.New(), otherOrganizationID}},
		{`INSERT INTO environments(id,project_id,name,slug) VALUES($1,$2,'Source','source'),($3,$4,'Target','target')`, []any{sourceEnvironmentID, sourceProjectID, targetEnvironmentID, targetProjectID}},
		{`INSERT INTO environments(id,project_id,name,slug) SELECT $1,id,'Other','other' FROM projects WHERE organization_id=$2`, []any{otherEnvironmentID, otherOrganizationID}},
		{`INSERT INTO environment_grants(environment_id,user_id,role) VALUES($1,$2,'developer')`, []any{sourceEnvironmentID, userID}},
		{`INSERT INTO compose_services(id,environment_id,name,slug,stack_name,compose_yaml) VALUES($1,$2,'App','app',$3,'services: {web: {image: nginx}}')`, []any{serviceID, sourceEnvironmentID, "move-api-" + serviceID.String()}},
	} {
		if _, err = db.Pool.Exec(ctx, statement.query, statement.args...); err != nil {
			t.Fatal(err)
		}
	}
	t.Cleanup(func() {
		_, _ = db.Pool.Exec(context.Background(), `DELETE FROM organizations WHERE id=$1`, organizationID)
		_, _ = db.Pool.Exec(context.Background(), `DELETE FROM users WHERE id=$1`, userID)
	})
	server := httptest.NewServer((&Server{Store: db, Logger: slog.New(slog.NewTextHandler(io.Discard, nil))}).Handler())
	defer server.Close()
	if status, response := scopedAPIRequest(t, server.URL+"/v1/environments", token, organizationID, http.MethodGet, nil); status != http.StatusOK || !bytes.Contains(response, []byte(sourceEnvironmentID.String())) || !bytes.Contains(response, []byte(targetEnvironmentID.String())) || bytes.Contains(response, []byte(otherEnvironmentID.String())) {
		t.Fatalf("environment inventory status=%d body=%s", status, response)
	}
	endpoint := server.URL + "/v1/services/" + serviceID.String() + "/environment"
	body := map[string]any{"environmentId": targetEnvironmentID}
	if status, response := scopedAPIRequest(t, endpoint, token, organizationID, http.MethodPut, body); status != http.StatusForbidden {
		t.Fatalf("move without target grant status=%d body=%s", status, response)
	}
	if _, err = db.Pool.Exec(ctx, `INSERT INTO environment_grants(environment_id,user_id,role) VALUES($1,$2,'developer')`, targetEnvironmentID, userID); err != nil {
		t.Fatal(err)
	}
	if status, response := scopedAPIRequest(t, endpoint, token, organizationID, http.MethodPut, body); status != http.StatusOK || !bytes.Contains(response, []byte(`"environmentId":"`+targetEnvironmentID.String()+`"`)) {
		t.Fatalf("authorized move status=%d body=%s", status, response)
	}
	var auditCount int
	if err = db.Pool.QueryRow(ctx, `SELECT count(*) FROM audit_events WHERE organization_id=$1 AND action='service.move' AND resource_id=$2`, organizationID, serviceID.String()).Scan(&auditCount); err != nil || auditCount != 1 {
		t.Fatalf("move audit count=%d err=%v", auditCount, err)
	}
}
