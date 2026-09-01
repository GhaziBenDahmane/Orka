package httpapi

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/GhaziBenDahmane/Orka/internal/cryptox"
	"github.com/GhaziBenDahmane/Orka/internal/store"
	"github.com/google/uuid"
)

func TestCommitStatusDeliveryHistoryAndRetryAPI(t *testing.T) {
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
	if err = store.Migrate(ctx, db.Pool); err != nil {
		t.Fatal(err)
	}
	organizationID, otherOrganizationID := uuid.New(), uuid.New()
	adminID, viewerID, otherAdminID := uuid.New(), uuid.New(), uuid.New()
	adminToken, viewerToken, otherAdminToken := "commit-admin-"+uuid.NewString(), "commit-viewer-"+uuid.NewString(), "commit-other-"+uuid.NewString()
	projectID, otherProjectID, environmentID, otherEnvironmentID := uuid.New(), uuid.New(), uuid.New(), uuid.New()
	serviceID, otherServiceID, deploymentID, otherDeploymentID := uuid.New(), uuid.New(), uuid.New(), uuid.New()
	deliveryID, activeDeliveryID, otherDeliveryID := uuid.New(), uuid.New(), uuid.New()
	statements := []struct {
		query string
		args  []any
	}{
		{`INSERT INTO organizations(id,name,slug) VALUES($1,'Commit status API',$2),($3,'Other commit status API',$4)`, []any{organizationID, "commit-status-api-" + organizationID.String(), otherOrganizationID, "other-commit-status-api-" + otherOrganizationID.String()}},
		{`INSERT INTO users(id,email,password_hash) VALUES($1,$2,'!test'),($3,$4,'!test'),($5,$6,'!test')`, []any{adminID, adminID.String() + "@example.test", viewerID, viewerID.String() + "@example.test", otherAdminID, otherAdminID.String() + "@example.test"}},
		{`INSERT INTO memberships(organization_id,user_id,role) VALUES($1,$2,'admin'),($1,$3,'viewer'),($4,$5,'admin')`, []any{organizationID, adminID, viewerID, otherOrganizationID, otherAdminID}},
		{`INSERT INTO sessions(id,user_id,token_hash,expires_at) VALUES($1,$2,$3,now()+interval '10 minutes'),($4,$5,$6,now()+interval '10 minutes'),($7,$8,$9,now()+interval '10 minutes')`, []any{uuid.New(), adminID, cryptox.Digest(adminToken), uuid.New(), viewerID, cryptox.Digest(viewerToken), uuid.New(), otherAdminID, cryptox.Digest(otherAdminToken)}},
		{`INSERT INTO projects(id,organization_id,name,slug) VALUES($1,$2,'Project','project'),($3,$4,'Other','other')`, []any{projectID, organizationID, otherProjectID, otherOrganizationID}},
		{`INSERT INTO environments(id,project_id,name,slug) VALUES($1,$2,'Production','production'),($3,$4,'Production','production')`, []any{environmentID, projectID, otherEnvironmentID, otherProjectID}},
		{`INSERT INTO compose_services(id,environment_id,name,slug,stack_name,compose_yaml) VALUES($1,$2,'API','api',$3,'services: {}'),($4,$5,'Other API','other-api',$6,'services: {}')`, []any{serviceID, environmentID, "commit-api-" + serviceID.String(), otherServiceID, otherEnvironmentID, "other-commit-api-" + otherServiceID.String()}},
		{`INSERT INTO deployments(id,compose_service_id,revision,compose_snapshot,env_snapshot,status,trigger,commit_sha) VALUES($1,$2,1,'services: {}','','failed','manual',$3),($4,$5,1,'services: {}','','failed','manual',$6)`, []any{deploymentID, serviceID, strings.Repeat("a", 40), otherDeploymentID, otherServiceID, strings.Repeat("b", 40)}},
		{`INSERT INTO commit_status_deliveries(id,deployment_id,state,status,response_code,last_error,finished_at,provider,repository_url,status_context,credential_server,credential_username,encrypted_credential) VALUES($1,$2,'failure','failed',503,'raw-secret-error',now(),'github','https://git.example/private','secret/context','secret-host','secret-user','encrypted-secret'),($3,$2,'error','failed',NULL,'active-secret-error',now(),'gitlab','https://git.example/active','secret/context','secret-host','secret-user','encrypted-secret'),($4,$5,'failure','failed',503,'foreign-secret-error',now(),'bitbucket','https://git.example/foreign','secret/context','secret-host','secret-user','encrypted-secret')`, []any{deliveryID, deploymentID, activeDeliveryID, otherDeliveryID, otherDeploymentID}},
		{`INSERT INTO jobs(id,kind,payload,status,attempts,max_attempts,last_error,finished_at) VALUES($1,'commit.status',$2,'failed',8,8,'raw-secret-error',now())`, []any{uuid.New(), []byte(`{"deliveryId":"` + deliveryID.String() + `"}`)}},
		{`INSERT INTO jobs(id,kind,payload,status,attempts,max_attempts,last_error,run_after) VALUES($1,'commit.status',$2,'pending',1,8,'active-secret-error',now()+interval '1 minute')`, []any{uuid.New(), []byte(`{"deliveryId":"` + activeDeliveryID.String() + `"}`)}},
	}
	for _, statement := range statements {
		if _, err = db.Pool.Exec(ctx, statement.query, statement.args...); err != nil {
			t.Fatal(err)
		}
	}
	t.Cleanup(func() {
		_, _ = db.Pool.Exec(context.Background(), `DELETE FROM organizations WHERE id IN ($1,$2)`, organizationID, otherOrganizationID)
		_, _ = db.Pool.Exec(context.Background(), `DELETE FROM users WHERE id IN ($1,$2,$3)`, adminID, viewerID, otherAdminID)
	})

	server := httptest.NewServer((&Server{Store: db, Logger: slog.New(slog.NewTextHandler(io.Discard, nil))}).Handler())
	t.Cleanup(server.Close)
	status, body := scopedAPIRequest(t, server.URL+"/v1/commit-status-deliveries?status=failed&provider=github&state=failure&limit=10", adminToken, organizationID, http.MethodGet, nil)
	if status != http.StatusOK || !strings.Contains(string(body), deliveryID.String()) || strings.Contains(string(body), "secret") || strings.Contains(string(body), "git.example") || strings.Contains(string(body), strings.Repeat("a", 40)) || strings.Contains(string(body), otherDeliveryID.String()) {
		t.Fatalf("commit status history status=%d body=%s", status, body)
	}
	for _, endpoint := range []string{
		server.URL + "/v1/commit-status-deliveries?status=invalid",
		server.URL + "/v1/commit-status-deliveries?provider=unknown",
		server.URL + "/v1/commit-status-deliveries?state=unknown",
		server.URL + "/v1/commit-status-deliveries?limit=201",
	} {
		if status, _ = scopedAPIRequest(t, endpoint, adminToken, organizationID, http.MethodGet, nil); status != http.StatusBadRequest {
			t.Fatalf("invalid callback query %s status=%d", endpoint, status)
		}
	}
	if status, _ = scopedAPIRequest(t, server.URL+"/v1/commit-status-deliveries", viewerToken, organizationID, http.MethodGet, nil); status != http.StatusForbidden {
		t.Fatalf("viewer history status=%d, want 403", status)
	}
	if status, _ = scopedAPIRequest(t, server.URL+"/v1/commit-status-deliveries/"+otherDeliveryID.String()+"/retry", adminToken, organizationID, http.MethodPost, nil); status != http.StatusNotFound {
		t.Fatalf("cross-tenant retry status=%d, want 404", status)
	}
	if status, body = scopedAPIRequest(t, server.URL+"/v1/commit-status-deliveries/"+activeDeliveryID.String()+"/retry", adminToken, organizationID, http.MethodPost, nil); status != http.StatusConflict || !strings.Contains(string(body), `"code":"delivery_in_progress"`) {
		t.Fatalf("active retry status=%d body=%s", status, body)
	}
	if status, body = scopedAPIRequest(t, server.URL+"/v1/commit-status-deliveries/"+deliveryID.String()+"/retry", adminToken, organizationID, http.MethodPost, nil); status != http.StatusAccepted || strings.Contains(string(body), "secret") || strings.Contains(string(body), "git.example") || !strings.Contains(string(body), `"status":"pending"`) || !strings.Contains(string(body), `"inProgress":true`) {
		t.Fatalf("redrive status=%d body=%s", status, body)
	}
	if status, body = scopedAPIRequest(t, server.URL+"/v1/commit-status-deliveries/"+deliveryID.String()+"/retry", adminToken, organizationID, http.MethodPost, nil); status != http.StatusConflict || !strings.Contains(string(body), `"code":"delivery_in_progress"`) {
		t.Fatalf("duplicate redrive status=%d body=%s", status, body)
	}
	if status, body = scopedAPIRequest(t, server.URL+"/v1/commit-status-deliveries", otherAdminToken, otherOrganizationID, http.MethodGet, nil); status != http.StatusOK || !strings.Contains(string(body), otherDeliveryID.String()) || strings.Contains(string(body), deliveryID.String()) {
		t.Fatalf("foreign tenant history status=%d body=%s", status, body)
	}
}
