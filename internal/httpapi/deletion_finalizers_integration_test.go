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

func TestDeletionFinalizerHistoryAndRetryAPI(t *testing.T) {
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
	organizationID, otherOrganizationID := uuid.New(), uuid.New()
	adminID, viewerID, otherAdminID := uuid.New(), uuid.New(), uuid.New()
	adminToken, viewerToken, otherAdminToken := "finalizer-admin-"+uuid.NewString(), "finalizer-viewer-"+uuid.NewString(), "finalizer-other-"+uuid.NewString()
	projectID, otherProjectID, environmentID, otherEnvironmentID := uuid.New(), uuid.New(), uuid.New(), uuid.New()
	serviceID, activeServiceID, otherServiceID := uuid.New(), uuid.New(), uuid.New()
	statements := []struct {
		query string
		args  []any
	}{
		{`INSERT INTO organizations(id,name,slug) VALUES($1,'Finalizer API',$2),($3,'Other finalizer API',$4)`, []any{organizationID, "finalizer-api-" + organizationID.String(), otherOrganizationID, "other-finalizer-api-" + otherOrganizationID.String()}},
		{`INSERT INTO users(id,email,password_hash) VALUES($1,$2,'!test'),($3,$4,'!test'),($5,$6,'!test')`, []any{adminID, adminID.String() + "@example.test", viewerID, viewerID.String() + "@example.test", otherAdminID, otherAdminID.String() + "@example.test"}},
		{`INSERT INTO memberships(organization_id,user_id,role) VALUES($1,$2,'admin'),($1,$3,'viewer'),($4,$5,'admin')`, []any{organizationID, adminID, viewerID, otherOrganizationID, otherAdminID}},
		{`INSERT INTO sessions(id,user_id,token_hash,expires_at) VALUES($1,$2,$3,now()+interval '10 minutes'),($4,$5,$6,now()+interval '10 minutes'),($7,$8,$9,now()+interval '10 minutes')`, []any{uuid.New(), adminID, cryptox.Digest(adminToken), uuid.New(), viewerID, cryptox.Digest(viewerToken), uuid.New(), otherAdminID, cryptox.Digest(otherAdminToken)}},
		{`INSERT INTO projects(id,organization_id,name,slug) VALUES($1,$2,'Project','project'),($3,$4,'Other','other')`, []any{projectID, organizationID, otherProjectID, otherOrganizationID}},
		{`INSERT INTO environments(id,project_id,name,slug) VALUES($1,$2,'Production','production'),($3,$4,'Other','other')`, []any{environmentID, projectID, otherEnvironmentID, otherProjectID}},
		{`INSERT INTO compose_services(id,environment_id,name,slug,stack_name,compose_yaml,deletion_requested_at) VALUES($1,$2,'Failed service','failed',$3,'services: {}',now()-interval '20 minutes'),($4,$2,'Active service','active',$5,'services: {}',now()-interval '10 minutes'),($6,$7,'Foreign service','foreign',$8,'services: {}',now()-interval '1 hour')`, []any{serviceID, environmentID, "failed-" + serviceID.String(), activeServiceID, "active-" + activeServiceID.String(), otherServiceID, otherEnvironmentID, "foreign-" + otherServiceID.String()}},
		{`INSERT INTO jobs(id,kind,payload,resource_key,status,attempts,max_attempts,last_error,finished_at) VALUES($1,'delete.compose',$2,$3,'failed',10,10,'raw secret swarm failure',now()),($4,'delete.compose',$5,$6,'failed',10,10,'foreign secret',now())`, []any{uuid.New(), []byte(`{"serviceId":"` + serviceID.String() + `","stackName":"failed","deleteVolumes":false}`), "service:" + serviceID.String(), uuid.New(), []byte(`{"serviceId":"` + otherServiceID.String() + `"}`), "service:" + otherServiceID.String()}},
		{`INSERT INTO jobs(id,kind,payload,resource_key,status,max_attempts) VALUES($1,'delete.compose',$2,$3,'pending',10)`, []any{uuid.New(), []byte(`{"serviceId":"` + activeServiceID.String() + `"}`), "service:" + activeServiceID.String()}},
	}
	for _, statement := range statements {
		if _, err = db.Pool.Exec(ctx, statement.query, statement.args...); err != nil {
			t.Fatal(err)
		}
	}
	t.Cleanup(func() {
		_, _ = db.Pool.Exec(context.Background(), `DELETE FROM jobs WHERE kind='delete.compose' AND payload->>'serviceId'=ANY($1)`, []string{serviceID.String(), activeServiceID.String(), otherServiceID.String()})
		_, _ = db.Pool.Exec(context.Background(), `DELETE FROM organizations WHERE id IN ($1,$2)`, organizationID, otherOrganizationID)
		_, _ = db.Pool.Exec(context.Background(), `DELETE FROM users WHERE id IN ($1,$2,$3)`, adminID, viewerID, otherAdminID)
	})
	server := httptest.NewServer((&Server{Store: db, Logger: slog.New(slog.NewTextHandler(io.Discard, nil))}).Handler())
	t.Cleanup(server.Close)

	status, body := scopedAPIRequest(t, server.URL+"/v1/deletion-finalizers?resourceType=service&status=failed&limit=10", adminToken, organizationID, http.MethodGet, nil)
	if status != http.StatusOK || !strings.Contains(string(body), serviceID.String()) || strings.Contains(string(body), otherServiceID.String()) || strings.Contains(string(body), "raw secret") || !strings.Contains(string(body), `"retryable":true`) {
		t.Fatalf("finalizer history status=%d body=%s", status, body)
	}
	for _, endpoint := range []string{server.URL + "/v1/deletion-finalizers?resourceType=unknown", server.URL + "/v1/deletion-finalizers?status=unknown", server.URL + "/v1/deletion-finalizers?limit=201"} {
		if status, _ = scopedAPIRequest(t, endpoint, adminToken, organizationID, http.MethodGet, nil); status != http.StatusBadRequest {
			t.Fatalf("invalid query %s status=%d", endpoint, status)
		}
	}
	if status, _ = scopedAPIRequest(t, server.URL+"/v1/deletion-finalizers", viewerToken, organizationID, http.MethodGet, nil); status != http.StatusForbidden {
		t.Fatalf("viewer history status=%d", status)
	}
	if status, _ = scopedAPIRequest(t, server.URL+"/v1/deletion-finalizers/service/"+otherServiceID.String()+"/retry", adminToken, organizationID, http.MethodPost, nil); status != http.StatusNotFound {
		t.Fatalf("cross-tenant retry status=%d", status)
	}
	if status, body = scopedAPIRequest(t, server.URL+"/v1/deletion-finalizers/service/"+activeServiceID.String()+"/retry", adminToken, organizationID, http.MethodPost, nil); status != http.StatusConflict || !strings.Contains(string(body), `"code":"finalizer_in_progress"`) {
		t.Fatalf("active retry status=%d body=%s", status, body)
	}
	if status, body = scopedAPIRequest(t, server.URL+"/v1/deletion-finalizers/service/"+serviceID.String()+"/retry", adminToken, organizationID, http.MethodPost, nil); status != http.StatusAccepted || strings.Contains(string(body), "secret") || !strings.Contains(string(body), `"status":"pending"`) {
		t.Fatalf("redrive status=%d body=%s", status, body)
	}
	if status, body = scopedAPIRequest(t, server.URL+"/v1/deletion-finalizers/service/"+serviceID.String()+"/retry", adminToken, organizationID, http.MethodPost, nil); status != http.StatusConflict || !strings.Contains(string(body), `"code":"finalizer_in_progress"`) {
		t.Fatalf("duplicate retry status=%d body=%s", status, body)
	}
	if status, body = scopedAPIRequest(t, server.URL+"/v1/deletion-finalizers", otherAdminToken, otherOrganizationID, http.MethodGet, nil); status != http.StatusOK || !strings.Contains(string(body), otherServiceID.String()) || strings.Contains(string(body), serviceID.String()) {
		t.Fatalf("foreign history status=%d body=%s", status, body)
	}
}
