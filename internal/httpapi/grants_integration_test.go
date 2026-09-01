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
	"github.com/bendahma/dokploy-go/internal/deploy"
	"github.com/bendahma/dokploy-go/internal/store"
	"github.com/google/uuid"
)

func TestEnvironmentGrantElevatesViewerForScopedMutation(t *testing.T) {
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
	box, _ := cryptox.New(bytes.Repeat([]byte{5}, 32))
	orgID, ownerID, viewerID, projectID, environmentID := uuid.New(), uuid.New(), uuid.New(), uuid.New(), uuid.New()
	ownerToken, viewerToken := "owner-"+uuid.NewString(), "viewer-"+uuid.NewString()
	statements := []struct {
		query string
		args  []any
	}{
		{`INSERT INTO organizations(id,name,slug) VALUES($1,'Scoped API',$2)`, []any{orgID, "scoped-api-" + orgID.String()}},
		{`INSERT INTO users(id,email,password_hash) VALUES($1,$2,'x'),($3,$4,'x')`, []any{ownerID, ownerID.String() + "@example.test", viewerID, viewerID.String() + "@example.test"}},
		{`INSERT INTO memberships(organization_id,user_id,role) VALUES($1,$2,'owner'),($1,$3,'viewer')`, []any{orgID, ownerID, viewerID}},
		{`INSERT INTO sessions(id,user_id,token_hash,expires_at) VALUES($1,$2,$3,now()+interval '5 minutes'),($4,$5,$6,now()+interval '5 minutes')`, []any{uuid.New(), ownerID, cryptox.Digest(ownerToken), uuid.New(), viewerID, cryptox.Digest(viewerToken)}},
		{`INSERT INTO projects(id,organization_id,name,slug) VALUES($1,$2,'Project','project')`, []any{projectID, orgID}},
		{`INSERT INTO environments(id,project_id,name,slug) VALUES($1,$2,'Production','production')`, []any{environmentID, projectID}},
	}
	for _, statement := range statements {
		if _, err = db.Pool.Exec(ctx, statement.query, statement.args...); err != nil {
			t.Fatal(err)
		}
	}
	t.Cleanup(func() {
		_, _ = db.Pool.Exec(context.Background(), `DELETE FROM organizations WHERE id=$1`, orgID)
		_, _ = db.Pool.Exec(context.Background(), `DELETE FROM users WHERE id IN ($1,$2)`, ownerID, viewerID)
	})
	server := httptest.NewServer((&Server{Store: db, Box: box, Compiler: deploy.Compiler{PublicNetwork: "dockyard-public"}, Logger: slog.New(slog.NewTextHandler(io.Discard, nil))}).Handler())
	defer server.Close()
	roleURL := server.URL + "/v1/authorization/effective-role?resourceType=environment&resourceId=" + environmentID.String()
	if status, body := scopedAPIRequest(t, roleURL, viewerToken, orgID, http.MethodGet, nil); status != http.StatusOK || !bytes.Contains(body, []byte(`"role":"viewer"`)) {
		t.Fatalf("effective role before grant = %d: %s", status, body)
	}
	serviceBody := map[string]any{"name": "API", "slug": "api", "composeYaml": "services:\n  app:\n    image: nginx:alpine\n"}
	if status, _ := scopedAPIRequest(t, server.URL+"/v1/environments/"+environmentID.String()+"/services", viewerToken, orgID, http.MethodPost, serviceBody); status != http.StatusForbidden {
		t.Fatalf("viewer create status before grant = %d", status)
	}
	grantURL := server.URL + "/v1/environments/" + environmentID.String() + "/grants/" + viewerID.String()
	if status, body := scopedAPIRequest(t, grantURL, ownerToken, orgID, http.MethodPut, map[string]string{"role": "developer"}); status != http.StatusOK {
		t.Fatalf("grant status = %d: %s", status, body)
	}
	if status, body := scopedAPIRequest(t, roleURL, viewerToken, orgID, http.MethodGet, nil); status != http.StatusOK || !bytes.Contains(body, []byte(`"role":"developer"`)) {
		t.Fatalf("effective role after grant = %d: %s", status, body)
	}
	status, body := scopedAPIRequest(t, server.URL+"/v1/environments/"+environmentID.String()+"/services", viewerToken, orgID, http.MethodPost, serviceBody)
	if status != http.StatusCreated {
		t.Fatalf("viewer create status after grant = %d: %s", status, body)
	}
	var created store.ComposeService
	if err = json.Unmarshal(body, &created); err != nil {
		t.Fatal(err)
	}
	patch := map[string]any{"composeYaml": "services:\n  app:\n    image: nginx:stable\n", "environment": map[string]string{}}
	if status, body = scopedAPIRequest(t, server.URL+"/v1/services/"+created.ID.String(), viewerToken, orgID, http.MethodPatch, patch); status != http.StatusOK {
		t.Fatalf("viewer service update with inherited grant = %d: %s", status, body)
	}
	if status, body = scopedAPIRequest(t, grantURL, ownerToken, orgID, http.MethodDelete, nil); status != http.StatusNoContent {
		t.Fatalf("delete grant status = %d: %s", status, body)
	}
	if status, _ := scopedAPIRequest(t, server.URL+"/v1/authorization/effective-role?resourceType=invalid&resourceId="+environmentID.String(), viewerToken, orgID, http.MethodGet, nil); status != http.StatusBadRequest {
		t.Fatalf("invalid resource type status = %d", status)
	}
	if status, _ = scopedAPIRequest(t, server.URL+"/v1/services/"+created.ID.String(), viewerToken, orgID, http.MethodPatch, patch); status != http.StatusForbidden {
		t.Fatalf("viewer update status after grant removal = %d", status)
	}
}

func TestResourceMiddlewareFencesMutationAfterGrantRevocation(t *testing.T) {
	databaseURL := os.Getenv("DOCKYARD_TEST_DATABASE_URL")
	if databaseURL == "" {
		t.Skip("DOCKYARD_TEST_DATABASE_URL is not set")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	db, err := store.Open(ctx, databaseURL)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(db.Pool.Close)
	box, err := cryptox.New(bytes.Repeat([]byte{6}, 32))
	if err != nil {
		t.Fatal(err)
	}
	organizationID, userID, projectID, environmentID, serviceID := uuid.New(), uuid.New(), uuid.New(), uuid.New(), uuid.New()
	token := "scoped-race-" + uuid.NewString()
	for _, statement := range []struct {
		query string
		args  []any
	}{
		{`INSERT INTO organizations(id,name,slug) VALUES($1,'Scoped race',$2)`, []any{organizationID, "scoped-race-" + organizationID.String()}},
		{`INSERT INTO users(id,email,password_hash) VALUES($1,$2,'!test')`, []any{userID, userID.String() + "@example.test"}},
		{`INSERT INTO memberships(organization_id,user_id,role) VALUES($1,$2,'viewer')`, []any{organizationID, userID}},
		{`INSERT INTO sessions(id,user_id,token_hash,expires_at,auth_method) VALUES($1,$2,$3,now()+interval '1 hour','local')`, []any{uuid.New(), userID, cryptox.Digest(token)}},
		{`INSERT INTO projects(id,organization_id,name,slug) VALUES($1,$2,'Project','project')`, []any{projectID, organizationID}},
		{`INSERT INTO environments(id,project_id,name,slug) VALUES($1,$2,'Environment','environment')`, []any{environmentID, projectID}},
		{`INSERT INTO compose_services(id,environment_id,name,slug,stack_name,compose_yaml) VALUES($1,$2,'Service','service',$3,'services: {}')`, []any{serviceID, environmentID, "scoped-race-" + serviceID.String()}},
		{`INSERT INTO environment_grants(environment_id,user_id,role) VALUES($1,$2,'developer')`, []any{environmentID, userID}},
	} {
		if _, err = db.Pool.Exec(ctx, statement.query, statement.args...); err != nil {
			t.Fatal(err)
		}
	}
	t.Cleanup(func() {
		_, _ = db.Pool.Exec(context.Background(), `DELETE FROM organizations WHERE id=$1`, organizationID)
		_, _ = db.Pool.Exec(context.Background(), `DELETE FROM users WHERE id=$1`, userID)
	})

	blocker, err := db.Pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer blocker.Rollback(context.Background())
	var lockedServiceID uuid.UUID
	if err = blocker.QueryRow(ctx, `SELECT id FROM compose_services WHERE id=$1 FOR UPDATE`, serviceID).Scan(&lockedServiceID); err != nil {
		t.Fatal(err)
	}

	server := httptest.NewServer((&Server{Store: db, Box: box, Compiler: deploy.Compiler{PublicNetwork: "dockyard-public"}, Logger: slog.New(slog.NewTextHandler(io.Discard, nil))}).Handler())
	defer server.Close()
	type response struct {
		status int
		body   []byte
		err    error
	}
	result := make(chan response, 1)
	go func() {
		payload, _ := json.Marshal(map[string]any{"composeYaml": "services:\n  app:\n    image: nginx:stable\n"})
		request, requestErr := http.NewRequest(http.MethodPatch, server.URL+"/v1/services/"+serviceID.String(), bytes.NewReader(payload))
		if requestErr != nil {
			result <- response{err: requestErr}
			return
		}
		request.Header.Set("Authorization", "Bearer "+token)
		request.Header.Set("X-Organization-ID", organizationID.String())
		request.Header.Set("Content-Type", "application/json")
		httpResponse, requestErr := http.DefaultClient.Do(request)
		if requestErr != nil {
			result <- response{err: requestErr}
			return
		}
		defer httpResponse.Body.Close()
		body, readErr := io.ReadAll(httpResponse.Body)
		result <- response{status: httpResponse.StatusCode, body: body, err: readErr}
	}()
	waitForBlockedScopedHTTPMutation(t, ctx, db)
	if _, err = db.Pool.Exec(ctx, `DELETE FROM environment_grants WHERE environment_id=$1 AND user_id=$2`, environmentID, userID); err != nil {
		t.Fatal(err)
	}
	if err = blocker.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	select {
	case got := <-result:
		if got.err != nil || got.status != http.StatusForbidden || !bytes.Contains(got.body, []byte(`"code":"forbidden"`)) {
			t.Fatalf("stale scoped request response=(%d,%s) err=%v", got.status, got.body, got.err)
		}
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	var compose string
	var revision int64
	if err = db.Pool.QueryRow(ctx, `SELECT compose_yaml,revision FROM compose_services WHERE id=$1`, serviceID).Scan(&compose, &revision); err != nil || compose != "services: {}" || revision != 1 {
		t.Fatalf("stale scoped request changed service: compose=%q revision=%d err=%v", compose, revision, err)
	}
}

func waitForBlockedScopedHTTPMutation(t *testing.T, ctx context.Context, db *store.Store) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		var blocked bool
		err := db.Pool.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE datname=current_database() AND pid<>pg_backend_pid() AND wait_event_type='Lock' AND query LIKE '%SELECT project.id,environment.id FROM compose_services service%FOR UPDATE OF service%')`).Scan(&blocked)
		if err != nil {
			t.Fatal(err)
		}
		if blocked {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("scoped HTTP mutation did not block behind the service lock")
}

func scopedAPIRequest(t *testing.T, endpoint, token string, orgID uuid.UUID, method string, body any) (int, []byte) {
	t.Helper()
	var payload []byte
	if body != nil {
		payload, _ = json.Marshal(body)
	}
	req, _ := http.NewRequest(method, endpoint, bytes.NewReader(payload))
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("X-Organization-ID", orgID.String())
	req.Header.Set("Content-Type", "application/json")
	response, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	data, _ := io.ReadAll(response.Body)
	return response.StatusCode, data
}
