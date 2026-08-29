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
	"github.com/bendahma/dokploy-go/internal/deploy"
	"github.com/bendahma/dokploy-go/internal/store"
	"github.com/google/uuid"
)

func TestTemplateVariablesAreDescribedOverriddenAndTenantScoped(t *testing.T) {
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
	box, err := cryptox.New(bytes.Repeat([]byte{19}, 32))
	if err != nil {
		t.Fatal(err)
	}

	orgID, otherOrgID := uuid.New(), uuid.New()
	viewerID, otherOwnerID := uuid.New(), uuid.New()
	projectID, otherProjectID := uuid.New(), uuid.New()
	environmentID, otherEnvironmentID := uuid.New(), uuid.New()
	viewerToken, otherToken := "template-viewer-"+uuid.NewString(), "template-other-"+uuid.NewString()
	statements := []struct {
		query string
		args  []any
	}{
		{`INSERT INTO organizations(id,name,slug) VALUES($1,'Template Tenant',$2),($3,'Other Tenant',$4)`, []any{orgID, "template-" + orgID.String(), otherOrgID, "template-" + otherOrgID.String()}},
		{`INSERT INTO users(id,email,password_hash) VALUES($1,$2,'x'),($3,$4,'x')`, []any{viewerID, viewerID.String() + "@example.test", otherOwnerID, otherOwnerID.String() + "@example.test"}},
		{`INSERT INTO memberships(organization_id,user_id,role) VALUES($1,$2,'viewer'),($3,$4,'owner')`, []any{orgID, viewerID, otherOrgID, otherOwnerID}},
		{`INSERT INTO sessions(id,user_id,token_hash,expires_at) VALUES($1,$2,$3,now()+interval '5 minutes'),($4,$5,$6,now()+interval '5 minutes')`, []any{uuid.New(), viewerID, cryptox.Digest(viewerToken), uuid.New(), otherOwnerID, cryptox.Digest(otherToken)}},
		{`INSERT INTO projects(id,organization_id,name,slug) VALUES($1,$2,'Project','project'),($3,$4,'Other','other')`, []any{projectID, orgID, otherProjectID, otherOrgID}},
		{`INSERT INTO environments(id,project_id,name,slug) VALUES($1,$2,'Production','production'),($3,$4,'Production','production')`, []any{environmentID, projectID, otherEnvironmentID, otherProjectID}},
		{`INSERT INTO environment_grants(environment_id,user_id,role) VALUES($1,$2,'developer')`, []any{environmentID, viewerID}},
	}
	for _, statement := range statements {
		if _, err = db.Pool.Exec(ctx, statement.query, statement.args...); err != nil {
			t.Fatal(err)
		}
	}
	t.Cleanup(func() {
		_, _ = db.Pool.Exec(context.Background(), `DELETE FROM organizations WHERE id IN ($1,$2)`, orgID, otherOrgID)
		_, _ = db.Pool.Exec(context.Background(), `DELETE FROM users WHERE id IN ($1,$2)`, viewerID, otherOwnerID)
	})

	templateTOML := `[variables]
admin_email = "admin@example.test"
api_token = "catalog-secret-must-not-leak"
hostname = "${domain}"
password = "${password:24}"

[config]
env = ["ADMIN_EMAIL=${admin_email}", "API_TOKEN=${api_token}", "PASSWORD=${password}"]

[[config.domains]]
serviceName = "app"
port = 8080
host = "${hostname}"
path = "/"
`
	config, _ := json.Marshal(map[string]string{"templateToml": templateTOML})
	orgTemplate, err := db.CreateTemplate(ctx, store.Template{OrganizationID: &orgID, Key: "variable-test", Version: "1", Name: "Variable Test", ComposeYAML: "services:\n  app:\n    image: nginx:alpine\n", Config: config, Source: "dokploy", Checksum: strings.Repeat("a", 64)})
	if err != nil {
		t.Fatal(err)
	}

	server := httptest.NewServer((&Server{Store: db, Box: box, Compiler: deploy.Compiler{PublicNetwork: "dockyard-public"}, Logger: slog.New(slog.NewTextHandler(io.Discard, nil))}).Handler())
	defer server.Close()
	status, body := scopedAPIRequest(t, server.URL+"/v1/templates", viewerToken, orgID, http.MethodGet, nil)
	if status != http.StatusOK {
		t.Fatalf("list status = %d: %s", status, body)
	}
	text := string(body)
	if strings.Contains(text, "catalog-secret-must-not-leak") || strings.Contains(text, "${password:24}") {
		t.Fatalf("template listing leaked secret material: %s", body)
	}
	if !strings.Contains(text, `"name":"admin_email","default":"admin@example.test"`) || !strings.Contains(text, `"name":"password","generated":true,"sensitive":true`) {
		t.Fatalf("template variable descriptors missing: %s", body)
	}

	instantiateBody := map[string]any{
		"environmentId": environmentID,
		"name":          "Customized App",
		"baseDomain":    "example.test",
		"variables": map[string]string{
			"admin_email": "operator@example.test",
			"api_token":   "operator-token",
			"hostname":    "custom.example.test",
			"password":    "operator-password",
		},
	}
	status, body = scopedAPIRequest(t, server.URL+"/v1/templates/"+orgTemplate.ID.String()+"/instantiate", viewerToken, orgID, http.MethodPost, instantiateBody)
	if status != http.StatusCreated {
		t.Fatalf("instantiate status = %d: %s", status, body)
	}
	if bytes.Contains(body, []byte("operator-password")) || bytes.Contains(body, []byte("operator-token")) {
		t.Fatalf("instantiate response leaked overrides: %s", body)
	}
	var created struct {
		Service store.ComposeService `json:"service"`
	}
	if err = json.Unmarshal(body, &created); err != nil {
		t.Fatal(err)
	}
	var encryptedEnvironment string
	if err = db.Pool.QueryRow(ctx, `SELECT encrypted_env FROM compose_services WHERE id=$1`, created.Service.ID).Scan(&encryptedEnvironment); err != nil {
		t.Fatal(err)
	}
	plain, err := box.Decrypt(encryptedEnvironment, "compose-env")
	if err != nil {
		t.Fatal(err)
	}
	var environment map[string]string
	if err = json.Unmarshal(plain, &environment); err != nil {
		t.Fatal(err)
	}
	if environment["ADMIN_EMAIL"] != "operator@example.test" || environment["API_TOKEN"] != "operator-token" || environment["PASSWORD"] != "operator-password" {
		t.Fatalf("stored environment did not use overrides: %#v", environment)
	}
	var routeHost string
	if err = db.Pool.QueryRow(ctx, `SELECT host FROM routes WHERE compose_service_id=$1`, created.Service.ID).Scan(&routeHost); err != nil || routeHost != "custom.example.test" {
		t.Fatalf("route host = %q, err = %v", routeHost, err)
	}

	status, _ = scopedAPIRequest(t, server.URL+"/v1/templates/"+orgTemplate.ID.String()+"/instantiate", viewerToken, orgID, http.MethodPost, map[string]any{"environmentId": environmentID, "name": "Rejected", "variables": map[string]string{"undeclared": "value"}})
	if status != http.StatusBadRequest {
		t.Fatalf("unknown override status = %d", status)
	}
	status, body = scopedAPIRequest(t, server.URL+"/v1/templates/"+orgTemplate.ID.String()+"/instantiate", otherToken, otherOrgID, http.MethodPost, map[string]any{"environmentId": otherEnvironmentID, "name": "Cross Tenant"})
	if status != http.StatusNotFound {
		t.Fatalf("cross-tenant instantiate status = %d: %s", status, body)
	}
	status, body = scopedAPIRequest(t, server.URL+"/v1/templates", otherToken, otherOrgID, http.MethodGet, nil)
	if status != http.StatusOK || bytes.Contains(body, []byte("variable-test")) {
		t.Fatalf("cross-tenant list status = %d: %s", status, body)
	}
}
