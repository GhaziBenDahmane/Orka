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

[[config.mounts]]
filePath = "/app/config.env"
content = "API_TOKEN=${api_token} PASSWORD=${password}"
`
	config, _ := json.Marshal(map[string]string{"templateToml": templateTOML})
	templateCompose := "services:\n  app:\n    image: nginx:alpine\n    volumes:\n      - ../files/app/config.env:/run/config.env:ro\n"
	orgTemplate, err := db.CreateTemplate(ctx, store.Template{OrganizationID: &orgID, Key: "variable-test", Version: "1", Name: "Variable Test", ComposeYAML: templateCompose, Config: config, Source: "dokploy", Checksum: strings.Repeat("a", 64)})
	if err != nil {
		t.Fatal(err)
	}
	restrictedConfig, _ := json.Marshal(map[string]string{"templateToml": "[variables]\n", "safetyClass": "requires_unsafe", "safetyReason": "service requests privileged mode"})
	restrictedTemplate, err := db.CreateTemplate(ctx, store.Template{OrganizationID: &orgID, Key: "restricted-test", Version: "1", Name: "Restricted Test", ComposeYAML: "services:\n  app:\n    image: example:1\n    privileged: true\n", Config: restrictedConfig, Source: "dokploy", Checksum: strings.Repeat("d", 64)})
	if err != nil {
		t.Fatal(err)
	}

	server := httptest.NewServer((&Server{Store: db, Box: box, Compiler: deploy.Compiler{PublicNetwork: "dockyard-public"}, Logger: slog.New(slog.NewTextHandler(io.Discard, nil))}).Handler())
	defer server.Close()
	status := 0
	var body []byte
	var catalog strings.Builder
	cursor := ""
	for page := 0; page < 100; page++ {
		endpoint := server.URL + "/v1/templates?limit=200"
		if cursor != "" {
			endpoint += "&cursor=" + cursor
		}
		status, body = scopedAPIRequest(t, endpoint, viewerToken, orgID, http.MethodGet, nil)
		var response struct {
			Items      []json.RawMessage `json:"items"`
			NextCursor string            `json:"nextCursor"`
		}
		if status != http.StatusOK || json.Unmarshal(body, &response) != nil {
			t.Fatalf("list status = %d: %s", status, body)
		}
		for _, item := range response.Items {
			catalog.Write(item)
		}
		cursor = response.NextCursor
		if cursor == "" {
			break
		}
	}
	if cursor != "" {
		t.Fatal("template catalog did not terminate within 100 pages")
	}
	text := catalog.String()
	if strings.Contains(text, "catalog-secret-must-not-leak") || strings.Contains(text, "${password:24}") {
		t.Fatalf("template listing leaked secret material: %s", body)
	}
	if !strings.Contains(text, `"name":"admin_email","default":"admin@example.test"`) || !strings.Contains(text, `"name":"password","generated":true,"sensitive":true`) {
		t.Fatalf("template variable descriptors missing: %s", body)
	}
	if !strings.Contains(text, `"safetyClass":"safe","deployable":true`) {
		t.Fatalf("legacy safe template classification missing: %s", body)
	}
	if !strings.Contains(text, `"key":"restricted-test"`) || !strings.Contains(text, `"safetyClass":"requires_unsafe","safetyReason":"service requests privileged mode","deployable":false`) {
		t.Fatalf("restricted template classification missing: %s", body)
	}
	status, body = scopedAPIRequest(t, server.URL+"/v1/templates?limit=1", viewerToken, orgID, http.MethodGet, nil)
	var firstPage struct {
		Items      []store.Template `json:"items"`
		NextCursor string           `json:"nextCursor"`
	}
	if status != http.StatusOK || json.Unmarshal(body, &firstPage) != nil || len(firstPage.Items) != 1 || firstPage.NextCursor == "" {
		t.Fatalf("first template page status = %d: %s", status, body)
	}
	status, body = scopedAPIRequest(t, server.URL+"/v1/templates?limit=1&cursor="+firstPage.NextCursor, viewerToken, orgID, http.MethodGet, nil)
	var secondPage struct {
		Items []store.Template `json:"items"`
	}
	if status != http.StatusOK || json.Unmarshal(body, &secondPage) != nil || len(secondPage.Items) != 1 || secondPage.Items[0].ID == firstPage.Items[0].ID {
		t.Fatalf("second template page status = %d: %s", status, body)
	}
	status, _ = scopedAPIRequest(t, server.URL+"/v1/templates?limit=201", viewerToken, orgID, http.MethodGet, nil)
	if status != http.StatusBadRequest {
		t.Fatalf("oversized template page status = %d", status)
	}
	status, _ = scopedAPIRequest(t, server.URL+"/v1/templates?cursor=not-a-cursor", viewerToken, orgID, http.MethodGet, nil)
	if status != http.StatusBadRequest {
		t.Fatalf("invalid template cursor status = %d", status)
	}
	status, body = scopedAPIRequest(t, server.URL+"/v1/templates/"+restrictedTemplate.ID.String()+"/preview", viewerToken, orgID, http.MethodPost, map[string]any{})
	if status != http.StatusBadRequest || !bytes.Contains(body, []byte("privileged")) {
		t.Fatalf("restricted template preview status = %d: %s", status, body)
	}
	previewVariables := map[string]string{
		"admin_email": "operator@example.test",
		"api_token":   "operator-token",
		"hostname":    "custom.example.test",
		"password":    "operator-password",
	}
	status, body = scopedAPIRequest(t, server.URL+"/v1/templates/"+orgTemplate.ID.String()+"/preview", viewerToken, orgID, http.MethodPost, map[string]any{"baseDomain": "example.test", "variables": previewVariables})
	if status != http.StatusOK || !bytes.Contains(body, []byte(`"name":"app","image":"nginx:alpine"`)) || !bytes.Contains(body, []byte(`"host":"custom.example.test"`)) || !bytes.Contains(body, []byte(`"environmentKeys":["ADMIN_EMAIL","API_TOKEN","PASSWORD"]`)) {
		t.Fatalf("template preview status = %d: %s", status, body)
	}
	if bytes.Contains(body, []byte("operator-password")) || bytes.Contains(body, []byte("operator-token")) || bytes.Contains(body, []byte("operator@example.test")) {
		t.Fatalf("template preview leaked variable values: %s", body)
	}
	unsafePreviewVariables := map[string]string{}
	for key, value := range previewVariables {
		unsafePreviewVariables[key] = value
	}
	unsafePreviewVariables["hostname"] = "app.example.test`) || Host(`attacker.example.test"
	status, body = scopedAPIRequest(t, server.URL+"/v1/templates/"+orgTemplate.ID.String()+"/preview", viewerToken, orgID, http.MethodPost, map[string]any{"variables": unsafePreviewVariables})
	if status != http.StatusBadRequest || !bytes.Contains(body, []byte("invalid_template")) {
		t.Fatalf("unsafe template route preview status = %d: %s", status, body)
	}

	instantiateBody := map[string]any{
		"environmentId": environmentID,
		"name":          "Customized App",
		"baseDomain":    "example.test",
		"variables":     previewVariables,
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
	if strings.Contains(created.Service.ComposeYAML, "operator-token") || strings.Contains(created.Service.ComposeYAML, "operator-password") || !strings.Contains(created.Service.ComposeYAML, "x-dockyard-files") || !strings.Contains(created.Service.ComposeYAML, deploy.InlineFileReferencePrefix+deploy.InlineFileEnvironmentPrefix) {
		t.Fatalf("stored Compose did not use an opaque managed-file reference: %s", created.Service.ComposeYAML)
	}
	var encryptedEnvironment string
	if err = db.Pool.QueryRow(ctx, `SELECT encrypted_env FROM compose_services WHERE id=$1`, created.Service.ID).Scan(&encryptedEnvironment); err != nil {
		t.Fatal(err)
	}
	plain, err := box.Decrypt(encryptedEnvironment, cryptox.ResourceContext("compose-env", created.Service.ID.String()))
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
	managedFileFound := false
	for key, value := range environment {
		if strings.HasPrefix(key, deploy.InlineFileEnvironmentPrefix) {
			managedFileFound = value == "API_TOKEN=operator-token PASSWORD=operator-password"
		}
	}
	if !managedFileFound {
		t.Fatalf("managed file content was not stored in the encrypted environment: %#v", environment)
	}
	var templateKey, templateVersion, templateChecksum, encryptedVariables string
	if err = db.Pool.QueryRow(ctx, `SELECT template_key,template_version,template_checksum,encrypted_variables FROM template_instances WHERE compose_service_id=$1`, created.Service.ID).Scan(&templateKey, &templateVersion, &templateChecksum, &encryptedVariables); err != nil {
		t.Fatal(err)
	}
	if templateKey != orgTemplate.Key || templateVersion != orgTemplate.Version || templateChecksum != orgTemplate.Checksum {
		t.Fatalf("template provenance = %q/%q/%q", templateKey, templateVersion, templateChecksum)
	}
	plainVariables, err := box.Decrypt(encryptedVariables, cryptox.ResourceContext("template-variables", created.Service.ID.String()))
	if err != nil || !bytes.Contains(plainVariables, []byte(`"password":"operator-password"`)) {
		t.Fatalf("encrypted template variables are unavailable: %s, %v", plainVariables, err)
	}
	if _, err = box.Decrypt(encryptedVariables, cryptox.ResourceContext("template-variables", uuid.NewString())); err == nil {
		t.Fatal("template variables were accepted for another service")
	}
	var routeHost string
	if err = db.Pool.QueryRow(ctx, `SELECT host FROM routes WHERE compose_service_id=$1`, created.Service.ID).Scan(&routeHost); err != nil || routeHost != "custom.example.test" {
		t.Fatalf("route host = %q, err = %v", routeHost, err)
	}
	checkedAt := time.Date(2026, time.August, 29, 14, 30, 0, 0, time.UTC)
	repairedAt := checkedAt.Add(-5 * time.Minute)
	if _, err = db.Pool.Exec(ctx, `INSERT INTO service_reconciliations(compose_service_id,state,consecutive_failures,detail,last_checked_at,last_repair_at)
		VALUES($1,'degraded',2,'replica shortfall',$2,$3)`, created.Service.ID, checkedAt, repairedAt); err != nil {
		t.Fatal(err)
	}
	status, detailBody := scopedAPIRequest(t, server.URL+"/v1/services/"+created.Service.ID.String(), viewerToken, orgID, http.MethodGet, nil)
	if status != http.StatusOK || !bytes.Contains(detailBody, []byte(`"templateKey":"variable-test"`)) || !bytes.Contains(detailBody, []byte(`"templateVersion":"1"`)) || !bytes.Contains(detailBody, []byte(`"drifted":false`)) {
		t.Fatalf("service template provenance status = %d: %s", status, detailBody)
	}
	var detail struct {
		Reconciliation *store.ServiceReconciliation `json:"reconciliation"`
	}
	if err = json.Unmarshal(detailBody, &detail); err != nil {
		t.Fatal(err)
	}
	if detail.Reconciliation == nil || detail.Reconciliation.ComposeServiceID != created.Service.ID || detail.Reconciliation.State != "degraded" || detail.Reconciliation.ConsecutiveFailures != 2 || detail.Reconciliation.Detail != "replica shortfall" || !detail.Reconciliation.LastCheckedAt.Equal(checkedAt) || detail.Reconciliation.LastRepairAt == nil || !detail.Reconciliation.LastRepairAt.Equal(repairedAt) {
		t.Fatalf("service reconciliation = %#v", detail.Reconciliation)
	}
	if bytes.Contains(detailBody, []byte("operator-password")) || bytes.Contains(detailBody, []byte("encryptedVariables")) {
		t.Fatalf("service detail leaked template variables: %s", detailBody)
	}
	status, body = scopedAPIRequest(t, server.URL+"/v1/services/"+created.Service.ID.String(), otherToken, otherOrgID, http.MethodGet, nil)
	if status != http.StatusNotFound || bytes.Contains(body, []byte("replica shortfall")) {
		t.Fatalf("cross-tenant service reconciliation status = %d: %s", status, body)
	}
	customCompose := "services:\n  app:\n    image: nginx:stable-alpine\n"
	status, body = scopedAPIRequest(t, server.URL+"/v1/services/"+created.Service.ID.String(), viewerToken, orgID, http.MethodPatch, map[string]any{"composeYaml": customCompose})
	if status != http.StatusOK {
		t.Fatalf("customize service status = %d: %s", status, body)
	}
	var preservedEnvironment string
	if err = db.Pool.QueryRow(ctx, `SELECT encrypted_env FROM compose_services WHERE id=$1`, created.Service.ID).Scan(&preservedEnvironment); err != nil || preservedEnvironment != encryptedEnvironment {
		t.Fatalf("compose-only update did not preserve encrypted environment: %v", err)
	}
	// Simulate an instance created before managed environment ownership was
	// recorded. The first write must reconstruct ownership before marking the
	// explicitly rotated keys as operator-managed.
	if _, err = db.Pool.Exec(ctx, `UPDATE template_instances SET managed_environment_keys='{}' WHERE compose_service_id=$1`, created.Service.ID); err != nil {
		t.Fatal(err)
	}
	status, body = scopedAPIRequest(t, server.URL+"/v1/services/"+created.Service.ID.String()+"/variables", viewerToken, orgID, http.MethodPut, map[string]any{"values": map[string]string{"MANUAL_ONLY": "keep-on-upgrade", "PASSWORD": "operator-rotated-password"}})
	if status != http.StatusOK || bytes.Contains(body, []byte("operator-rotated-password")) {
		t.Fatalf("template runtime variable override status = %d: %s", status, body)
	}
	status, detailBody = scopedAPIRequest(t, server.URL+"/v1/services/"+created.Service.ID.String(), viewerToken, orgID, http.MethodGet, nil)
	if status != http.StatusOK || !bytes.Contains(detailBody, []byte(`"drifted":true`)) {
		t.Fatalf("template drift was not reported: %d: %s", status, detailBody)
	}
	upgradeTOML := strings.Replace(templateTOML, `admin_email = "admin@example.test"`, `admin_email = "new-default@example.test"
feature = "enabled"`, 1)
	upgradeTOML = strings.Replace(upgradeTOML, `"PASSWORD=${password}"`, `"PASSWORD=${password}", "FEATURE=${feature}"`, 1)
	upgradeConfig, _ := json.Marshal(map[string]string{"templateToml": upgradeTOML})
	upgradeCompose := "services:\n  app:\n    image: nginx:1.27-alpine\n    volumes:\n      - ../files/app/config.env:/run/config.env:ro\n"
	upgradeTemplate, err := db.CreateTemplate(ctx, store.Template{OrganizationID: &orgID, Key: orgTemplate.Key, Version: "2", Name: "Variable Test", ComposeYAML: upgradeCompose, Config: upgradeConfig, Source: "dokploy", Checksum: strings.Repeat("b", 64)})
	if err != nil {
		t.Fatal(err)
	}
	status, body = scopedAPIRequest(t, server.URL+"/v1/services/"+created.Service.ID.String()+"/template-versions", viewerToken, orgID, http.MethodGet, nil)
	if status != http.StatusOK || !bytes.Contains(body, []byte(upgradeTemplate.ID.String())) || bytes.Contains(body, []byte("templateToml")) {
		t.Fatalf("template versions status = %d: %s", status, body)
	}
	upgradeBody := map[string]any{"templateId": upgradeTemplate.ID, "variables": map[string]string{"admin_email": "upgraded@example.test"}}
	status, body = scopedAPIRequest(t, server.URL+"/v1/services/"+created.Service.ID.String()+"/template-upgrades", viewerToken, orgID, http.MethodPost, upgradeBody)
	if status != http.StatusConflict || !bytes.Contains(body, []byte("template_drift")) {
		t.Fatalf("drifted upgrade status = %d: %s", status, body)
	}
	upgradeBody["allowDrift"] = true
	status, body = scopedAPIRequest(t, server.URL+"/v1/services/"+created.Service.ID.String()+"/template-upgrades", viewerToken, orgID, http.MethodPost, upgradeBody)
	if status != http.StatusOK || bytes.Contains(body, []byte("operator-password")) {
		t.Fatalf("template upgrade status = %d: %s", status, body)
	}
	var upgradedEncryptedEnvironment string
	if err = db.Pool.QueryRow(ctx, `SELECT encrypted_env FROM compose_services WHERE id=$1`, created.Service.ID).Scan(&upgradedEncryptedEnvironment); err != nil {
		t.Fatal(err)
	}
	upgradedEnvironmentJSON, err := box.Decrypt(upgradedEncryptedEnvironment, cryptox.ResourceContext("compose-env", created.Service.ID.String()))
	if err != nil {
		t.Fatal(err)
	}
	var upgradedEnvironment map[string]string
	if err = json.Unmarshal(upgradedEnvironmentJSON, &upgradedEnvironment); err != nil {
		t.Fatal(err)
	}
	if upgradedEnvironment["PASSWORD"] != "operator-rotated-password" || upgradedEnvironment["MANUAL_ONLY"] != "keep-on-upgrade" || upgradedEnvironment["ADMIN_EMAIL"] != "upgraded@example.test" || upgradedEnvironment["FEATURE"] != "enabled" {
		t.Fatalf("upgraded environment = %#v", upgradedEnvironment)
	}
	var managedEnvironmentKeys []string
	if err = db.Pool.QueryRow(ctx, `SELECT managed_environment_keys FROM template_instances WHERE compose_service_id=$1`, created.Service.ID).Scan(&managedEnvironmentKeys); err != nil {
		t.Fatal(err)
	}
	for _, name := range managedEnvironmentKeys {
		if name == "PASSWORD" || name == "MANUAL_ONLY" {
			t.Fatalf("operator-owned variable remained template-managed: %v", managedEnvironmentKeys)
		}
	}
	status, detailBody = scopedAPIRequest(t, server.URL+"/v1/services/"+created.Service.ID.String(), viewerToken, orgID, http.MethodGet, nil)
	if status != http.StatusOK || !bytes.Contains(detailBody, []byte(`"templateVersion":"2"`)) || !bytes.Contains(detailBody, []byte(`"drifted":false`)) {
		t.Fatalf("upgraded provenance status = %d: %s", status, detailBody)
	}
	status, _ = scopedAPIRequest(t, server.URL+"/v1/templates/"+orgTemplate.ID.String()+"/instantiate", viewerToken, orgID, http.MethodPost, map[string]any{"environmentId": environmentID, "name": "Upgrade Route Blocker", "baseDomain": "example.test", "variables": map[string]string{"hostname": "blocked.example.test"}})
	if status != http.StatusCreated {
		t.Fatalf("route blocker instantiate status = %d", status)
	}
	rollbackCompose := strings.Replace(upgradeCompose, "nginx:1.27-alpine", "nginx:1.28-alpine", 1)
	rollbackTemplate, err := db.CreateTemplate(ctx, store.Template{OrganizationID: &orgID, Key: orgTemplate.Key, Version: "3", Name: "Variable Test", ComposeYAML: rollbackCompose, Config: upgradeConfig, Source: "dokploy", Checksum: strings.Repeat("c", 64)})
	if err != nil {
		t.Fatal(err)
	}
	var beforeRevision int64
	var beforeEnvironment, beforeRouteHost, beforeTemplateVersion string
	if err = db.Pool.QueryRow(ctx, `SELECT s.revision,s.encrypted_env,r.host,t.template_version FROM compose_services s JOIN routes r ON r.compose_service_id=s.id JOIN template_instances t ON t.compose_service_id=s.id WHERE s.id=$1`, created.Service.ID).Scan(&beforeRevision, &beforeEnvironment, &beforeRouteHost, &beforeTemplateVersion); err != nil {
		t.Fatal(err)
	}
	status, body = scopedAPIRequest(t, server.URL+"/v1/services/"+created.Service.ID.String()+"/template-upgrades", viewerToken, orgID, http.MethodPost, map[string]any{"templateId": rollbackTemplate.ID, "variables": map[string]string{"hostname": "blocked.example.test"}})
	if status != http.StatusConflict {
		t.Fatalf("upgrade route collision status = %d: %s", status, body)
	}
	var afterRevision int64
	var afterEnvironment, afterRouteHost, afterTemplateVersion string
	if err = db.Pool.QueryRow(ctx, `SELECT s.revision,s.encrypted_env,r.host,t.template_version FROM compose_services s JOIN routes r ON r.compose_service_id=s.id JOIN template_instances t ON t.compose_service_id=s.id WHERE s.id=$1`, created.Service.ID).Scan(&afterRevision, &afterEnvironment, &afterRouteHost, &afterTemplateVersion); err != nil {
		t.Fatal(err)
	}
	if afterRevision != beforeRevision || afterEnvironment != beforeEnvironment || afterRouteHost != beforeRouteHost || afterTemplateVersion != beforeTemplateVersion {
		t.Fatalf("failed upgrade was not atomic: before=(%d,%q,%q,%q) after=(%d,%q,%q,%q)", beforeRevision, beforeEnvironment, beforeRouteHost, beforeTemplateVersion, afterRevision, afterEnvironment, afterRouteHost, afterTemplateVersion)
	}
	status, body = scopedAPIRequest(t, server.URL+"/v1/services/"+created.Service.ID.String()+"/template-versions", otherToken, otherOrgID, http.MethodGet, nil)
	if status != http.StatusNotFound {
		t.Fatalf("cross-tenant template versions status = %d: %s", status, body)
	}
	status, body = scopedAPIRequest(t, server.URL+"/v1/services/"+created.Service.ID.String()+"/template-upgrades", otherToken, otherOrgID, http.MethodPost, map[string]any{"templateId": rollbackTemplate.ID})
	if status != http.StatusNotFound {
		t.Fatalf("cross-tenant template upgrade status = %d: %s", status, body)
	}
	status, body = scopedAPIRequest(t, server.URL+"/v1/templates/"+orgTemplate.ID.String()+"/preview", otherToken, otherOrgID, http.MethodPost, map[string]any{})
	if status != http.StatusNotFound {
		t.Fatalf("cross-tenant template preview status = %d: %s", status, body)
	}

	status, _ = scopedAPIRequest(t, server.URL+"/v1/templates/"+orgTemplate.ID.String()+"/instantiate", viewerToken, orgID, http.MethodPost, map[string]any{"environmentId": environmentID, "name": "Rejected", "variables": map[string]string{"undeclared": "value"}})
	if status != http.StatusBadRequest {
		t.Fatalf("unknown override status = %d", status)
	}
	collisionBody := map[string]any{"environmentId": environmentID, "name": "Collision", "variables": map[string]string{"hostname": "custom.example.test"}}
	status, _ = scopedAPIRequest(t, server.URL+"/v1/templates/"+orgTemplate.ID.String()+"/instantiate", viewerToken, orgID, http.MethodPost, collisionBody)
	if status != http.StatusConflict {
		t.Fatalf("route collision status = %d", status)
	}
	var partialServices int
	if err = db.Pool.QueryRow(ctx, `SELECT count(*) FROM compose_services WHERE environment_id=$1 AND slug='collision'`, environmentID).Scan(&partialServices); err != nil || partialServices != 0 {
		t.Fatalf("failed template left %d partial services: %v", partialServices, err)
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
