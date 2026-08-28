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

func TestApplicationBuildSettingsAreEncryptedAndRedacted(t *testing.T) {
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
	box, err := cryptox.New(bytes.Repeat([]byte{13}, 32))
	if err != nil {
		t.Fatal(err)
	}

	organizationID, userID, projectID, environmentID, serviceID := uuid.New(), uuid.New(), uuid.New(), uuid.New(), uuid.New()
	token := "build-settings-" + uuid.NewString()
	statements := []struct {
		query string
		args  []any
	}{
		{`INSERT INTO organizations(id,name,slug) VALUES($1,'Build settings',$2)`, []any{organizationID, "build-settings-" + organizationID.String()}},
		{`INSERT INTO users(id,email,password_hash) VALUES($1,$2,'!test')`, []any{userID, userID.String() + "@example.test"}},
		{`INSERT INTO memberships(organization_id,user_id,role) VALUES($1,$2,'owner')`, []any{organizationID, userID}},
		{`INSERT INTO sessions(id,user_id,token_hash,expires_at) VALUES($1,$2,$3,now()+interval '5 minutes')`, []any{uuid.New(), userID, cryptox.Digest(token)}},
		{`INSERT INTO projects(id,organization_id,name,slug) VALUES($1,$2,'Project','project')`, []any{projectID, organizationID}},
		{`INSERT INTO environments(id,project_id,name,slug) VALUES($1,$2,'Production','production')`, []any{environmentID, projectID}},
		{`INSERT INTO compose_services(id,environment_id,name,slug,stack_name,compose_yaml) VALUES($1,$2,'API','api',$3,'services: {api: {image: placeholder}}')`, []any{serviceID, environmentID, "build-settings-" + serviceID.String()}},
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

	server := httptest.NewServer((&Server{Store: db, Box: box, Logger: slog.New(slog.NewTextHandler(io.Discard, nil))}).Handler())
	defer server.Close()
	body := []byte(`{"repositoryUrl":"https://github.com/acme/api.git","gitRef":"main","contextDirectory":".","dockerfile":"Dockerfile","buildTarget":"runtime","enableSubmodules":true,"buildArguments":{"GO_VERSION":"1.26"},"buildSecrets":{"NPM_TOKEN":"never-return-this"},"targetService":"api","registryImage":"ghcr.io/acme/api"}`)
	req, _ := http.NewRequest(http.MethodPut, server.URL+"/v1/services/"+serviceID.String()+"/source", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("X-Organization-ID", organizationID.String())
	req.Header.Set("Content-Type", "application/json")
	response, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	data, _ := io.ReadAll(response.Body)
	response.Body.Close()
	if response.StatusCode != http.StatusOK {
		t.Fatalf("status=%d: %s", response.StatusCode, data)
	}
	if bytes.Contains(data, []byte("never-return-this")) || bytes.Contains(data, []byte(`"GO_VERSION":"1.26"`)) || !bytes.Contains(data, []byte(`"hasBuildArguments":true`)) || !bytes.Contains(data, []byte(`"hasBuildSecrets":true`)) {
		t.Fatalf("source response leaked settings or omitted flags: %s", data)
	}

	var target, encrypted string
	var submodules bool
	if err = db.Pool.QueryRow(ctx, `SELECT build_target,enable_submodules,encrypted_build_config FROM application_sources WHERE compose_service_id=$1`, serviceID).Scan(&target, &submodules, &encrypted); err != nil {
		t.Fatal(err)
	}
	if target != "runtime" || !submodules || encrypted == "" || strings.Contains(encrypted, "never-return-this") {
		t.Fatalf("stored target=%q submodules=%t encrypted=%q", target, submodules, encrypted)
	}
	plain, err := box.Decrypt(encrypted, "application-build-config:"+serviceID.String())
	if err != nil {
		t.Fatal(err)
	}
	var config store.ApplicationBuildConfig
	if err = json.Unmarshal(plain, &config); err != nil {
		t.Fatal(err)
	}
	if config.Arguments["GO_VERSION"] != "1.26" || config.Secrets["NPM_TOKEN"] != "never-return-this" {
		t.Fatalf("decrypted build config=%#v", config)
	}

	detailRequest, _ := http.NewRequest(http.MethodGet, server.URL+"/v1/services/"+serviceID.String(), nil)
	detailRequest.Header.Set("Authorization", "Bearer "+token)
	detailRequest.Header.Set("X-Organization-ID", organizationID.String())
	detailResponse, err := http.DefaultClient.Do(detailRequest)
	if err != nil {
		t.Fatal(err)
	}
	detailData, _ := io.ReadAll(detailResponse.Body)
	detailResponse.Body.Close()
	if detailResponse.StatusCode != http.StatusOK || bytes.Contains(detailData, []byte("never-return-this")) || bytes.Contains(detailData, []byte(`"GO_VERSION":"1.26"`)) || !bytes.Contains(detailData, []byte(`"hasBuildSecrets":true`)) {
		t.Fatalf("service detail did not safely report build settings: status=%d body=%s", detailResponse.StatusCode, detailData)
	}

	// Omitting the two maps updates non-secret source fields without silently
	// clearing existing encrypted build arguments or secrets.
	updateBody := []byte(`{"repositoryUrl":"https://github.com/acme/api.git","gitRef":"release","contextDirectory":".","dockerfile":"Dockerfile","buildTarget":"runtime","enableSubmodules":true,"targetService":"api","registryImage":"ghcr.io/acme/api"}`)
	updateRequest, _ := http.NewRequest(http.MethodPut, server.URL+"/v1/services/"+serviceID.String()+"/source", bytes.NewReader(updateBody))
	updateRequest.Header.Set("Authorization", "Bearer "+token)
	updateRequest.Header.Set("X-Organization-ID", organizationID.String())
	updateRequest.Header.Set("Content-Type", "application/json")
	updateResponse, err := http.DefaultClient.Do(updateRequest)
	if err != nil {
		t.Fatal(err)
	}
	updateData, _ := io.ReadAll(updateResponse.Body)
	updateResponse.Body.Close()
	if updateResponse.StatusCode != http.StatusOK || !bytes.Contains(updateData, []byte(`"hasBuildArguments":true`)) || !bytes.Contains(updateData, []byte(`"hasBuildSecrets":true`)) {
		t.Fatalf("source update did not preserve hidden build config: status=%d body=%s", updateResponse.StatusCode, updateData)
	}
	var preserved string
	if err = db.Pool.QueryRow(ctx, `SELECT encrypted_build_config FROM application_sources WHERE compose_service_id=$1`, serviceID).Scan(&preserved); err != nil {
		t.Fatal(err)
	}
	preservedPlain, err := box.Decrypt(preserved, "application-build-config:"+serviceID.String())
	if err != nil || !bytes.Contains(preservedPlain, []byte("never-return-this")) || !bytes.Contains(preservedPlain, []byte("GO_VERSION")) {
		t.Fatalf("build config was not preserved when omitted: %s err=%v", preservedPlain, err)
	}

	clearBody := []byte(`{"repositoryUrl":"https://github.com/acme/api.git","gitRef":"release","contextDirectory":".","dockerfile":"Dockerfile","buildTarget":"runtime","enableSubmodules":true,"buildArguments":{},"buildSecrets":{},"targetService":"api","registryImage":"ghcr.io/acme/api"}`)
	clearRequest, _ := http.NewRequest(http.MethodPut, server.URL+"/v1/services/"+serviceID.String()+"/source", bytes.NewReader(clearBody))
	clearRequest.Header.Set("Authorization", "Bearer "+token)
	clearRequest.Header.Set("X-Organization-ID", organizationID.String())
	clearRequest.Header.Set("Content-Type", "application/json")
	clearResponse, err := http.DefaultClient.Do(clearRequest)
	if err != nil {
		t.Fatal(err)
	}
	clearData, _ := io.ReadAll(clearResponse.Body)
	clearResponse.Body.Close()
	if clearResponse.StatusCode != http.StatusOK || bytes.Contains(clearData, []byte(`"hasBuildArguments":true`)) || bytes.Contains(clearData, []byte(`"hasBuildSecrets":true`)) {
		t.Fatalf("source update did not clear explicit empty build config: status=%d body=%s", clearResponse.StatusCode, clearData)
	}
	if err = db.Pool.QueryRow(ctx, `SELECT encrypted_build_config FROM application_sources WHERE compose_service_id=$1`, serviceID).Scan(&preserved); err != nil || preserved != "" {
		t.Fatalf("build config was not cleared: ciphertext=%q err=%v", preserved, err)
	}

	staticBody := []byte(`{"repositoryUrl":"https://github.com/acme/api.git","gitRef":"release","contextDirectory":".","dockerfile":"Dockerfile","buildType":"static","outputDirectory":"dist","buildArguments":{},"buildSecrets":{},"targetService":"api","registryImage":"ghcr.io/acme/api"}`)
	staticRequest, _ := http.NewRequest(http.MethodPut, server.URL+"/v1/services/"+serviceID.String()+"/source", bytes.NewReader(staticBody))
	staticRequest.Header.Set("Authorization", "Bearer "+token)
	staticRequest.Header.Set("X-Organization-ID", organizationID.String())
	staticRequest.Header.Set("Content-Type", "application/json")
	staticResponse, err := http.DefaultClient.Do(staticRequest)
	if err != nil {
		t.Fatal(err)
	}
	staticData, _ := io.ReadAll(staticResponse.Body)
	staticResponse.Body.Close()
	if staticResponse.StatusCode != http.StatusOK || !bytes.Contains(staticData, []byte(`"buildType":"static"`)) || !bytes.Contains(staticData, []byte(`"outputDirectory":"dist"`)) {
		t.Fatalf("static source update failed: status=%d body=%s", staticResponse.StatusCode, staticData)
	}
}
