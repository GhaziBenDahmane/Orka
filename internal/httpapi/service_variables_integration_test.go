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

	"github.com/GhaziBenDahmane/Orka/internal/cryptox"
	"github.com/GhaziBenDahmane/Orka/internal/store"
	"github.com/google/uuid"
)

func TestServiceVariablesAreWriteOnlyEncryptedAndMutationFenced(t *testing.T) {
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
	organizationID, userID, projectID, environmentID, serviceID := uuid.New(), uuid.New(), uuid.New(), uuid.New(), uuid.New()
	token := "variables-" + uuid.NewString()
	initialPlain, _ := json.Marshal(map[string]string{"EXISTING": "preserve-this-secret", "ROTATE_ME": "old-secret"})
	initialEncrypted, err := box.Encrypt(initialPlain, composeEnvironmentContext(serviceID))
	if err != nil {
		t.Fatal(err)
	}
	for _, statement := range []struct {
		query string
		args  []any
	}{
		{`INSERT INTO organizations(id,name,slug) VALUES($1,'Variables API',$2)`, []any{organizationID, "variables-" + organizationID.String()}},
		{`INSERT INTO users(id,email,password_hash) VALUES($1,$2,'x')`, []any{userID, userID.String() + "@example.test"}},
		{`INSERT INTO memberships(organization_id,user_id,role) VALUES($1,$2,'owner')`, []any{organizationID, userID}},
		{`INSERT INTO sessions(id,user_id,token_hash,expires_at) VALUES($1,$2,$3,now()+interval '5 minutes')`, []any{uuid.New(), userID, cryptox.Digest(token)}},
		{`INSERT INTO projects(id,organization_id,name,slug) VALUES($1,$2,'Project','project')`, []any{projectID, organizationID}},
		{`INSERT INTO environments(id,project_id,name,slug) VALUES($1,$2,'Production','production')`, []any{environmentID, projectID}},
		{`INSERT INTO compose_services(id,environment_id,name,slug,stack_name,compose_yaml,encrypted_env) VALUES($1,$2,'App','app',$3,'services: {web: {image: nginx}}',$4)`, []any{serviceID, environmentID, "variables-" + serviceID.String(), initialEncrypted}},
	} {
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
	endpoint := server.URL + "/v1/services/" + serviceID.String() + "/variables"

	status, response := scopedAPIRequest(t, endpoint, token, organizationID, http.MethodGet, nil)
	if status != http.StatusOK || !bytes.Contains(response, []byte(`"name":"EXISTING"`)) || bytes.Contains(response, []byte("preserve-this-secret")) || bytes.Contains(response, []byte("old-secret")) {
		t.Fatalf("redacted list status=%d body=%s", status, response)
	}
	secretMarker := "new-secret-never-return"
	status, response = scopedAPIRequest(t, endpoint, token, organizationID, http.MethodPut, map[string]any{"values": map[string]string{"ROTATE_ME": secretMarker, "ADDED": "added-secret"}})
	if status != http.StatusOK || bytes.Contains(response, []byte(secretMarker)) || bytes.Contains(response, []byte("added-secret")) {
		t.Fatalf("variable merge status=%d leaked value body=%s", status, response)
	}
	var encrypted string
	var revision int64
	if err = db.Pool.QueryRow(ctx, `SELECT encrypted_env,revision FROM compose_services WHERE id=$1`, serviceID).Scan(&encrypted, &revision); err != nil {
		t.Fatal(err)
	}
	if encrypted == initialEncrypted || strings.Contains(encrypted, secretMarker) || revision != 2 {
		t.Fatalf("stored environment was not safely revised: revision=%d ciphertext=%q", revision, encrypted)
	}
	plain, err := box.Decrypt(encrypted, composeEnvironmentContext(serviceID))
	if err != nil {
		t.Fatal(err)
	}
	var values map[string]string
	if err = json.Unmarshal(plain, &values); err != nil || values["EXISTING"] != "preserve-this-secret" || values["ROTATE_ME"] != secretMarker || values["ADDED"] != "added-secret" {
		t.Fatalf("merged environment=%v err=%v", values, err)
	}
	status, response = scopedAPIRequest(t, server.URL+"/v1/services/"+serviceID.String(), token, organizationID, http.MethodPatch, map[string]any{"composeYaml": "services: {web: {image: nginx:stable}}"})
	if status != http.StatusOK || bytes.Contains(response, []byte(secretMarker)) {
		t.Fatalf("compose-only update status=%d body=%s", status, response)
	}
	var preservedEncrypted string
	if err = db.Pool.QueryRow(ctx, `SELECT encrypted_env,revision FROM compose_services WHERE id=$1`, serviceID).Scan(&preservedEncrypted, &revision); err != nil || preservedEncrypted != encrypted || revision != 3 {
		t.Fatalf("compose-only update did not preserve ciphertext: revision=%d preserved=%v err=%v", revision, preservedEncrypted == encrypted, err)
	}
	var auditMetadata string
	if err = db.Pool.QueryRow(ctx, `SELECT metadata::text FROM audit_events WHERE organization_id=$1 AND action='service.variables.upsert' ORDER BY created_at DESC LIMIT 1`, organizationID).Scan(&auditMetadata); err != nil || strings.Contains(auditMetadata, secretMarker) || !strings.Contains(auditMetadata, "ROTATE_ME") {
		t.Fatalf("audit metadata=%q err=%v", auditMetadata, err)
	}

	deployment, err := db.QueueDeployment(ctx, organizationID, serviceID, userID, "manual")
	if err != nil {
		t.Fatal(err)
	}
	status, response = scopedAPIRequest(t, endpoint, token, organizationID, http.MethodPut, map[string]any{"values": map[string]string{"BLOCKED": "value"}})
	if status != http.StatusConflict || !bytes.Contains(response, []byte(`"code":"deployment_active"`)) {
		t.Fatalf("active deployment mutation status=%d body=%s", status, response)
	}
	status, response = scopedAPIRequest(t, server.URL+"/v1/services/"+serviceID.String(), token, organizationID, http.MethodPatch, map[string]any{"composeYaml": "services: {web: {image: nginx:alpine}}"})
	if status != http.StatusConflict || !bytes.Contains(response, []byte(`"code":"deployment_active"`)) {
		t.Fatalf("active deployment compose update status=%d body=%s", status, response)
	}
	if err = db.CancelDeployment(ctx, organizationID, deployment.ID); err != nil {
		t.Fatal(err)
	}
	status, response = scopedAPIRequest(t, endpoint+"/ROTATE_ME", token, organizationID, http.MethodDelete, nil)
	if status != http.StatusNoContent {
		t.Fatalf("delete variable status=%d body=%s", status, response)
	}
	if err = db.Pool.QueryRow(ctx, `SELECT encrypted_env,revision FROM compose_services WHERE id=$1`, serviceID).Scan(&encrypted, &revision); err != nil {
		t.Fatal(err)
	}
	plain, err = box.Decrypt(encrypted, composeEnvironmentContext(serviceID))
	if err != nil {
		t.Fatal(err)
	}
	values = nil
	if err = json.Unmarshal(plain, &values); err != nil || values["ROTATE_ME"] != "" || values["EXISTING"] == "" || revision != 4 {
		t.Fatalf("environment after delete=%v revision=%d err=%v", values, revision, err)
	}

	if _, err = db.Pool.Exec(ctx, `UPDATE memberships SET role='viewer' WHERE organization_id=$1 AND user_id=$2`, organizationID, userID); err != nil {
		t.Fatal(err)
	}
	if status, _ = scopedAPIRequest(t, endpoint, token, organizationID, http.MethodGet, nil); status != http.StatusOK {
		t.Fatalf("viewer list status=%d", status)
	}
	if status, response = scopedAPIRequest(t, endpoint, token, organizationID, http.MethodPut, map[string]any{"values": map[string]string{"DENIED": "value"}}); status != http.StatusForbidden {
		t.Fatalf("viewer mutation status=%d body=%s", status, response)
	}
}

func TestServiceVariableValidation(t *testing.T) {
	for _, name := range []string{"", "1BAD", "WITH-DASH", "WITH.DOT", strings.Repeat("A", maxServiceVariableName+1)} {
		if err := validateServiceVariable(name, "value"); err == nil {
			t.Fatalf("validateServiceVariable(%q) accepted invalid name", name)
		}
	}
	if err := validateServiceVariable("VALID_NAME_9", ""); err != nil {
		t.Fatalf("empty values are valid rotations: %v", err)
	}
	if err := validateServiceVariable("VALID", strings.Repeat("x", maxServiceVariableValue+1)); err == nil {
		t.Fatal("oversized variable value was accepted")
	}
	tooMany := make(map[string]string, maxServiceVariables+1)
	for i := 0; i <= maxServiceVariables; i++ {
		tooMany["VARIABLE_"+strings.Repeat("A", i/26)+string(rune('A'+i%26))] = "value"
	}
	if err := validateServiceVariables(tooMany); err == nil {
		t.Fatal("too many service variables were accepted")
	}
}
