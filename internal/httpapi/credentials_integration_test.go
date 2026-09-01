package httpapi

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
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
	"golang.org/x/crypto/ssh"
)

func TestSourceCredentialIsEncryptedAndRedacted(t *testing.T) {
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
	box, err := cryptox.New(bytes.Repeat([]byte{7}, 32))
	if err != nil {
		t.Fatal(err)
	}
	orgID, userID := uuid.New(), uuid.New()
	token := "session-" + uuid.NewString()
	tx, err := db.Pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(ctx)
	_, err = tx.Exec(ctx, `INSERT INTO organizations(id,name,slug) VALUES($1,'Credential Test',$2)`, orgID, "credential-"+orgID.String())
	if err == nil {
		_, err = tx.Exec(ctx, `INSERT INTO users(id,email,password_hash) VALUES($1,$2,'!test')`, userID, userID.String()+"@example.test")
	}
	if err == nil {
		_, err = tx.Exec(ctx, `INSERT INTO memberships(organization_id,user_id,role) VALUES($1,$2,'owner')`, orgID, userID)
	}
	if err == nil {
		_, err = tx.Exec(ctx, `INSERT INTO sessions(id,user_id,token_hash,expires_at) VALUES($1,$2,$3,now()+interval '5 minutes')`, uuid.New(), userID, cryptox.Digest(token))
	}
	if err == nil {
		err = tx.Commit(ctx)
	}
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = db.Pool.Exec(context.Background(), `DELETE FROM organizations WHERE id=$1`, orgID)
		_, _ = db.Pool.Exec(context.Background(), `DELETE FROM users WHERE id=$1`, userID)
	})

	server := httptest.NewServer((&Server{Store: db, Box: box, PublicURL: "http://example.test", Logger: slog.New(slog.NewTextHandler(io.Discard, nil))}).Handler())
	defer server.Close()
	body := []byte(`{"kind":"registry","name":"ci","server":"ghcr.io","username":"robot","secret":"never-return-this"}`)
	req, _ := http.NewRequest(http.MethodPost, server.URL+"/v1/source-credentials", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("X-Organization-ID", orgID.String())
	req.Header.Set("Content-Type", "application/json")
	response, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	data, _ := io.ReadAll(response.Body)
	response.Body.Close()
	if response.StatusCode != http.StatusCreated {
		t.Fatalf("status = %d: %s", response.StatusCode, data)
	}
	if strings.Contains(string(data), "never-return-this") || strings.Contains(string(data), "encryptedSecret") {
		t.Fatalf("credential response leaked secret material: %s", data)
	}
	var item struct {
		ID uuid.UUID `json:"id"`
	}
	if err = json.Unmarshal(data, &item); err != nil {
		t.Fatal(err)
	}
	var encrypted string
	if err = db.Pool.QueryRow(ctx, `SELECT encrypted_secret FROM source_credentials WHERE id=$1`, item.ID).Scan(&encrypted); err != nil {
		t.Fatal(err)
	}
	if encrypted == "never-return-this" || encrypted == "" {
		t.Fatalf("secret was not encrypted: %q", encrypted)
	}
	plain, err := box.Decrypt(encrypted, cryptox.ResourceContext("source-credential", item.ID.String()))
	if err != nil || string(plain) != "never-return-this" {
		t.Fatalf("encrypted secret cannot be recovered: %v", err)
	}
	if _, err = box.DecryptResource(encrypted, "source-credential", uuid.NewString(), "source-credential"); err == nil {
		t.Fatal("source credential ciphertext was accepted for another credential")
	}
	originalEncrypted := encrypted
	projectID, environmentID, serviceID := uuid.New(), uuid.New(), uuid.New()
	for _, statement := range []struct {
		query string
		args  []any
	}{
		{`INSERT INTO projects(id,organization_id,name,slug) VALUES($1,$2,'Credential project','credential-project')`, []any{projectID, orgID}},
		{`INSERT INTO environments(id,project_id,name,slug) VALUES($1,$2,'Production','production')`, []any{environmentID, projectID}},
		{`INSERT INTO compose_services(id,environment_id,name,slug,stack_name,compose_yaml) VALUES($1,$2,'Application','application',$3,'services: {web: {image: example/app:1}}')`, []any{serviceID, environmentID, "credential-rotation-" + serviceID.String()}},
		{`INSERT INTO application_sources(compose_service_id,repository_url,target_service,registry_image,registry_credential_id) VALUES($1,'https://github.com/example/app','web','ghcr.io/example/app',$2)`, []any{serviceID, item.ID}},
	} {
		if _, err = db.Pool.Exec(ctx, statement.query, statement.args...); err != nil {
			t.Fatal(err)
		}
	}
	deployment, err := db.QueueDeployment(ctx, orgID, serviceID, userID, "manual")
	if err != nil {
		t.Fatal(err)
	}
	rotateBody := []byte(`{"secret":"rotated-never-return-this"}`)
	req, _ = http.NewRequest(http.MethodPut, server.URL+"/v1/source-credentials/"+item.ID.String(), bytes.NewReader(rotateBody))
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("X-Organization-ID", orgID.String())
	req.Header.Set("Content-Type", "application/json")
	response, err = http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	data, _ = io.ReadAll(response.Body)
	response.Body.Close()
	if response.StatusCode != http.StatusConflict || !bytes.Contains(data, []byte(`"code":"deployment_active"`)) || bytes.Contains(data, []byte("rotated-never-return-this")) {
		t.Fatalf("active-deployment rotation status=%d body=%s", response.StatusCode, data)
	}
	if err = db.Pool.QueryRow(ctx, `SELECT encrypted_secret FROM source_credentials WHERE id=$1`, item.ID).Scan(&encrypted); err != nil || encrypted != originalEncrypted {
		t.Fatalf("blocked rotation changed source credential: changed=%v err=%v", encrypted != originalEncrypted, err)
	}
	if err = db.CancelDeployment(ctx, orgID, deployment.ID); err != nil {
		t.Fatal(err)
	}
	req, _ = http.NewRequest(http.MethodPut, server.URL+"/v1/source-credentials/"+item.ID.String(), bytes.NewReader(rotateBody))
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("X-Organization-ID", orgID.String())
	req.Header.Set("Content-Type", "application/json")
	response, err = http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	data, _ = io.ReadAll(response.Body)
	response.Body.Close()
	if response.StatusCode != http.StatusOK || bytes.Contains(data, []byte("rotated-never-return-this")) || bytes.Contains(data, []byte("encryptedSecret")) {
		t.Fatalf("credential rotation status=%d leaked secret material: %s", response.StatusCode, data)
	}
	if err = db.Pool.QueryRow(ctx, `SELECT encrypted_secret FROM source_credentials WHERE id=$1`, item.ID).Scan(&encrypted); err != nil {
		t.Fatal(err)
	}
	plain, err = box.Decrypt(encrypted, cryptox.ResourceContext("source-credential", item.ID.String()))
	if err != nil || string(plain) != "rotated-never-return-this" || encrypted == originalEncrypted {
		t.Fatalf("rotated secret was not replaced safely: changed=%v plaintext=%q err=%v", encrypted != originalEncrypted, plain, err)
	}
	var rotationAudits int
	if err = db.Pool.QueryRow(ctx, `SELECT count(*) FROM audit_events WHERE organization_id=$1 AND actor_user_id=$2 AND action='source_credential.rotate' AND resource_id=$3`, orgID, userID, item.ID.String()).Scan(&rotationAudits); err != nil || rotationAudits != 1 {
		t.Fatalf("credential rotation audit events=%d err=%v", rotationAudits, err)
	}

	gitCredentialID := uuid.New()
	gitEncrypted, err := box.Encrypt([]byte("old-git-token"), cryptox.ResourceContext("source-credential", gitCredentialID.String()))
	if err != nil {
		t.Fatal(err)
	}
	if _, err = db.CreateSourceCredential(ctx, store.SourceCredential{ID: gitCredentialID, OrganizationID: orgID, Kind: "git", Name: "template-sync", Server: "github.com", Username: "token", EncryptedSecret: gitEncrypted}); err != nil {
		t.Fatal(err)
	}
	repository, err := db.CreateTemplateRepository(ctx, store.TemplateRepository{OrganizationID: orgID, Name: "Private templates", Slug: "private-templates", RepositoryURL: "https://github.com/example/templates", GitRef: "main", CredentialID: &gitCredentialID})
	if err != nil {
		t.Fatal(err)
	}
	runningRepository, err := db.BeginTemplateRepositorySync(ctx, orgID, repository.ID)
	if err != nil {
		t.Fatal(err)
	}
	req, _ = http.NewRequest(http.MethodDelete, server.URL+"/v1/source-credentials/"+gitCredentialID.String(), nil)
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("X-Organization-ID", orgID.String())
	response, err = http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	data, _ = io.ReadAll(response.Body)
	response.Body.Close()
	if response.StatusCode != http.StatusConflict || !bytes.Contains(data, []byte(`"code":"resource_busy"`)) {
		t.Fatalf("active-template-sync deletion status=%d body=%s", response.StatusCode, data)
	}
	if _, err = db.GetSourceCredential(ctx, orgID, gitCredentialID); err != nil {
		t.Fatalf("blocked deletion removed source credential: %v", err)
	}
	gitRotateBody := []byte(`{"secret":"new-git-token"}`)
	req, _ = http.NewRequest(http.MethodPut, server.URL+"/v1/source-credentials/"+gitCredentialID.String(), bytes.NewReader(gitRotateBody))
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("X-Organization-ID", orgID.String())
	req.Header.Set("Content-Type", "application/json")
	response, err = http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	data, _ = io.ReadAll(response.Body)
	response.Body.Close()
	if response.StatusCode != http.StatusConflict || !bytes.Contains(data, []byte(`"code":"resource_busy"`)) || bytes.Contains(data, []byte("new-git-token")) {
		t.Fatalf("active-template-sync rotation status=%d body=%s", response.StatusCode, data)
	}
	if err = db.Pool.QueryRow(ctx, `SELECT encrypted_secret FROM source_credentials WHERE id=$1`, gitCredentialID).Scan(&encrypted); err != nil || encrypted != gitEncrypted {
		t.Fatalf("blocked template credential rotation changed ciphertext: changed=%v err=%v", encrypted != gitEncrypted, err)
	}
	if err = db.FinishTemplateRepositorySync(ctx, runningRepository, "succeeded", ""); err != nil {
		t.Fatal(err)
	}
	req, _ = http.NewRequest(http.MethodPut, server.URL+"/v1/source-credentials/"+gitCredentialID.String(), bytes.NewReader(gitRotateBody))
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("X-Organization-ID", orgID.String())
	req.Header.Set("Content-Type", "application/json")
	response, err = http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	data, _ = io.ReadAll(response.Body)
	response.Body.Close()
	if response.StatusCode != http.StatusOK || bytes.Contains(data, []byte("new-git-token")) {
		t.Fatalf("post-sync credential rotation status=%d body=%s", response.StatusCode, data)
	}
	if err = db.Pool.QueryRow(ctx, `SELECT encrypted_secret FROM source_credentials WHERE id=$1`, gitCredentialID).Scan(&encrypted); err != nil {
		t.Fatal(err)
	}
	plain, err = box.Decrypt(encrypted, cryptox.ResourceContext("source-credential", gitCredentialID.String()))
	if err != nil || string(plain) != "new-git-token" || encrypted == gitEncrypted {
		t.Fatalf("post-sync credential rotation was not persisted safely: changed=%v plaintext=%q err=%v", encrypted != gitEncrypted, plain, err)
	}

	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	privatePEM := string(pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(privateKey)}))
	publicKey, err := ssh.NewPublicKey(&privateKey.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	knownHosts := "git.example.test " + strings.TrimSpace(string(ssh.MarshalAuthorizedKey(publicKey)))
	sshBody, _ := json.Marshal(map[string]string{"kind": "git-ssh", "name": "deploy-key", "server": "git.example.test", "username": "git", "privateKey": privatePEM, "knownHosts": knownHosts})
	req, _ = http.NewRequest(http.MethodPost, server.URL+"/v1/source-credentials", bytes.NewReader(sshBody))
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("X-Organization-ID", orgID.String())
	req.Header.Set("Content-Type", "application/json")
	response, err = http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	data, _ = io.ReadAll(response.Body)
	response.Body.Close()
	if response.StatusCode != http.StatusCreated || bytes.Contains(data, []byte("PRIVATE KEY")) || bytes.Contains(data, []byte("knownHosts")) {
		t.Fatalf("SSH credential response status=%d leaked secret material: %s", response.StatusCode, data)
	}
}
