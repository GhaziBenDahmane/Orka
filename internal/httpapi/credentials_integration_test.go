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

	"github.com/bendahma/dokploy-go/internal/cryptox"
	"github.com/bendahma/dokploy-go/internal/store"
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
