package httpapi

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"io"
	"log/slog"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/bendahma/dokploy-go/internal/cryptox"
	"github.com/bendahma/dokploy-go/internal/store"
	"github.com/google/uuid"
)

func TestCustomTLSCertificateAPIEncryptsAndNeverReturnsKeyMaterial(t *testing.T) {
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
	box, err := cryptox.New(bytes.Repeat([]byte{41}, 32))
	if err != nil {
		t.Fatal(err)
	}
	organizationID, userID := uuid.New(), uuid.New()
	token := "custom-tls-" + uuid.NewString()
	for _, statement := range []struct {
		query string
		args  []any
	}{
		{`INSERT INTO organizations(id,name,slug) VALUES($1,'Custom TLS API',$2)`, []any{organizationID, "custom-tls-api-" + organizationID.String()}},
		{`INSERT INTO users(id,email,password_hash) VALUES($1,$2,'x')`, []any{userID, userID.String() + "@example.test"}},
		{`INSERT INTO memberships(organization_id,user_id,role) VALUES($1,$2,'owner')`, []any{organizationID, userID}},
		{`INSERT INTO sessions(id,user_id,token_hash,expires_at) VALUES($1,$2,$3,now()+interval '5 minutes')`, []any{uuid.New(), userID, cryptox.Digest(token)}},
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
	certificatePEM, privateKeyPEM := testServerCertificate(t, "app.example.test", 1)
	status, response := scopedAPIRequest(t, server.URL+"/v1/custom-tls-certificates", token, organizationID, http.MethodPost, map[string]any{"name": "Production wildcard", "certificatePem": string(certificatePEM), "privateKeyPem": string(privateKeyPEM)})
	assertCustomTLSResponseRedacted(t, status, http.StatusCreated, response)
	var created struct {
		ID          uuid.UUID `json:"id"`
		Fingerprint string    `json:"fingerprint"`
		Revision    int64     `json:"revision"`
	}
	if err = json.Unmarshal(response, &created); err != nil || created.ID == uuid.Nil || created.Fingerprint == "" || created.Revision != 1 {
		t.Fatalf("created=%#v error=%v body=%s", created, err, response)
	}
	var encryptedCertificate, encryptedPrivateKey string
	if err = db.Pool.QueryRow(ctx, `SELECT encrypted_certificate,encrypted_private_key FROM custom_tls_certificates WHERE id=$1`, created.ID).Scan(&encryptedCertificate, &encryptedPrivateKey); err != nil {
		t.Fatal(err)
	}
	if encryptedCertificate == string(certificatePEM) || encryptedPrivateKey == string(privateKeyPEM) || encryptedCertificate == "" || encryptedPrivateKey == "" {
		t.Fatal("custom TLS material was not encrypted at rest")
	}
	plainCertificate, err := box.Decrypt(encryptedCertificate, cryptox.ResourceContext("custom-tls-certificate-certificate", created.ID.String()))
	if err != nil || !bytes.Equal(plainCertificate, certificatePEM) {
		t.Fatalf("stored certificate cannot be decrypted with its resource context: %v", err)
	}
	plainPrivateKey, err := box.Decrypt(encryptedPrivateKey, cryptox.ResourceContext("custom-tls-certificate-private-key", created.ID.String()))
	if err != nil || !bytes.Equal(plainPrivateKey, privateKeyPEM) {
		t.Fatalf("stored private key cannot be decrypted with its resource context: %v", err)
	}

	rotatedCertificatePEM, rotatedPrivateKeyPEM := testServerCertificate(t, "app.example.test", 2)
	status, response = scopedAPIRequest(t, server.URL+"/v1/custom-tls-certificates/"+created.ID.String(), token, organizationID, http.MethodPut, map[string]any{"name": "Production wildcard", "certificatePem": string(rotatedCertificatePEM), "privateKeyPem": string(rotatedPrivateKeyPEM), "revision": created.Revision})
	assertCustomTLSResponseRedacted(t, status, http.StatusOK, response)
	if !bytes.Contains(response, []byte(`"revision":2`)) {
		t.Fatalf("rotation did not advance revision: %s", response)
	}

	if _, err = db.Pool.Exec(ctx, `UPDATE memberships SET role='viewer' WHERE organization_id=$1 AND user_id=$2`, organizationID, userID); err != nil {
		t.Fatal(err)
	}
	status, response = scopedAPIRequest(t, server.URL+"/v1/custom-tls-certificates", token, organizationID, http.MethodGet, nil)
	assertCustomTLSResponseRedacted(t, status, http.StatusOK, response)
	if !bytes.Contains(response, []byte(created.ID.String())) || !bytes.Contains(response, []byte(`"dnsNames":["app.example.test"]`)) {
		t.Fatalf("viewer did not receive certificate metadata: %s", response)
	}
	status, _ = scopedAPIRequest(t, server.URL+"/v1/custom-tls-certificates", token, organizationID, http.MethodPost, map[string]any{"name": "Denied", "certificatePem": string(certificatePEM), "privateKeyPem": string(privateKeyPEM)})
	if status != http.StatusForbidden {
		t.Fatalf("viewer create status=%d", status)
	}
}

func testServerCertificate(t *testing.T, hostname string, serial int64) ([]byte, []byte) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	template := &x509.Certificate{SerialNumber: big.NewInt(serial), Subject: pkix.Name{CommonName: hostname}, DNSNames: []string{hostname}, NotBefore: now.Add(-time.Minute), NotAfter: now.Add(48 * time.Hour), KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	raw, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: raw}), pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
}

func assertCustomTLSResponseRedacted(t *testing.T, status, want int, body []byte) {
	t.Helper()
	if status != want || bytes.Contains(body, []byte("certificatePem")) || bytes.Contains(body, []byte("privateKeyPem")) || bytes.Contains(body, []byte("encryptedCertificate")) || bytes.Contains(body, []byte("encryptedPrivateKey")) || bytes.Contains(body, []byte("PRIVATE KEY")) {
		t.Fatalf("custom TLS response status=%d want=%d leaked secret material: %s", status, want, body)
	}
}
