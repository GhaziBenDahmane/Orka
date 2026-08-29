package templates

import (
	"context"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/bendahma/dokploy-go/internal/store"
)

func TestGitHubArchiveURL(t *testing.T) {
	got, err := GitHubArchiveURL("https://github.com/acme/catalog.git", "main")
	if err != nil {
		t.Fatal(err)
	}
	if got != "https://codeload.github.com/acme/catalog/tar.gz/main" {
		t.Fatalf("url=%q", got)
	}
	for _, invalid := range []string{"http://github.com/acme/catalog", "https://evil.test/acme/catalog", "https://github.com/acme/catalog/extra", "https://user@github.com/acme/catalog", "https://github.com/acme/catalog?x=1"} {
		if _, err := GitHubArchiveURL(invalid, "main"); err == nil {
			t.Errorf("accepted %q", invalid)
		}
	}
}

func TestFetchCatalogArchiveUsesBearerToken(t *testing.T) {
	var authorization, accept string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		authorization, accept = r.Header.Get("Authorization"), r.Header.Get("Accept")
		http.Error(w, "not an archive", http.StatusUnauthorized)
	}))
	t.Cleanup(server.Close)
	if _, _, err := fetchCatalogArchive(context.Background(), server.Client(), server.URL, "private-token"); err == nil {
		t.Fatal("unauthorized archive response was accepted")
	}
	if authorization != "Bearer private-token" || accept != "application/vnd.github+json" {
		t.Fatalf("authorization=%q accept=%q", authorization, accept)
	}
}

func TestVerifyRepositoryCatalogEnforcesPinnedSigner(t *testing.T) {
	root := t.TempDir()
	catalogRoot := filepath.Join(root, "catalog")
	blueprint := filepath.Join(catalogRoot, "blueprints", "demo")
	if err := os.MkdirAll(blueprint, 0700); err != nil {
		t.Fatal(err)
	}
	for name, contents := range map[string]string{
		"meta.json":          `{"id":"demo","name":"Demo","version":"1"}`,
		"template.toml":      "[variables]\n",
		"docker-compose.yml": "services:\n  web:\n    image: example@sha256:" + strings.Repeat("a", 64) + "\n",
	} {
		if err := os.WriteFile(filepath.Join(blueprint, name), []byte(contents), 0600); err != nil {
			t.Fatal(err)
		}
	}
	publicKey, privateKey, err := GenerateCatalogKey()
	if err != nil {
		t.Fatal(err)
	}
	if err = SignCatalog(catalogRoot, privateKey); err != nil {
		t.Fatal(err)
	}
	repository := store.TemplateRepository{CatalogPath: "catalog", TrustedPublicKey: base64.StdEncoding.EncodeToString(publicKey), RequireSignature: true}
	fingerprint, err := VerifyRepositoryCatalog(repository, root)
	if err != nil {
		t.Fatal(err)
	}
	if fingerprint != PublicKeyFingerprint(publicKey) {
		t.Fatalf("fingerprint=%q", fingerprint)
	}
	if err = os.WriteFile(filepath.Join(blueprint, "meta.json"), []byte(`{"id":"tampered"}`), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err = VerifyRepositoryCatalog(repository, root); err == nil || !strings.Contains(err.Error(), "contents do not match") {
		t.Fatalf("tampered catalog error=%v", err)
	}
	if _, err = VerifyRepositoryCatalog(store.TemplateRepository{RequireSignature: true}, root); err == nil {
		t.Fatal("required signature accepted without a trusted key")
	}
	pemKey, err := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil {
		t.Fatal(err)
	}
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pemKey})
	if _, err = ParsePublicKey(append(pemBytes, []byte("unexpected")...)); err == nil {
		t.Fatal("public key parser accepted trailing PEM data")
	}
}
