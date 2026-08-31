package templates

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
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

type catalogArchiveEntry struct {
	name      string
	contents  string
	directory bool
}

func TestGitHubArchiveURL(t *testing.T) {
	got, err := GitHubArchiveURL("https://github.com/acme/catalog.git", "main")
	if err != nil {
		t.Fatal(err)
	}
	if got != "https://codeload.github.com/acme/catalog/tar.gz/main" {
		t.Fatalf("url=%q", got)
	}
	for _, invalid := range []string{"http://github.com/acme/catalog", "https://evil.test/acme/catalog", "https://github.com/acme/catalog/extra", "https://user@github.com/acme/catalog", "https://github.com/acme/catalog?x=1", "https://github.com/./catalog", "https://github.com/acme/..", "https://github.com/" + strings.Repeat("o", maxGitHubOwnerBytes+1) + "/catalog", "https://github.com/acme/" + strings.Repeat("r", maxGitHubRepositoryBytes+1)} {
		if _, err := GitHubArchiveURL(invalid, "main"); err == nil {
			t.Errorf("accepted %q", invalid)
		}
	}
	for _, ref := range []string{"", ".hidden", "feature..branch", "refs/heads/main.lock", "refs//heads/main", "feature branch", "feature~1", "feature^2", "feature:one", "feature?", "feature*", "feature[1", "feature\\one", "feature\nheader", strings.Repeat("r", 201)} {
		if _, err := GitHubArchiveURL("https://github.com/acme/catalog", ref); err == nil {
			t.Errorf("accepted invalid ref %q", ref)
		}
	}
}

func TestNormalizeCatalogPath(t *testing.T) {
	for raw, want := range map[string]string{"": "", "/": "", "catalog": "catalog", "/catalog/blueprints/": "catalog/blueprints"} {
		got, err := NormalizeCatalogPath(raw)
		if err != nil || got != want {
			t.Errorf("NormalizeCatalogPath(%q) = %q, %v; want %q", raw, got, err, want)
		}
	}
	for _, raw := range []string{".", "..", "../catalog", "catalog/../other", "catalog//blueprints", `catalog\blueprints`, "catalog\x00blueprints", "catalog\nblueprints", strings.Repeat("a", maxCatalogPathBytes+1), strings.Repeat("a/", maxCatalogPathDepth) + "end"} {
		if _, err := NormalizeCatalogPath(raw); err == nil {
			t.Errorf("unsafe catalog path %q was accepted", raw)
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

func TestFetchCatalogArchiveRejectsUnsafeToken(t *testing.T) {
	for _, token := range []string{"secret\nheader", strings.Repeat("t", maxGitHubTokenBytes+1)} {
		if root, cleanup, err := fetchCatalogArchive(context.Background(), nil, "https://codeload.github.com/acme/catalog/tar.gz/main", token); err == nil {
			if cleanup != nil {
				cleanup()
			}
			t.Fatalf("unsafe token produced archive root %q", root)
		}
	}
}

func TestCatalogHTTPClientDisablesAmbientProxy(t *testing.T) {
	t.Setenv("HTTPS_PROXY", "http://proxy.example.test:8080")
	client := catalogHTTPClient(nil)
	transport, ok := client.Transport.(*http.Transport)
	if !ok || transport.Proxy != nil {
		t.Fatalf("catalog transport = %#v; ambient proxy was retained", client.Transport)
	}
	original := &http.Client{Transport: http.DefaultTransport}
	secured := catalogHTTPClient(original)
	if secured == original || secured.Transport != original.Transport || original.CheckRedirect != nil {
		t.Fatal("explicit client transport was replaced or caller client was mutated")
	}
}

func TestFetchCatalogArchiveRefusesCredentialBearingRedirect(t *testing.T) {
	redirectedRequests := 0
	target := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		redirectedRequests++
	}))
	t.Cleanup(target.Close)
	archive := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer private-token" {
			t.Errorf("authorization=%q", r.Header.Get("Authorization"))
		}
		http.Redirect(w, r, target.URL, http.StatusTemporaryRedirect)
	}))
	t.Cleanup(archive.Close)

	_, _, err := fetchCatalogArchive(context.Background(), archive.Client(), archive.URL, "private-token")
	if err == nil || !strings.Contains(err.Error(), "redirects are disabled") {
		t.Fatalf("redirect error=%v", err)
	}
	if redirectedRequests != 0 {
		t.Fatalf("redirect target received %d credential-bearing request(s)", redirectedRequests)
	}
}

func TestFetchCatalogArchiveExtractsSingleRoot(t *testing.T) {
	server := newCatalogArchiveServer(t, []catalogArchiveEntry{
		{name: "catalog-main/", directory: true},
		{name: "catalog-main/blueprints/", directory: true},
		{name: "catalog-main/blueprints/demo/", directory: true},
		{name: "catalog-main/blueprints/demo/meta.json", contents: `{"id":"demo"}`},
	})
	root, cleanup, err := fetchCatalogArchive(context.Background(), server.Client(), server.URL, "")
	if err != nil {
		t.Fatal(err)
	}
	defer cleanup()
	contents, err := os.ReadFile(filepath.Join(root, "blueprints", "demo", "meta.json"))
	if err != nil || string(contents) != `{"id":"demo"}` {
		t.Fatalf("extracted contents=%q err=%v", contents, err)
	}
}

func TestFetchCatalogArchiveRejectsUnsafeStructure(t *testing.T) {
	deepPath := "catalog-main/" + strings.Repeat("directory/", maxCatalogPathDepth) + "file"
	tests := map[string][]catalogArchiveEntry{
		"parent traversal":     {{name: "../escaped", directory: true}},
		"normalized traversal": {{name: "catalog-main/blueprints/../escaped", directory: true}},
		"duplicate separator":  {{name: "catalog-main//blueprints/demo", directory: true}},
		"backslash path":       {{name: `catalog-main\blueprints`, directory: true}},
		"control character":    {{name: "catalog-main/blueprints/bad\nname", directory: true}},
		"oversized segment":    {{name: "catalog-main/" + strings.Repeat("a", 256), directory: true}},
		"multiple roots": {
			{name: "catalog-main/blueprints/", directory: true},
			{name: "other-main/blueprints/", directory: true},
		},
		"excessive depth": {{name: deepPath, contents: "x"}},
	}
	for name, entries := range tests {
		t.Run(name, func(t *testing.T) {
			server := newCatalogArchiveServer(t, entries)
			if root, cleanup, err := fetchCatalogArchive(context.Background(), server.Client(), server.URL, ""); err == nil {
				cleanup()
				t.Fatalf("unsafe archive extracted to %s", root)
			}
		})
	}
}

func TestFetchCatalogArchiveCountsDirectoryEntries(t *testing.T) {
	entries := make([]catalogArchiveEntry, maxCatalogEntries+1)
	for index := range entries {
		entries[index] = catalogArchiveEntry{name: "catalog-main/repeated/", directory: true}
	}
	server := newCatalogArchiveServer(t, entries)
	if root, cleanup, err := fetchCatalogArchive(context.Background(), server.Client(), server.URL, ""); err == nil || !strings.Contains(err.Error(), "entry limit") {
		if cleanup != nil {
			cleanup()
		}
		t.Fatalf("directory entry limit root=%q err=%v", root, err)
	}
}

func TestFetchCatalogArchiveRejectsAnnouncedOversize(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Length", "67108865")
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(server.Close)
	if root, cleanup, err := fetchCatalogArchive(context.Background(), server.Client(), server.URL, ""); err == nil || !strings.Contains(err.Error(), "exceeds 64 MiB") {
		if cleanup != nil {
			cleanup()
		}
		t.Fatalf("oversized archive root=%q err=%v", root, err)
	}
}

func newCatalogArchiveServer(t *testing.T, entries []catalogArchiveEntry) *httptest.Server {
	t.Helper()
	var payload bytes.Buffer
	gzipWriter := gzip.NewWriter(&payload)
	tarWriter := tar.NewWriter(gzipWriter)
	for _, entry := range entries {
		typeflag, mode, size := byte(tar.TypeReg), int64(0644), int64(len(entry.contents))
		if entry.directory {
			typeflag, mode, size = tar.TypeDir, 0755, 0
		}
		if err := tarWriter.WriteHeader(&tar.Header{Name: entry.name, Typeflag: typeflag, Mode: mode, Size: size}); err != nil {
			t.Fatal(err)
		}
		if size > 0 {
			if _, err := tarWriter.Write([]byte(entry.contents)); err != nil {
				t.Fatal(err)
			}
		}
	}
	if err := tarWriter.Close(); err != nil {
		t.Fatal(err)
	}
	if err := gzipWriter.Close(); err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(payload.Bytes())
	}))
	t.Cleanup(server.Close)
	return server
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
