package templates

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLoadPrivateKeyRequiresPrivateRegularConsistentKey(t *testing.T) {
	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		t.Fatal(err)
	}
	directory := t.TempDir()
	keyPath := filepath.Join(directory, "catalog-key.pem")
	if err = os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: encoded}), 0600); err != nil {
		t.Fatal(err)
	}
	if loaded, loadErr := LoadPrivateKey(keyPath); loadErr != nil || !loaded.Equal(privateKey) {
		t.Fatalf("loaded key matches=%t err=%v", loadErr == nil && loaded.Equal(privateKey), loadErr)
	}
	if err = os.Chmod(keyPath, 0644); err != nil {
		t.Fatal(err)
	}
	if _, err = LoadPrivateKey(keyPath); err == nil || !strings.Contains(err.Error(), "group or other") {
		t.Fatalf("loose private-key permissions error=%v", err)
	}
	if err = os.Chmod(keyPath, 0600); err != nil {
		t.Fatal(err)
	}
	linkPath := filepath.Join(directory, "catalog-key-link.pem")
	if err = os.Symlink(keyPath, linkPath); err != nil {
		t.Fatal(err)
	}
	if _, err = LoadPrivateKey(linkPath); err == nil || !strings.Contains(err.Error(), "regular file") {
		t.Fatalf("private-key symlink error=%v", err)
	}
	if err = os.WriteFile(keyPath, append(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: encoded}), []byte("unexpected")...), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err = LoadPrivateKey(keyPath); err == nil || !strings.Contains(err.Error(), "trailing data") {
		t.Fatalf("trailing private-key data error=%v", err)
	}
	inconsistent := append(ed25519.PrivateKey(nil), privateKey...)
	inconsistent[len(inconsistent)-1] ^= 0xff
	if err = os.WriteFile(keyPath, []byte(base64.StdEncoding.EncodeToString(inconsistent)), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err = LoadPrivateKey(keyPath); err == nil || !strings.Contains(err.Error(), "inconsistent") {
		t.Fatalf("inconsistent private-key error=%v", err)
	}
}

func TestSignCatalogAtomicallyReplacesOutputSymlinks(t *testing.T) {
	root := t.TempDir()
	blueprint := filepath.Join(root, "blueprints", "demo")
	if err := os.MkdirAll(blueprint, 0700); err != nil {
		t.Fatal(err)
	}
	for name, contents := range map[string]string{
		"docker-compose.yml": "services:\n  app:\n    image: example:1\n",
		"meta.json":          `{"id":"demo","name":"Demo","version":"1"}`,
		"template.toml":      "[variables]\n",
	} {
		if err := os.WriteFile(filepath.Join(blueprint, name), []byte(contents), 0600); err != nil {
			t.Fatal(err)
		}
	}
	victimManifest := filepath.Join(t.TempDir(), "manifest-victim")
	victimSignature := filepath.Join(t.TempDir(), "signature-victim")
	for _, path := range []string{victimManifest, victimSignature} {
		if err := os.WriteFile(path, []byte("do not overwrite"), 0600); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Symlink(victimManifest, filepath.Join(root, manifestName)); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(victimSignature, filepath.Join(root, signatureName)); err != nil {
		t.Fatal(err)
	}
	publicKey, privateKey, err := GenerateCatalogKey()
	if err != nil {
		t.Fatal(err)
	}
	if err = SignCatalog(root, privateKey); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{victimManifest, victimSignature} {
		contents, readErr := os.ReadFile(path)
		if readErr != nil || string(contents) != "do not overwrite" {
			t.Fatalf("signing followed output symlink %s: contents=%q err=%v", path, contents, readErr)
		}
	}
	for _, name := range []string{manifestName, signatureName} {
		info, statErr := os.Lstat(filepath.Join(root, name))
		if statErr != nil {
			t.Fatalf("inspect published artifact %s: %v", name, statErr)
		}
		if !info.Mode().IsRegular() {
			t.Fatalf("published artifact %s mode=%v", name, info.Mode())
		}
	}
	if err = VerifyCatalog(root, publicKey); err != nil {
		t.Fatalf("verify atomically published catalog: %v", err)
	}
	if err = SignCatalog(root, make(ed25519.PrivateKey, ed25519.PrivateKeySize)); err == nil {
		t.Fatal("accepted inconsistent private key")
	}
}

func TestCatalogSigningRejectsUnsafeInputFiles(t *testing.T) {
	root := t.TempDir()
	blueprint := filepath.Join(root, "blueprints", "demo")
	if err := os.MkdirAll(blueprint, 0700); err != nil {
		t.Fatal(err)
	}
	for name, contents := range map[string]string{
		"docker-compose.yml": "services:\n  app:\n    image: example:1\n",
		"meta.json":          `{"id":"demo","name":"Demo","version":"1"}`,
		"template.toml":      "[variables]\n",
	} {
		if err := os.WriteFile(filepath.Join(blueprint, name), []byte(contents), 0600); err != nil {
			t.Fatal(err)
		}
	}
	publicKey, privateKey, err := GenerateCatalogKey()
	if err != nil {
		t.Fatal(err)
	}
	if err = SignCatalog(root, privateKey); err != nil {
		t.Fatal(err)
	}
	manifestCopy := filepath.Join(t.TempDir(), "manifest.json")
	manifest, err := os.ReadFile(filepath.Join(root, manifestName))
	if err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(manifestCopy, manifest, 0600); err != nil {
		t.Fatal(err)
	}
	if err = os.Remove(filepath.Join(root, manifestName)); err != nil {
		t.Fatal(err)
	}
	if err = os.Symlink(manifestCopy, filepath.Join(root, manifestName)); err != nil {
		t.Fatal(err)
	}
	if err = VerifyCatalog(root, publicKey); err == nil || !strings.Contains(err.Error(), "regular file") {
		t.Fatalf("manifest symlink error=%v", err)
	}
	if err = os.Remove(filepath.Join(root, manifestName)); err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(filepath.Join(root, manifestName), manifest, 0644); err != nil {
		t.Fatal(err)
	}
	if err = os.Truncate(filepath.Join(blueprint, "docker-compose.yml"), maxCatalogFileBytes+1); err != nil {
		t.Fatal(err)
	}
	if _, err = BuildCatalogManifest(root); err == nil || !strings.Contains(err.Error(), "size exceeds") {
		t.Fatalf("oversized catalog source error=%v", err)
	}
}
