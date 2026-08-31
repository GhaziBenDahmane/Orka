package controlplanerecovery

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/bendahma/dokploy-go/internal/agentpki"
)

func signedManifest(t *testing.T, mutate func(*Manifest), extra map[string]any) ([]byte, []byte, []byte, []byte, Expected) {
	t.Helper()
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	publicDER, err := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil {
		t.Fatal(err)
	}
	masterKey := []byte("01234567890123456789012345678901")
	masterHash, publicHash := sha256.Sum256(masterKey), sha256.Sum256(publicDER)
	expected := Expected{
		Stack: "dockyard", Database: "dockyard",
		ControllerImage: "ghcr.io/example/dockyard@sha256:" + strings.Repeat("a", 64),
	}
	manifest := Manifest{
		FormatVersion: 2, CreatedAt: "2026-08-31T10:00:00Z", Stack: expected.Stack,
		Database: expected.Database, SchemaVersion: "20260831100000", ControllerImage: expected.ControllerImage,
		DatabaseSHA256: strings.Repeat("b", 64), DatabaseBytes: 4096,
		MasterKeySHA256: hex.EncodeToString(masterHash[:]), AgentCASHA256: "",
		RecoverySigningKeySHA256: hex.EncodeToString(publicHash[:]),
	}
	if mutate != nil {
		mutate(&manifest)
	}
	encoded, err := json.Marshal(manifest)
	if err != nil {
		t.Fatal(err)
	}
	if extra != nil {
		var object map[string]any
		if err = json.Unmarshal(encoded, &object); err != nil {
			t.Fatal(err)
		}
		for key, value := range extra {
			object[key] = value
		}
		encoded, err = json.Marshal(object)
		if err != nil {
			t.Fatal(err)
		}
	}
	return encoded, ed25519.Sign(privateKey, encoded), pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: publicDER}), masterKey, expected
}

func TestVerifySignedManifest(t *testing.T) {
	manifest, signature, publicKey, masterKey, expected := signedManifest(t, nil, nil)
	got, err := Verify(manifest, signature, publicKey, masterKey, nil, nil, expected, time.Date(2026, 8, 31, 10, 1, 0, 0, time.UTC))
	if err != nil || got.DatabaseBytes != 4096 || got.SchemaVersion != "20260831100000" {
		t.Fatalf("manifest=%+v err=%v", got, err)
	}
}

func TestVerifySignedManifestRejectsInvalidInput(t *testing.T) {
	now := time.Date(2026, 8, 31, 10, 1, 0, 0, time.UTC)
	tests := []struct {
		name   string
		mutate func(*Manifest)
		extra  map[string]any
		change func(*Expected, *[]byte, *[]byte)
		want   string
	}{
		{name: "unknown field", extra: map[string]any{"credential": "secret"}, want: "unknown field"},
		{name: "future timestamp", mutate: func(m *Manifest) { m.CreatedAt = "2026-09-01T10:00:00Z" }, want: "createdAt"},
		{name: "wrong format", mutate: func(m *Manifest) { m.FormatVersion = 1 }, want: "format"},
		{name: "mutable image", mutate: func(m *Manifest) { m.ControllerImage = "ghcr.io/example/dockyard:latest" }, want: "digest-pinned"},
		{name: "invalid agent CA hash", mutate: func(m *Manifest) { m.AgentCASHA256 = "invalid" }, want: "agent CA"},
		{name: "empty dump", mutate: func(m *Manifest) { m.DatabaseBytes = 0 }, want: "size"},
		{name: "wrong signing key fingerprint", mutate: func(m *Manifest) { m.RecoverySigningKeySHA256 = strings.Repeat("d", 64) }, want: "verification key"},
		{name: "wrong stack", change: func(e *Expected, _, _ *[]byte) { e.Stack = "other" }, want: "requested deployment"},
		{name: "wrong master key", change: func(_ *Expected, key, _ *[]byte) { (*key)[0] ^= 0xff }, want: "master key"},
		{name: "tampered signature", change: func(_ *Expected, _, signature *[]byte) { (*signature)[0] ^= 0xff }, want: "signature is invalid"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			manifest, signature, publicKey, masterKey, expected := signedManifest(t, test.mutate, test.extra)
			if test.change != nil {
				test.change(&expected, &masterKey, &signature)
			}
			if _, err := Verify(manifest, signature, publicKey, masterKey, nil, nil, expected, now); err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("error=%v want substring %q", err, test.want)
			}
		})
	}
}

func TestVerifyRequiresMatchingAgentCAKeypair(t *testing.T) {
	now := time.Date(2026, 8, 31, 10, 1, 0, 0, time.UTC)
	certificate, key, err := agentpki.NewCA(now, 365*24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	block, _ := pem.Decode(certificate)
	certificateHash := sha256.Sum256(block.Bytes)
	manifest, signature, publicKey, masterKey, expected := signedManifest(t, func(manifest *Manifest) {
		manifest.AgentCASHA256 = hex.EncodeToString(certificateHash[:])
	}, nil)
	if _, err = Verify(manifest, signature, publicKey, masterKey, certificate, key, expected, now); err != nil {
		t.Fatal(err)
	}
	if _, err = Verify(manifest, signature, publicKey, masterKey, nil, nil, expected, now); err == nil || !strings.Contains(err.Error(), "certificate and private key") {
		t.Fatalf("missing keypair error=%v", err)
	}
	_, otherKey, err := agentpki.NewCA(now, 365*24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = Verify(manifest, signature, publicKey, masterKey, certificate, otherKey, expected, now); err == nil || !strings.Contains(err.Error(), "do not match") {
		t.Fatalf("mismatched keypair error=%v", err)
	}
}

func TestReadRegularFileRejectsSymlinkAndOversize(t *testing.T) {
	directory := t.TempDir()
	target := filepath.Join(directory, "target")
	if err := os.WriteFile(target, []byte("data"), 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(directory, "link")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadRegularFile(link, 8); err == nil || !strings.Contains(err.Error(), "regular file") {
		t.Fatalf("symlink error=%v", err)
	}
	if _, err := ReadRegularFile(target, 3); err == nil || !strings.Contains(err.Error(), "invalid size") {
		t.Fatalf("oversize error=%v", err)
	}
	if data, err := ReadRegularFile(target, 4); err != nil || string(data) != "data" {
		t.Fatalf("data=%q err=%v", data, err)
	}
}
