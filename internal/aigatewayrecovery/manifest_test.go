package aigatewayrecovery

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
	key := []byte("0123456789012345678901234567890123456789012")
	keyHash, publicHash := sha256.Sum256(key), sha256.Sum256(publicDER)
	expected := Expected{
		Stack: "dockyard-ai", Service: "dockyard-ai_9router", Volume: "dockyard-ai_nine-router-data",
		StorageNodeID: "nodeabc123", RouterImage: "example/9router@sha256:" + strings.Repeat("a", 64),
		HelperImage: "example/dockyard@sha256:" + strings.Repeat("b", 64), ObjectRef: "s3://recovery/ai-gateway.enc",
	}
	createdAt := "2026-08-31T10:00:00Z"
	manifest := Manifest{
		FormatVersion: 1, CreatedAt: createdAt, Stack: expected.Stack, Service: expected.Service,
		Volume: expected.Volume, StorageNodeID: expected.StorageNodeID, RouterImage: expected.RouterImage,
		HelperImage: expected.HelperImage, ObjectRef: expected.ObjectRef,
		EncryptionAAD:       "orka-ai-gateway:" + expected.Stack + ":" + createdAt,
		EncryptionKeySHA256: hex.EncodeToString(keyHash[:]), SHA256: strings.Repeat("c", 64),
		PlaintextSHA256: strings.Repeat("d", 64), SizeBytes: 123,
		RecoverySigningKeySHA256: hex.EncodeToString(publicHash[:]),
	}
	if mutate != nil {
		mutate(&manifest)
	}
	var data []byte
	if extra == nil {
		data, err = json.Marshal(manifest)
	} else {
		var object map[string]any
		encoded, marshalErr := json.Marshal(manifest)
		if marshalErr == nil {
			marshalErr = json.Unmarshal(encoded, &object)
		}
		for name, value := range extra {
			object[name] = value
		}
		data, err = json.Marshal(object)
		if marshalErr != nil {
			err = marshalErr
		}
	}
	if err != nil {
		t.Fatal(err)
	}
	signature := ed25519.Sign(privateKey, data)
	publicPEM := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: publicDER})
	return data, signature, publicPEM, key, expected
}

func TestVerifySignedManifest(t *testing.T) {
	manifest, signature, publicKey, key, expected := signedManifest(t, nil, nil)
	got, err := Verify(manifest, signature, publicKey, key, expected, time.Date(2026, 8, 31, 10, 1, 0, 0, time.UTC))
	if err != nil || got.ObjectRef != expected.ObjectRef || got.SizeBytes != 123 {
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
		{name: "mismatched AAD", mutate: func(m *Manifest) { m.EncryptionAAD = "other" }, want: "encryption context"},
		{name: "mutable image", mutate: func(m *Manifest) { m.RouterImage = "example/9router:latest" }, want: "image identity"},
		{name: "wrong deployment", change: func(e *Expected, _, _ *[]byte) { e.Volume = "other" }, want: "requested deployment"},
		{name: "wrong encryption key", change: func(_ *Expected, key, _ *[]byte) { *key = []byte("different") }, want: "encryption key"},
		{name: "tampered signature", change: func(_ *Expected, _, signature *[]byte) { (*signature)[0] ^= 0xff }, want: "signature is invalid"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			manifest, signature, publicKey, key, expected := signedManifest(t, test.mutate, test.extra)
			if test.change != nil {
				test.change(&expected, &key, &signature)
			}
			if _, err := Verify(manifest, signature, publicKey, key, expected, now); err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("error=%v want substring %q", err, test.want)
			}
		})
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
