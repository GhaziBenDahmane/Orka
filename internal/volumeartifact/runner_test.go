package volumeartifact

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
)

func TestEncryptedBackupAndRestoreRoundTrip(t *testing.T) {
	var stored []byte
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodPut:
			stored, _ = io.ReadAll(r.Body)
			w.WriteHeader(http.StatusNoContent)
		case http.MethodGet:
			_, _ = w.Write(stored)
		default:
			w.WriteHeader(http.StatusMethodNotAllowed)
		}
	}))
	defer server.Close()
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		t.Fatal(err)
	}
	encodedKey := base64.RawStdEncoding.EncodeToString(key)
	volume, work := filepath.Join(t.TempDir(), "volume"), t.TempDir()
	if err := os.MkdirAll(volume, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(volume, "state.db"), []byte("important state"), 0600); err != nil {
		t.Fatal(err)
	}
	backup, err := Run(context.Background(), Job{Mode: "backup", TransferURL: server.URL, EncryptionKey: encodedKey, EncryptionAAD: "volume-backup:test"}, volume, work)
	if err != nil || backup.SizeBytes == 0 || backup.SHA256 == "" || backup.PlaintextSHA256 == "" {
		t.Fatalf("backup=%+v err=%v", backup, err)
	}
	if err = os.WriteFile(filepath.Join(volume, "state.db"), []byte("corrupt"), 0600); err != nil {
		t.Fatal(err)
	}
	restored, err := Run(context.Background(), Job{Mode: "restore", TransferURL: server.URL, EncryptionKey: encodedKey, EncryptionAAD: "volume-backup:test", SHA256: backup.SHA256, PlaintextSHA256: backup.PlaintextSHA256, SizeBytes: backup.SizeBytes}, volume, work)
	if err != nil || restored != backup {
		t.Fatalf("restore=%+v backup=%+v err=%v", restored, backup, err)
	}
	data, err := os.ReadFile(filepath.Join(volume, "state.db"))
	if err != nil || string(data) != "important state" {
		t.Fatalf("restored data=%q err=%v", data, err)
	}
}

func TestRestoreRejectsTamperedCiphertextWithoutChangingVolume(t *testing.T) {
	key := make([]byte, 32)
	_, _ = rand.Read(key)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte("tampered")) }))
	defer server.Close()
	volume := t.TempDir()
	if err := os.WriteFile(filepath.Join(volume, "live"), []byte("safe"), 0600); err != nil {
		t.Fatal(err)
	}
	_, err := Run(context.Background(), Job{Mode: "restore", TransferURL: server.URL, EncryptionKey: base64.RawStdEncoding.EncodeToString(key), EncryptionAAD: "volume-backup:test", SHA256: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", PlaintextSHA256: "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", SizeBytes: 8}, volume, t.TempDir())
	if err == nil {
		t.Fatal("tampered artifact was restored")
	}
	data, readErr := os.ReadFile(filepath.Join(volume, "live"))
	if readErr != nil || string(data) != "safe" {
		t.Fatalf("live data changed: %q %v", data, readErr)
	}
}
