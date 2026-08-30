package volumeartifact

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/bendahma/dokploy-go/internal/cryptox"
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

func TestTransferEnforcesExpectedSizeAndCleansPartialDownloads(t *testing.T) {
	tests := []struct {
		name        string
		serve       func(http.ResponseWriter)
		expected    int64
		wantErr     string
		wantContent string
	}{
		{name: "exact", expected: 8, wantContent: "artifact", serve: func(w http.ResponseWriter) { _, _ = w.Write([]byte("artifact")) }},
		{name: "content length mismatch", expected: 7, wantErr: "content length mismatch", serve: func(w http.ResponseWriter) { _, _ = w.Write([]byte("artifact")) }},
		{name: "oversized chunked", expected: 7, wantErr: "size mismatch", serve: func(w http.ResponseWriter) {
			w.(http.Flusher).Flush()
			_, _ = w.Write([]byte("artifact"))
		}},
		{name: "truncated chunked", expected: 9, wantErr: "size mismatch", serve: func(w http.ResponseWriter) {
			w.(http.Flusher).Flush()
			_, _ = w.Write([]byte("artifact"))
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { test.serve(w) }))
			defer server.Close()
			filename := filepath.Join(t.TempDir(), "artifact.enc")
			err := transfer(context.Background(), http.MethodGet, server.URL, filename, test.expected)
			if test.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), test.wantErr) {
					t.Fatalf("error=%v, want %q", err, test.wantErr)
				}
				if _, statErr := os.Stat(filename); !errors.Is(statErr, os.ErrNotExist) {
					t.Fatalf("partial artifact remains: %v", statErr)
				}
				return
			}
			content, readErr := os.ReadFile(filename)
			if err != nil || readErr != nil || string(content) != test.wantContent {
				t.Fatalf("error=%v read=%v content=%q", err, readErr, content)
			}
		})
	}
}

func TestTransferSendsVerifiedUploadLength(t *testing.T) {
	var contentLength int64
	var content []byte
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		contentLength = r.ContentLength
		content, _ = io.ReadAll(r.Body)
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()
	filename := filepath.Join(t.TempDir(), "artifact.enc")
	if err := os.WriteFile(filename, []byte("artifact"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := transfer(context.Background(), http.MethodPut, server.URL, filename, 8); err != nil {
		t.Fatal(err)
	}
	if contentLength != 8 || string(content) != "artifact" {
		t.Fatalf("content length=%d content=%q", contentLength, content)
	}
	if err := transfer(context.Background(), http.MethodPut, server.URL, filename, 7); err == nil || !strings.Contains(err.Error(), "upload size mismatch") {
		t.Fatalf("mismatched upload error=%v", err)
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

func TestRestoreRejectsAuthenticatedInvalidArchiveWithoutChangingVolume(t *testing.T) {
	key := make([]byte, 32)
	_, _ = rand.Read(key)
	box, err := cryptox.New(key)
	if err != nil {
		t.Fatal(err)
	}
	plaintext := []byte("authenticated but not a gzip archive")
	var ciphertext bytes.Buffer
	if err = box.EncryptStream(&ciphertext, bytes.NewReader(plaintext), "volume-backup:test"); err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write(ciphertext.Bytes()) }))
	defer server.Close()
	volume := t.TempDir()
	if err = os.WriteFile(filepath.Join(volume, "live"), []byte("safe"), 0600); err != nil {
		t.Fatal(err)
	}
	encryptedHash, plaintextHash := sha256.Sum256(ciphertext.Bytes()), sha256.Sum256(plaintext)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	_, err = Run(ctx, Job{
		Mode: "restore", TransferURL: server.URL, EncryptionKey: base64.RawStdEncoding.EncodeToString(key), EncryptionAAD: "volume-backup:test",
		SHA256: hex.EncodeToString(encryptedHash[:]), PlaintextSHA256: hex.EncodeToString(plaintextHash[:]), SizeBytes: int64(ciphertext.Len()),
	}, volume, t.TempDir())
	if err == nil || ctx.Err() != nil {
		t.Fatalf("invalid authenticated archive error=%v context=%v", err, ctx.Err())
	}
	data, readErr := os.ReadFile(filepath.Join(volume, "live"))
	if readErr != nil || string(data) != "safe" {
		t.Fatalf("live data changed: %q %v", data, readErr)
	}
}
