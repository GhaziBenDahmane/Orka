package backup

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestS3ConfigurationAndObjectKey(t *testing.T) {
	client, err := NewS3(S3Config{Endpoint: "https://objects.example.test", Bucket: "backups", Prefix: "/tenant/database/", UseTLS: true, AccessKey: "access", SecretKey: "secret"})
	if err != nil {
		t.Fatal(err)
	}
	if got, keyErr := client.ObjectKey("backup.dump"); keyErr != nil || got != "tenant/database/backup.dump" {
		t.Fatalf("object key = %q", got)
	}
	for _, config := range []S3Config{
		{Endpoint: "ftp://example.test", Bucket: "backups", AccessKey: "a", SecretKey: "s"},
		{Endpoint: "https://example.test/path", Bucket: "backups", UseTLS: true, AccessKey: "a", SecretKey: "s"},
		{Endpoint: "http://example.test", Bucket: "backups", UseTLS: true, AccessKey: "a", SecretKey: "s"},
		{Endpoint: "http://example.test", Bucket: "", AccessKey: "a", SecretKey: "s"},
		{Endpoint: "https://objects.example.test", Bucket: strings.Repeat("b", maxS3BucketBytes+1), UseTLS: true, AccessKey: "a", SecretKey: "s"},
		{Endpoint: "https://objects.example.test", Region: "bad region", Bucket: "backups", UseTLS: true, AccessKey: "a", SecretKey: "s"},
		{Endpoint: "https://objects.example.test", Bucket: "backups", Prefix: strings.Repeat("p", maxS3PrefixBytes+1), UseTLS: true, AccessKey: "a", SecretKey: "s"},
		{Endpoint: "https://objects.example.test", Bucket: "backups", Prefix: "tenant\\escape", UseTLS: true, AccessKey: "a", SecretKey: "s"},
		{Endpoint: "https://objects.example.test", Bucket: "backups", Prefix: "tenant//escape", UseTLS: true, AccessKey: "a", SecretKey: "s"},
		{Endpoint: "https://objects.example.test", Bucket: "backups", Prefix: "tenant\u202Eescape", UseTLS: true, AccessKey: "a", SecretKey: "s"},
		{Endpoint: "https://objects.example.test", Bucket: "backups", Prefix: string([]byte{'t', 0xff}), UseTLS: true, AccessKey: "a", SecretKey: "s"},
		{Endpoint: "https://objects.example.test", Bucket: "backups", UseTLS: true, AccessKey: strings.Repeat("a", maxS3AccessKeyBytes+1), SecretKey: "s"},
		{Endpoint: "https://objects.example.test", Bucket: "backups", UseTLS: true, AccessKey: "a", SecretKey: "secret\nvalue"},
		{Endpoint: "https://objects.example.test", Bucket: "backups", UseTLS: true, AccessKey: "a", SecretKey: "s", SessionToken: strings.Repeat("t", maxS3SessionTokenBytes+1)},
	} {
		if _, err = NewS3(config); err == nil {
			t.Fatalf("expected invalid config rejection: %#v", config)
		}
	}
	for _, endpoint := range []string{
		"https://user@objects.example.test", "https://objects.example.test?token=secret", "https://objects.example.test/#fragment",
		"https://bad_label.example.test", "https://-bad.example.test", "https://objects.example.test:",
		"https://objects.example.test:0", "https://objects.example.test:65536", "https://[not-an-ip]",
	} {
		if _, err = NewS3(S3Config{Endpoint: endpoint, Bucket: "backups", UseTLS: true, AccessKey: "access", SecretKey: "secret"}); err == nil {
			t.Errorf("unsafe endpoint %q was accepted", endpoint)
		}
	}
	for _, endpoint := range []string{"https://objects.example.test:9443", "https://127.0.0.1", "https://[2001:db8::1]:9443"} {
		if _, err = NewS3(S3Config{Endpoint: endpoint, Bucket: "backups", UseTLS: true, AccessKey: "access", SecretKey: "secret"}); err != nil {
			t.Errorf("valid endpoint %q was rejected: %v", endpoint, err)
		}
	}
}

func TestS3ObjectKeysStayInsideConfiguredPrefix(t *testing.T) {
	client, err := NewS3(S3Config{Endpoint: "https://objects.example.test", Bucket: "backups", Prefix: "organization-1", UseTLS: true, AccessKey: "access", SecretKey: "secret"})
	if err != nil {
		t.Fatal(err)
	}
	if key, keyErr := client.ObjectKey("database/backup.enc"); keyErr != nil || key != "organization-1/database/backup.enc" {
		t.Fatalf("key=%q error=%v", key, keyErr)
	}
	for _, key := range []string{"../organization-2/backup.enc", "/organization-2/backup.enc", "database//backup.enc", "database/./backup.enc", "database\\backup.enc", "database/\u202Ebackup.enc", string([]byte{'b', 0xff})} {
		if _, keyErr := client.ObjectKey(key); keyErr == nil {
			t.Errorf("unsafe relative key %q was accepted", key)
		}
	}
	for _, key := range []string{"organization-2/backup.enc", "organization-1-other/backup.enc"} {
		if err = client.Delete(context.Background(), key); err == nil {
			t.Errorf("out-of-prefix stored key %q was accepted", key)
		}
	}
}

func TestS3GetVerifiesMetadataAndBoundsResponse(t *testing.T) {
	tests := []struct {
		name         string
		metadataSize int64
		body         string
		wantErr      bool
		wantGET      bool
	}{
		{name: "exact", metadataSize: 8, body: "artifact", wantGET: true},
		{name: "metadata mismatch", metadataSize: 7, body: "artifact", wantErr: true},
		{name: "oversized body", metadataSize: 8, body: "artifact!", wantErr: true, wantGET: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			getCalled := false
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("ETag", `"0123456789abcdef0123456789abcdef"`)
				w.Header().Set("Last-Modified", "Sun, 30 Aug 2026 12:00:00 GMT")
				switch r.Method {
				case http.MethodHead:
					w.Header().Set("Content-Length", fmt.Sprint(test.metadataSize))
				case http.MethodGet:
					getCalled = true
					w.(http.Flusher).Flush()
					_, _ = w.Write([]byte(test.body))
				default:
					http.Error(w, "unexpected method", http.StatusMethodNotAllowed)
				}
			}))
			defer server.Close()
			client, err := NewS3(S3Config{Endpoint: server.URL, Region: "us-east-1", Bucket: "backups", AccessKey: "access", SecretKey: "secret"})
			if err != nil {
				t.Fatal(err)
			}
			filename := filepath.Join(t.TempDir(), "artifact")
			err = client.Get(context.Background(), "database/object.enc", filename, 8)
			if test.wantErr {
				if err == nil {
					t.Fatal("expected download to fail")
				}
				if _, statErr := os.Stat(filename); !errors.Is(statErr, os.ErrNotExist) {
					t.Fatalf("partial download remains: %v", statErr)
				}
			} else {
				content, readErr := os.ReadFile(filename)
				if err != nil || readErr != nil || string(content) != test.body {
					t.Fatalf("error=%v read=%v content=%q", err, readErr, content)
				}
			}
			if getCalled != test.wantGET {
				t.Fatalf("GET called=%t want=%t", getCalled, test.wantGET)
			}
		})
	}
}

func TestCopyExactFileBoundsDownloadsAndCleansPartialOutput(t *testing.T) {
	tests := []struct {
		name     string
		content  string
		expected int64
		wantErr  bool
	}{
		{name: "exact", content: "backup", expected: 6},
		{name: "oversized", content: "backup-extra", expected: 6, wantErr: true},
		{name: "truncated", content: "back", expected: 6, wantErr: true},
		{name: "missing expected size", content: "backup", expected: 0, wantErr: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			filename := filepath.Join(t.TempDir(), "artifact")
			err := copyExactFile(filename, strings.NewReader(test.content), test.expected)
			if test.wantErr {
				if err == nil {
					t.Fatal("expected bounded copy to fail")
				}
				if _, statErr := os.Stat(filename); !errors.Is(statErr, os.ErrNotExist) {
					t.Fatalf("partial download remains: %v", statErr)
				}
				return
			}
			content, readErr := os.ReadFile(filename)
			if err != nil || readErr != nil || string(content) != test.content {
				t.Fatalf("error=%v read=%v content=%q", err, readErr, content)
			}
		})
	}
}

func TestSHA256SumReaderRequiresExactSize(t *testing.T) {
	content := "immutable audit batch"
	want := sha256.Sum256([]byte(content))
	digest, size, err := sha256sumReader(strings.NewReader(content), int64(len(content)))
	if err != nil || size != int64(len(content)) || digest != hex.EncodeToString(want[:]) {
		t.Fatalf("digest=%q size=%d error=%v", digest, size, err)
	}
	for name, expected := range map[string]int64{"oversized": int64(len(content) - 1), "truncated": int64(len(content) + 1)} {
		t.Run(name, func(t *testing.T) {
			if _, _, err := sha256sumReader(strings.NewReader(content), expected); err == nil {
				t.Fatal("size mismatch was accepted")
			}
		})
	}
}

func TestPutImmutableVerifiesExistingObjectSizeAndDigest(t *testing.T) {
	contents := []byte("immutable audit batch")
	digestBytes := sha256.Sum256(contents)
	digest := hex.EncodeToString(digestBytes[:])
	tests := []struct {
		name         string
		metadataSize int
		body         string
		wantErr      bool
	}{
		{name: "same object", metadataSize: len(contents), body: string(contents)},
		{name: "different metadata size", metadataSize: len(contents) + 1, body: string(contents), wantErr: true},
		{name: "different digest", metadataSize: len(contents), body: strings.Repeat("x", len(contents)), wantErr: true},
		{name: "oversized response", metadataSize: len(contents), body: string(contents) + "!", wantErr: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("ETag", `"0123456789abcdef0123456789abcdef"`)
				w.Header().Set("Last-Modified", "Sun, 30 Aug 2026 12:00:00 GMT")
				switch r.Method {
				case http.MethodPut:
					w.Header().Set("Content-Type", "application/xml")
					w.WriteHeader(http.StatusPreconditionFailed)
					_, _ = w.Write([]byte(`<Error><Code>PreconditionFailed</Code><Message>exists</Message></Error>`))
				case http.MethodHead:
					w.Header().Set("Content-Length", fmt.Sprint(test.metadataSize))
				case http.MethodGet:
					w.(http.Flusher).Flush()
					_, _ = w.Write([]byte(test.body))
				default:
					http.Error(w, "unexpected method", http.StatusMethodNotAllowed)
				}
			}))
			defer server.Close()
			client, err := NewS3(S3Config{Endpoint: server.URL, Region: "us-east-1", Bucket: "backups", AccessKey: "access", SecretKey: "secret"})
			if err != nil {
				t.Fatal(err)
			}
			err = client.PutImmutable(context.Background(), "audit/batch.ndjson", contents, digest, time.Now().Add(time.Hour))
			if test.wantErr && err == nil {
				t.Fatal("conflicting immutable object was accepted")
			}
			if !test.wantErr && err != nil {
				t.Fatalf("identical immutable object rejected: %v", err)
			}
		})
	}
}
