package backup

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestS3ConfigurationAndObjectKey(t *testing.T) {
	client, err := NewS3(S3Config{Endpoint: "https://objects.example.test", Bucket: "backups", Prefix: "/tenant/database/", UseTLS: true, AccessKey: "access", SecretKey: "secret"})
	if err != nil {
		t.Fatal(err)
	}
	if got := client.ObjectKey("backup.dump"); got != "tenant/database/backup.dump" {
		t.Fatalf("object key = %q", got)
	}
	for _, config := range []S3Config{
		{Endpoint: "ftp://example.test", Bucket: "backups", AccessKey: "a", SecretKey: "s"},
		{Endpoint: "https://example.test/path", Bucket: "backups", UseTLS: true, AccessKey: "a", SecretKey: "s"},
		{Endpoint: "http://example.test", Bucket: "backups", UseTLS: true, AccessKey: "a", SecretKey: "s"},
		{Endpoint: "http://example.test", Bucket: "", AccessKey: "a", SecretKey: "s"},
	} {
		if _, err = NewS3(config); err == nil {
			t.Fatalf("expected invalid config rejection: %#v", config)
		}
	}
	for _, endpoint := range []string{"https://user@objects.example.test", "https://objects.example.test?token=secret", "https://objects.example.test/#fragment"} {
		if _, err = NewS3(S3Config{Endpoint: endpoint, Bucket: "backups", UseTLS: true, AccessKey: "access", SecretKey: "secret"}); err == nil {
			t.Errorf("unsafe endpoint %q was accepted", endpoint)
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
