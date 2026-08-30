package backup

import (
	"errors"
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
