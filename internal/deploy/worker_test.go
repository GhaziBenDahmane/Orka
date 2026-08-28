package deploy

import (
	"os"
	"path/filepath"
	"testing"
)

func TestChecksumFileStreamsContent(t *testing.T) {
	path := filepath.Join(t.TempDir(), "backup.dump")
	if err := os.WriteFile(path, []byte("dockyard\n"), 0600); err != nil {
		t.Fatal(err)
	}
	sum, size, err := checksumFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if size != 9 {
		t.Fatalf("size = %d, want 9", size)
	}
	if sum != "96d9d15068389c532b968b3b106186d5f93e2375969694df105e647228fef291" {
		t.Fatalf("unexpected checksum %q", sum)
	}
}

func TestChecksumFileMissing(t *testing.T) {
	if _, _, err := checksumFile(filepath.Join(t.TempDir(), "missing")); err == nil {
		t.Fatal("expected an error")
	}
}
