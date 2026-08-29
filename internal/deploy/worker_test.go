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

func TestWritePlanFilesUsesPrivatePermissions(t *testing.T) {
	directory := t.TempDir()
	if err := writePlanFiles(directory, map[string]string{"credentials.yml": "password: secret\n"}); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(filepath.Join(directory, "credentials.yml"))
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0600 {
		t.Fatalf("permissions = %o", info.Mode().Perm())
	}
	if err = writePlanFiles(directory, map[string]string{"../escape": "bad"}); err == nil {
		t.Fatal("expected path traversal rejection")
	}
	if err = writePlanFiles(directory, map[string]string{`..\escape`: "bad"}); err == nil {
		t.Fatal("expected portable path traversal rejection")
	}
}

func TestWritePlanFilesDoesNotOverwriteAndRollsBack(t *testing.T) {
	directory := t.TempDir()
	collision := filepath.Join(directory, "existing.conf")
	if err := os.WriteFile(collision, []byte("preserve"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := writePlanFiles(directory, map[string]string{"aaa.conf": "temporary", "existing.conf": "overwrite"}); err == nil {
		t.Fatal("expected existing helper file rejection")
	}
	contents, err := os.ReadFile(collision)
	if err != nil || string(contents) != "preserve" {
		t.Fatalf("existing file changed: contents=%q err=%v", contents, err)
	}
	if _, err = os.Stat(filepath.Join(directory, "aaa.conf")); !os.IsNotExist(err) {
		t.Fatalf("partially-created helper file was not rolled back: %v", err)
	}
}
