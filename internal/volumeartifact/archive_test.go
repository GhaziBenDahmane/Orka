package volumeartifact

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"os"
	"path/filepath"
	"testing"
)

func TestArchiveRestoreReplacesVolumeAndPreservesSafeSymlink(t *testing.T) {
	source, target := filepath.Join(t.TempDir(), "source"), filepath.Join(t.TempDir(), "target")
	if err := os.MkdirAll(filepath.Join(source, "nested"), 0750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(source, "nested", "data.txt"), []byte("durable data"), 0640); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("nested/data.txt", filepath.Join(source, "current")); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(target, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(target, "stale"), []byte("remove me"), 0600); err != nil {
		t.Fatal(err)
	}
	var archive bytes.Buffer
	if err := WriteArchive(&archive, source); err != nil {
		t.Fatal(err)
	}
	reader := bytes.NewReader(archive.Bytes())
	if err := RestoreArchive(reader, target); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(filepath.Join(target, "current"))
	if err != nil || string(data) != "durable data" {
		t.Fatalf("restored data=%q err=%v", data, err)
	}
	if _, err = os.Stat(filepath.Join(target, "stale")); !os.IsNotExist(err) {
		t.Fatalf("stale volume data survived restore: %v", err)
	}
}

func TestRestoreRejectsTraversalBeforeChangingVolume(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "live"), []byte("unchanged"), 0600); err != nil {
		t.Fatal(err)
	}
	var payload bytes.Buffer
	gz := gzip.NewWriter(&payload)
	tw := tar.NewWriter(gz)
	if err := tw.WriteHeader(&tar.Header{Name: "../escape", Typeflag: tar.TypeReg, Mode: 0600, Size: 4}); err != nil {
		t.Fatal(err)
	}
	_, _ = tw.Write([]byte("evil"))
	_ = tw.Close()
	_ = gz.Close()
	if err := RestoreArchive(bytes.NewReader(payload.Bytes()), root); err == nil {
		t.Fatal("path traversal archive was accepted")
	}
	data, err := os.ReadFile(filepath.Join(root, "live"))
	if err != nil || string(data) != "unchanged" {
		t.Fatalf("live data changed after rejected archive: %q %v", data, err)
	}
}

func TestArchiveRejectsEscapingSymlinkAndSpecialFile(t *testing.T) {
	root := t.TempDir()
	if err := os.Symlink("../outside", filepath.Join(root, "escape")); err != nil {
		t.Fatal(err)
	}
	if err := WriteArchive(&bytes.Buffer{}, root); err == nil {
		t.Fatal("escaping symlink was archived")
	}
}
