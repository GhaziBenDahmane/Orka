package deploy

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"github.com/GhaziBenDahmane/Orka/internal/cryptox"
	"github.com/google/uuid"
)

func TestBackupFileEncryptionRoundTrip(t *testing.T) {
	directory := t.TempDir()
	source := filepath.Join(directory, "backup.dump")
	encrypted := source + ".enc"
	restored := filepath.Join(directory, "restored.dump")
	plaintext := bytes.Repeat([]byte("database-row\n"), 10000)
	if err := os.WriteFile(source, plaintext, 0600); err != nil {
		t.Fatal(err)
	}
	box, _ := cryptox.New(bytes.Repeat([]byte{7}, 32))
	backupID := uuid.New()
	if err := encryptBackupFile(box, source, encrypted, backupID); err != nil {
		t.Fatal(err)
	}
	ciphertext, err := os.ReadFile(encrypted)
	if err != nil || bytes.Contains(ciphertext, []byte("database-row")) {
		t.Fatalf("artifact was not encrypted: %v", err)
	}
	if err = decryptBackupFile(box, encrypted, restored, backupID); err != nil {
		t.Fatal(err)
	}
	result, err := os.ReadFile(restored)
	if err != nil || !bytes.Equal(result, plaintext) {
		t.Fatalf("restored artifact mismatch: %v", err)
	}
	if err = decryptBackupFile(box, encrypted, filepath.Join(directory, "wrong.dump"), uuid.New()); err == nil {
		t.Fatal("backup context mismatch was accepted")
	}
}
