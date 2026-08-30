package deploy

import (
	"encoding/base64"
	"strings"
	"testing"
)

func validRemoteArtifactJob() RemoteArtifactJob {
	return RemoteArtifactJob{
		Mode:            "download",
		Network:         "database_default",
		Image:           "postgres:17",
		Command:         []string{"pg_restore", "backup.dump"},
		ArtifactName:    "backup.dump",
		TransferURL:     "https://objects.example.test/backups/object?signature=value",
		EncryptionKey:   base64.RawStdEncoding.EncodeToString(make([]byte, 32)),
		EncryptionAAD:   "database-backup:test",
		SHA256:          strings.Repeat("a", 64),
		PlaintextSHA256: strings.Repeat("b", 64),
		SizeBytes:       1024,
	}
}

func TestValidateRemoteArtifactJobRequiresTrustedTransferMetadata(t *testing.T) {
	if err := ValidateRemoteArtifactJob(validRemoteArtifactJob()); err != nil {
		t.Fatalf("valid download rejected: %v", err)
	}
	upload := validRemoteArtifactJob()
	upload.Mode, upload.SHA256, upload.PlaintextSHA256, upload.SizeBytes = "upload", "", "", 0
	if err := ValidateRemoteArtifactJob(upload); err != nil {
		t.Fatalf("valid upload rejected: %v", err)
	}
	tests := map[string]func(*RemoteArtifactJob){
		"URL scheme":       func(job *RemoteArtifactJob) { job.TransferURL = "file:///tmp/artifact" },
		"URL credentials":  func(job *RemoteArtifactJob) { job.TransferURL = "https://user:secret@objects.example.test/object" },
		"URL fragment":     func(job *RemoteArtifactJob) { job.TransferURL += "#ignored" },
		"URL invalid host": func(job *RemoteArtifactJob) { job.TransferURL = "https://bad_label.example.test/object" },
		"URL invalid port": func(job *RemoteArtifactJob) { job.TransferURL = "https://objects.example.test:65536/object" },
		"URL too long": func(job *RemoteArtifactJob) {
			job.TransferURL = "https://objects.example.test/" + strings.Repeat("a", maxRemoteArtifactTransferURLBytes)
		},
		"encryption key":   func(job *RemoteArtifactJob) { job.EncryptionKey = "invalid" },
		"encryption AAD":   func(job *RemoteArtifactJob) { job.EncryptionAAD = "" },
		"oversized AAD":    func(job *RemoteArtifactJob) { job.EncryptionAAD = strings.Repeat("a", maxRemoteArtifactAADBytes+1) },
		"encrypted digest": func(job *RemoteArtifactJob) { job.SHA256 = strings.Repeat("z", 64) },
		"plaintext digest": func(job *RemoteArtifactJob) { job.PlaintextSHA256 = strings.Repeat("z", 64) },
		"artifact size":    func(job *RemoteArtifactJob) { job.SizeBytes = 0 },
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			job := validRemoteArtifactJob()
			mutate(&job)
			if err := ValidateRemoteArtifactJob(job); err == nil {
				t.Fatal("invalid remote artifact job was accepted")
			}
		})
	}
}
