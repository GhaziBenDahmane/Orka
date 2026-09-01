package deploy

import (
	"encoding/base64"
	"strings"
	"testing"

	"github.com/GhaziBenDahmane/Orka/internal/volumeartifact"
)

func validRemoteArtifactJob() RemoteArtifactJob {
	return RemoteArtifactJob{
		Mode:            "download",
		Network:         "database_default",
		Image:           "postgres@sha256:" + strings.Repeat("a", 64),
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

func TestValidateRemoteArtifactResult(t *testing.T) {
	job := validRemoteArtifactJob()
	valid := RemoteArtifactResult{SHA256: job.SHA256, PlaintextSHA256: job.PlaintextSHA256, SizeBytes: job.SizeBytes}
	if err := ValidateRemoteArtifactResult(job, valid); err != nil {
		t.Fatalf("valid result rejected: %v", err)
	}
	for name, mutate := range map[string]func(*RemoteArtifactResult){
		"size":             func(result *RemoteArtifactResult) { result.SizeBytes++ },
		"encrypted digest": func(result *RemoteArtifactResult) { result.SHA256 = strings.Repeat("c", 64) },
		"plaintext digest": func(result *RemoteArtifactResult) { result.PlaintextSHA256 = strings.Repeat("c", 64) },
		"invalid digest":   func(result *RemoteArtifactResult) { result.SHA256 = strings.Repeat("z", 64) },
	} {
		t.Run(name, func(t *testing.T) {
			result := valid
			mutate(&result)
			if err := ValidateRemoteArtifactResult(job, result); err == nil {
				t.Fatal("untrusted result was accepted")
			}
		})
	}
	upload := job
	upload.Mode, upload.SHA256, upload.PlaintextSHA256, upload.SizeBytes = "upload", "", "", 0
	if err := ValidateRemoteArtifactResult(upload, RemoteArtifactResult{SHA256: strings.Repeat("c", 64), PlaintextSHA256: strings.Repeat("d", 64), SizeBytes: 42}); err != nil {
		t.Fatalf("valid upload result rejected: %v", err)
	}
}

func TestValidateRemoteVolumeAndDatabaseTransferResults(t *testing.T) {
	volumeJob := VolumeArtifactJob{Job: volumeartifact.Job{Mode: "restore", SHA256: strings.Repeat("a", 64), PlaintextSHA256: strings.Repeat("b", 64), SizeBytes: 42}}
	volumeResult := volumeartifact.Result{SHA256: volumeJob.SHA256, PlaintextSHA256: volumeJob.PlaintextSHA256, SizeBytes: volumeJob.SizeBytes}
	if err := ValidateVolumeArtifactResult(volumeJob, volumeResult); err != nil {
		t.Fatalf("valid volume result rejected: %v", err)
	}
	volumeResult.SizeBytes++
	if err := ValidateVolumeArtifactResult(volumeJob, volumeResult); err == nil {
		t.Fatal("mismatched volume restore result was accepted")
	}
	if err := ValidateDatabaseTransferResult(DatabaseTransferResult{SHA256: strings.Repeat("a", 64), SizeBytes: 42}); err != nil {
		t.Fatalf("valid database transfer result rejected: %v", err)
	}
	if err := ValidateDatabaseTransferResult(DatabaseTransferResult{SHA256: strings.Repeat("z", 64), SizeBytes: 42}); err == nil {
		t.Fatal("invalid database transfer result was accepted")
	}
}

func TestValidateRemoteResolvedUtilityImageBindsRequestedIdentity(t *testing.T) {
	digestA := "sha256:" + strings.Repeat("a", 64)
	digestB := "sha256:" + strings.Repeat("b", 64)

	resolved, err := validateRemoteResolvedUtilityImage("postgres:17", " docker.io/library/postgres@"+digestA+"\n")
	if err != nil || resolved != "postgres@"+digestA {
		t.Fatalf("canonical repository alias rejected: resolved=%q err=%v", resolved, err)
	}
	if _, err = validateRemoteResolvedUtilityImage("postgres:17", "docker.io/library/mysql@"+digestA); err == nil || !strings.Contains(err.Error(), "different repository") {
		t.Fatalf("different repository accepted: %v", err)
	}
	if _, err = validateRemoteResolvedUtilityImage("postgres@"+digestA, "postgres@"+digestB); err == nil || !strings.Contains(err.Error(), "different digest") {
		t.Fatalf("changed pinned digest accepted: %v", err)
	}
	if resolved, err = validateRemoteResolvedUtilityImage("postgres@"+digestA, "postgres@"+digestA); err != nil || resolved != "postgres@"+digestA {
		t.Fatalf("matching pinned image rejected: resolved=%q err=%v", resolved, err)
	}
	for _, invalid := range []string{"postgres:17", "not an image", ""} {
		if _, err = validateRemoteResolvedUtilityImage("postgres:17", invalid); err == nil {
			t.Fatalf("invalid agent resolution %q accepted", invalid)
		}
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
