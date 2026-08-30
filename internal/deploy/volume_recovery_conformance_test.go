package deploy

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/bendahma/dokploy-go/internal/ociref"
	"github.com/bendahma/dokploy-go/internal/volumeartifact"
	"github.com/google/uuid"
)

type volumeRecoveryEvidence struct {
	Status                    string  `json:"status"`
	SourceCommit              string  `json:"sourceCommit"`
	Image                     string  `json:"image"`
	ArtifactBytes             int64   `json:"artifactBytes"`
	EncryptedSHA256           string  `json:"encryptedSha256"`
	PlaintextSHA256           string  `json:"plaintextSha256"`
	BackupSeconds             float64 `json:"backupSeconds"`
	RTOSeconds                float64 `json:"rtoSeconds"`
	BackupQuiesced            bool    `json:"backupQuiesced"`
	RestoreQuiesced           bool    `json:"restoreQuiesced"`
	EncryptedArtifactVerified bool    `json:"encryptedArtifactVerified"`
	CorruptionReplaced        bool    `json:"corruptionReplaced"`
	PermissionsVerified       bool    `json:"permissionsVerified"`
	SymlinkVerified           bool    `json:"symlinkVerified"`
	WorkloadResumed           bool    `json:"workloadResumed"`
	RestartVerified           bool    `json:"restartVerified"`
}

func (e volumeRecoveryEvidence) validate() error {
	if e.Status != "passed" || !ociref.IsDigestPinned(e.Image) || e.ArtifactBytes <= 0 || !artifactSHA256.MatchString(e.EncryptedSHA256) || !artifactSHA256.MatchString(e.PlaintextSHA256) || e.BackupSeconds < 0 || e.RTOSeconds < 0 {
		return errors.New("invalid named-volume recovery evidence identity or measurements")
	}
	if !e.BackupQuiesced || !e.RestoreQuiesced || !e.EncryptedArtifactVerified || !e.CorruptionReplaced || !e.PermissionsVerified || !e.SymlinkVerified || !e.WorkloadResumed || !e.RestartVerified {
		return errors.New("named-volume recovery evidence has an unverified assertion")
	}
	return nil
}

// TestNamedVolumeRecoveryConformance is an opt-in release gate that exercises
// the production helper image through a real Swarm service. It proves that
// writers are quiesced, the encrypted artifact replaces corrupted data, and
// the mounting workload resumes and survives a restart.
func TestNamedVolumeRecoveryConformance(t *testing.T) {
	if os.Getenv("DOCKYARD_TEST_VOLUME_RECOVERY") != "1" {
		t.Skip("set DOCKYARD_TEST_VOLUME_RECOVERY=1 to run named-volume recovery conformance")
	}
	helperImage := strings.TrimSpace(os.Getenv("DOCKYARD_TEST_VOLUME_HELPER_IMAGE"))
	if !ociref.IsDigestPinned(helperImage) {
		t.Fatal("DOCKYARD_TEST_VOLUME_HELPER_IMAGE must be an immutable sha256 image reference")
	}
	if _, err := exec.LookPath("docker"); err != nil {
		t.Skip("docker is not installed")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Minute)
	defer cancel()

	initializedSwarm := strings.TrimSpace(volumeDocker(t, ctx, "info", "--format", "{{.Swarm.LocalNodeState}}")) != "active"
	if initializedSwarm {
		volumeDocker(t, ctx, "swarm", "init", "--advertise-addr", "127.0.0.1")
		t.Cleanup(func() { volumeDockerCleanup("swarm", "leave", "--force") })
	}

	runID := strings.ReplaceAll(uuid.NewString()[:8], "-", "")
	stackName := "volume-recovery-" + runID
	volumeName := stackName + "_data"
	networkName := stackName + "-network"
	workloadService := stackName + "_writer"
	helperService := stackName + "-controller"
	probeImage := "docker:29-cli@sha256:000bb62ff495f986c9f5578eb67cc2cb98b91138eda81d7762d5371eb8a497fe"

	volumeDocker(t, ctx, "pull", helperImage)
	volumeDocker(t, ctx, "pull", probeImage)
	volumeDocker(t, ctx, "network", "create", "--driver", "overlay", "--attachable", networkName)
	volumeDocker(t, ctx, "volume", "create", volumeName)
	t.Cleanup(func() {
		volumeDockerCleanup("service", "rm", workloadService, helperService)
		removeVolumeTestResources(networkName, volumeName, workloadService, helperService)
	})

	const marker = "orka-volume-recovery-ok"
	volumeDocker(t, ctx, "run", "--rm", "--entrypoint", "sh", "--mount", "type=volume,source="+volumeName+",target=/volume", probeImage, "-ec", "mkdir -p /volume/nested; printf '"+marker+"' >/volume/nested/data.txt; chmod 0640 /volume/nested/data.txt; ln -s nested/data.txt /volume/current")
	nodeID := strings.TrimSpace(volumeDocker(t, ctx, "info", "--format", "{{.Swarm.NodeID}}"))
	volumeDocker(t, ctx, "service", "create", "--detach", "--name", workloadService, "--label", "com.docker.stack.namespace="+stackName, "--constraint", "node.id=="+nodeID, "--mount", "type=volume,source="+volumeName+",target=/volume", "--entrypoint", "sh", probeImage, "-c", "while :; do sleep 60; done")
	volumeDocker(t, ctx, "service", "create", "--detach", "--with-registry-auth", "--name", helperService, "--constraint", "node.id=="+nodeID, "--entrypoint", "sh", helperImage, "-c", "while :; do sleep 60; done")
	waitVolumeReplicas(t, ctx, workloadService, "1/1")
	waitVolumeReplicas(t, ctx, helperService, "1/1")

	artifactPath := filepath.Join(t.TempDir(), "volume.tar.gz.enc")
	var backupQuiesced, restoreQuiesced atomic.Bool
	var backupObservation, restoreObservation atomic.Value
	transferURL, stopServer := volumeTransferServer(t, artifactPath, workloadService, &backupQuiesced, &restoreQuiesced, &backupObservation, &restoreObservation)
	defer stopServer()
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		t.Fatal(err)
	}
	aad := "volume-backup:" + uuid.NewString()
	runner := Swarm{DockerBin: "docker", ServiceName: helperService, Timeout: 5 * time.Minute}

	backupStarted := time.Now()
	backup, err := runner.RunVolumeArtifact(ctx, VolumeArtifactJob{Job: volumeartifact.Job{Mode: "backup", TransferURL: transferURL, EncryptionKey: base64.RawStdEncoding.EncodeToString(key), EncryptionAAD: aad}, VolumeName: volumeName, NodeID: nodeID, Network: networkName, StackName: stackName, Quiesce: true})
	if err != nil {
		t.Fatal(err)
	}
	backupSeconds := time.Since(backupStarted).Seconds()
	if !backupQuiesced.Load() {
		t.Fatalf("mounting workload was not quiesced during artifact upload: %v", backupObservation.Load())
	}
	waitVolumeReplicas(t, ctx, workloadService, "1/1")
	encrypted, err := os.ReadFile(artifactPath)
	if err != nil || int64(len(encrypted)) != backup.SizeBytes || bytes.Contains(encrypted, []byte(marker)) {
		t.Fatalf("encrypted artifact validation failed: bytes=%d expected=%d err=%v", len(encrypted), backup.SizeBytes, err)
	}

	volumeDocker(t, ctx, "service", "scale", "--detach=false", workloadService+"=0")
	volumeDocker(t, ctx, "run", "--rm", "--entrypoint", "sh", "--mount", "type=volume,source="+volumeName+",target=/volume", probeImage, "-ec", "rm -rf /volume/* /volume/.[!.]* /volume/..?*; printf corrupted >/volume/corrupt.txt")
	volumeDocker(t, ctx, "service", "scale", "--detach=false", workloadService+"=1")
	waitVolumeReplicas(t, ctx, workloadService, "1/1")

	restoreStarted := time.Now()
	restored, err := runner.RunVolumeArtifact(ctx, VolumeArtifactJob{Job: volumeartifact.Job{Mode: "restore", TransferURL: transferURL, EncryptionKey: base64.RawStdEncoding.EncodeToString(key), EncryptionAAD: aad, SHA256: backup.SHA256, PlaintextSHA256: backup.PlaintextSHA256, SizeBytes: backup.SizeBytes}, VolumeName: volumeName, NodeID: nodeID, Network: networkName, StackName: stackName, Quiesce: true})
	if err != nil {
		t.Fatal(err)
	}
	restoreSeconds := time.Since(restoreStarted).Seconds()
	if !restoreQuiesced.Load() {
		t.Fatalf("mounting workload was not quiesced during artifact download: %v", restoreObservation.Load())
	}
	if restored != backup {
		t.Fatalf("restore result=%#v backup=%#v", restored, backup)
	}
	waitVolumeReplicas(t, ctx, workloadService, "1/1")
	verifyVolumeContents(t, ctx, probeImage, volumeName, marker)
	volumeDocker(t, ctx, "service", "update", "--force", "--detach=false", workloadService)
	waitVolumeReplicas(t, ctx, workloadService, "1/1")
	verifyVolumeContents(t, ctx, probeImage, volumeName, marker)

	sourceCommit := os.Getenv("GITHUB_SHA")
	if sourceCommit == "" {
		sourceCommit = "local"
	}
	evidence := volumeRecoveryEvidence{
		Status: "passed", SourceCommit: sourceCommit, Image: helperImage,
		ArtifactBytes: backup.SizeBytes, EncryptedSHA256: backup.SHA256, PlaintextSHA256: backup.PlaintextSHA256,
		BackupSeconds: backupSeconds, RTOSeconds: restoreSeconds, BackupQuiesced: true, RestoreQuiesced: true,
		EncryptedArtifactVerified: true, CorruptionReplaced: true, PermissionsVerified: true, SymlinkVerified: true,
		WorkloadResumed: true, RestartVerified: true,
	}
	if err = evidence.validate(); err != nil {
		t.Fatal(err)
	}
	encoded, err := json.Marshal(evidence)
	if err != nil {
		t.Fatal(err)
	}
	evidenceFile := os.Getenv("DOCKYARD_VOLUME_RECOVERY_EVIDENCE")
	if evidenceFile == "" {
		evidenceFile = "volume-recovery-conformance.json"
	}
	if err = os.WriteFile(evidenceFile, append(encoded, '\n'), 0644); err != nil {
		t.Fatal(err)
	}
	t.Logf("VOLUME_RECOVERY_EVIDENCE %s", encoded)
}

func volumeTransferServer(t *testing.T, artifactPath, workloadService string, backupQuiesced, restoreQuiesced *atomic.Bool, backupObservation, restoreObservation *atomic.Value) (string, func()) {
	t.Helper()
	listener, err := net.Listen("tcp4", "0.0.0.0:0")
	if err != nil {
		t.Fatal(err)
	}
	server := &http.Server{ReadHeaderTimeout: 10 * time.Second, Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		desired, inspectErr := volumeDockerOutput(r.Context(), "service", "inspect", "--format", "{{.Spec.Mode.Replicated.Replicas}}", workloadService)
		running, tasksErr := volumeDockerOutput(r.Context(), "service", "ps", "--filter", "desired-state=running", "--format", "{{.ID}}", workloadService)
		observation := fmt.Sprintf("desired=%q running=%q inspectErr=%v tasksErr=%v", strings.TrimSpace(desired), strings.TrimSpace(running), inspectErr, tasksErr)
		quiesced := inspectErr == nil && tasksErr == nil && strings.TrimSpace(desired) == "0" && strings.TrimSpace(running) == ""
		switch r.Method {
		case http.MethodPut:
			backupQuiesced.Store(quiesced)
			backupObservation.Store(observation)
			temporary := artifactPath + ".upload"
			file, createErr := os.OpenFile(temporary, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0600)
			if createErr != nil {
				http.Error(w, createErr.Error(), http.StatusInternalServerError)
				return
			}
			written, copyErr := io.Copy(file, io.LimitReader(r.Body, 1<<30))
			closeErr := file.Close()
			if copyErr != nil || closeErr != nil || written != r.ContentLength || os.Rename(temporary, artifactPath) != nil {
				http.Error(w, "artifact upload failed", http.StatusInternalServerError)
				return
			}
			w.WriteHeader(http.StatusNoContent)
		case http.MethodGet:
			restoreQuiesced.Store(quiesced)
			restoreObservation.Store(observation)
			http.ServeFile(w, r, artifactPath)
		default:
			w.WriteHeader(http.StatusMethodNotAllowed)
		}
	})}
	go func() { _ = server.Serve(listener) }()
	gateway := strings.TrimSpace(volumeDocker(t, context.Background(), "network", "inspect", "--format", "{{(index .IPAM.Config 0).Gateway}}", "docker_gwbridge"))
	port := listener.Addr().(*net.TCPAddr).Port
	return "http://" + net.JoinHostPort(gateway, strconv.Itoa(port)) + "/artifact", func() {
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = server.Shutdown(shutdownCtx)
	}
}

func verifyVolumeContents(t *testing.T, ctx context.Context, image, volumeName, marker string) {
	t.Helper()
	output := volumeDocker(t, ctx, "run", "--rm", "--entrypoint", "sh", "--mount", "type=volume,source="+volumeName+",target=/volume", image, "-ec", "test ! -e /volume/corrupt.txt; test \"$(cat /volume/nested/data.txt)\" = '"+marker+"'; test \"$(readlink /volume/current)\" = nested/data.txt; test \"$(stat -c %a /volume/nested/data.txt)\" = 640; printf verified")
	if strings.TrimSpace(output) != "verified" {
		t.Fatalf("unexpected volume verification output %q", output)
	}
}

func waitVolumeReplicas(t *testing.T, ctx context.Context, service, expected string) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Minute)
	for time.Now().Before(deadline) {
		output, err := volumeDockerOutput(ctx, "service", "ls", "--filter", "name="+service, "--format", "{{.Replicas}}")
		if err == nil && strings.TrimSpace(output) == expected {
			return
		}
		time.Sleep(time.Second)
	}
	output, _ := volumeDockerOutput(ctx, "service", "ps", "--no-trunc", service)
	t.Fatalf("service %s did not reach %s:\n%s", service, expected, output)
}

func waitVolumeServicesGone(services ...string) {
	deadline := time.Now().Add(30 * time.Second)
	for time.Now().Before(deadline) {
		allGone := true
		for _, service := range services {
			if output, _ := volumeDockerOutput(context.Background(), "service", "ls", "--filter", "name="+service, "--format", "{{.Name}}"); strings.TrimSpace(output) != "" {
				allGone = false
			}
		}
		if allGone {
			return
		}
		time.Sleep(250 * time.Millisecond)
	}
}

func removeVolumeTestResources(networkName, volumeName string, services ...string) {
	waitVolumeServicesGone(services...)
	deadline := time.Now().Add(30 * time.Second)
	networkRemoved, volumeRemoved := false, false
	for time.Now().Before(deadline) && (!networkRemoved || !volumeRemoved) {
		if !networkRemoved {
			_, err := volumeDockerOutput(context.Background(), "network", "rm", networkName)
			networkRemoved = err == nil
		}
		if !volumeRemoved {
			_, err := volumeDockerOutput(context.Background(), "volume", "rm", volumeName)
			volumeRemoved = err == nil
		}
		if !networkRemoved || !volumeRemoved {
			time.Sleep(500 * time.Millisecond)
		}
	}
}

func volumeDocker(t *testing.T, ctx context.Context, args ...string) string {
	t.Helper()
	output, err := volumeDockerOutput(ctx, args...)
	if err != nil {
		t.Fatalf("docker %s: %v\n%s", strings.Join(args, " "), err, output)
	}
	return output
}

func volumeDockerOutput(ctx context.Context, args ...string) (string, error) {
	output, err := exec.CommandContext(ctx, "docker", args...).CombinedOutput()
	return string(output), err
}

func volumeDockerCleanup(args ...string) {
	cleanupCtx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	_, _ = volumeDockerOutput(cleanupCtx, args...)
}

func TestVolumeRecoveryEvidenceContract(t *testing.T) {
	evidence := volumeRecoveryEvidence{
		Status: "passed", SourceCommit: "local", Image: "registry.example/orka@sha256:" + strings.Repeat("a", 64),
		ArtifactBytes: 42, EncryptedSHA256: strings.Repeat("b", 64), PlaintextSHA256: strings.Repeat("c", 64), BackupSeconds: 1, RTOSeconds: 2,
		BackupQuiesced: true, RestoreQuiesced: true, EncryptedArtifactVerified: true, CorruptionReplaced: true,
		PermissionsVerified: true, SymlinkVerified: true, WorkloadResumed: true, RestartVerified: true,
	}
	if err := evidence.validate(); err != nil {
		t.Fatal(err)
	}
	evidence.RestoreQuiesced = false
	if err := evidence.validate(); err == nil {
		t.Fatal("incomplete recovery evidence passed validation")
	}
}
