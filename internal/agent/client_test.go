package agent

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/bendahma/dokploy-go/internal/agentpki"
	"github.com/bendahma/dokploy-go/internal/cryptox"
	"github.com/bendahma/dokploy-go/internal/database"
	"github.com/bendahma/dokploy-go/internal/deploy"
	"github.com/google/uuid"
)

type fakeScheduler struct {
	stack, compose     string
	environment        map[string]string
	registryCredential *deploy.Credential
	artifact           []byte
	wantArtifact       []byte
	nodes              []deploy.Node
	transfer           *deploy.DatabaseTransferJob
	status             deploy.StackStatus
	containerCalls     int
}

func TestRotateCertificateValidatesBeforeAtomicIdentityReplacement(t *testing.T) {
	now := time.Now().UTC()
	caPEM, caKey, err := agentpki.NewCA(now, 24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	clusterID := uuid.New()
	newState := func(t *testing.T) (string, []byte) {
		t.Helper()
		directory := t.TempDir()
		key, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			t.Fatal(err)
		}
		csr, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{Subject: pkix.Name{CommonName: "dockyard-agent"}}, key)
		if err != nil {
			t.Fatal(err)
		}
		certificate, _, err := agentpki.SignAgentCSR(caPEM, caKey, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csr}), clusterID, now.Add(-50*time.Minute), time.Hour)
		if err != nil {
			t.Fatal(err)
		}
		identity := append(append([]byte{}, certificate...), pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})...)
		certPath, _, caPath := identityPaths(directory)
		if err = writeIdentityFile(certPath, identity, 0600); err == nil {
			err = writeIdentityFile(caPath, caPEM, 0644)
		}
		if err != nil {
			t.Fatal(err)
		}
		return directory, identity
	}
	rotationServer := func(t *testing.T, certificateCluster uuid.UUID, signerCertificate, signerKey []byte, issuedAt time.Time, mismatchKey bool) *httptest.Server {
		t.Helper()
		return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			var input struct {
				CSR string `json:"csr"`
			}
			if err := json.NewDecoder(r.Body).Decode(&input); err != nil {
				t.Error(err)
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			csr := []byte(input.CSR)
			if mismatchKey {
				key, keyErr := rsa.GenerateKey(rand.Reader, 2048)
				if keyErr != nil {
					t.Error(keyErr)
					w.WriteHeader(http.StatusInternalServerError)
					return
				}
				request, requestErr := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{Subject: pkix.Name{CommonName: "other-agent"}}, key)
				if requestErr != nil {
					t.Error(requestErr)
					w.WriteHeader(http.StatusInternalServerError)
					return
				}
				csr = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: request})
			}
			certificate, _, err := agentpki.SignAgentCSR(signerCertificate, signerKey, csr, certificateCluster, issuedAt, 7*24*time.Hour)
			if err != nil {
				t.Error(err)
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			_ = json.NewEncoder(w).Encode(map[string]string{"certificate": string(certificate)})
		}))
	}
	t.Run("valid replacement", func(t *testing.T) {
		directory, original := newState(t)
		server := rotationServer(t, clusterID, caPEM, caKey, time.Now(), false)
		defer server.Close()
		if _, err := rotateIfNeeded(context.Background(), Config{StateDirectory: directory, AgentURL: server.URL}, server.Client()); err != nil {
			t.Fatal(err)
		}
		updated, err := os.ReadFile(filepath.Join(directory, "identity.pem"))
		if err != nil || bytes.Equal(updated, original) {
			t.Fatalf("identity was not replaced: err=%v", err)
		}
		if _, err = tls.LoadX509KeyPair(filepath.Join(directory, "identity.pem"), filepath.Join(directory, "identity.pem")); err != nil {
			t.Fatalf("saved replacement identity is invalid: %v", err)
		}
	})
	t.Run("wrong cluster identity", func(t *testing.T) {
		directory, original := newState(t)
		server := rotationServer(t, uuid.New(), caPEM, caKey, time.Now(), false)
		defer server.Close()
		current := server.Client()
		preservedClient, err := rotateIfNeeded(context.Background(), Config{StateDirectory: directory, AgentURL: server.URL}, current)
		if err == nil || !strings.Contains(err.Error(), "changed the cluster identity") {
			t.Fatalf("rotation error=%v", err)
		}
		if preservedClient != current {
			t.Fatal("rotation failure did not preserve the working HTTP client")
		}
		preserved, readErr := os.ReadFile(filepath.Join(directory, "identity.pem"))
		if readErr != nil || !bytes.Equal(preserved, original) {
			t.Fatalf("current identity changed after rejected rotation: err=%v", readErr)
		}
	})
	assertRejected := func(t *testing.T, server *httptest.Server, want string) {
		t.Helper()
		defer server.Close()
		directory, original := newState(t)
		current := server.Client()
		preservedClient, rotationErr := rotateIfNeeded(context.Background(), Config{StateDirectory: directory, AgentURL: server.URL}, current)
		if rotationErr == nil || !strings.Contains(rotationErr.Error(), want) {
			t.Fatalf("rotation error=%v, want substring %q", rotationErr, want)
		}
		if preservedClient != current {
			t.Fatal("rotation failure did not preserve the working HTTP client")
		}
		preserved, readErr := os.ReadFile(filepath.Join(directory, "identity.pem"))
		if readErr != nil || !bytes.Equal(preserved, original) {
			t.Fatalf("current identity changed after rejected rotation: err=%v", readErr)
		}
	}
	t.Run("untrusted authority", func(t *testing.T) {
		untrustedCA, untrustedKey, caErr := agentpki.NewCA(now, 24*time.Hour)
		if caErr != nil {
			t.Fatal(caErr)
		}
		assertRejected(t, rotationServer(t, clusterID, untrustedCA, untrustedKey, time.Now(), false), "verify rotated agent certificate")
	})
	t.Run("expired replacement", func(t *testing.T) {
		assertRejected(t, rotationServer(t, clusterID, caPEM, caKey, time.Now().Add(-8*24*time.Hour), false), "verify rotated agent certificate")
	})
	t.Run("mismatched private key", func(t *testing.T) {
		assertRejected(t, rotationServer(t, clusterID, caPEM, caKey, time.Now(), true), "does not match the generated private key")
	})
}

func TestHeartbeatMigratesAgentToNewCertificateAuthority(t *testing.T) {
	now := time.Now().UTC()
	oldCA, oldCAKey, err := agentpki.NewCA(now, 48*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	newCA, newCAKey, err := agentpki.NewCA(now, 48*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	clusterID := uuid.New()
	state := t.TempDir()
	oldKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	oldCSR, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{Subject: pkix.Name{CommonName: "dockyard-agent"}}, oldKey)
	if err != nil {
		t.Fatal(err)
	}
	oldCertificate, _, err := agentpki.SignAgentCSR(oldCA, oldCAKey, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: oldCSR}), clusterID, now, 24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	identity := append(append([]byte{}, oldCertificate...), pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(oldKey)})...)
	certPath, _, caPath := identityPaths(state)
	if err = writeIdentityFile(certPath, identity, 0600); err == nil {
		err = writeIdentityFile(caPath, oldCA, 0644)
	}
	if err != nil {
		t.Fatal(err)
	}
	bundle := append(append([]byte{}, newCA...), oldCA...)
	rotationCalls := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/agent/heartbeat":
			_ = json.NewEncoder(w).Encode(map[string]string{"caCertificate": string(bundle), "signingCaCertificate": string(newCA)})
		case "/v1/agent/rotate":
			rotationCalls++
			var input struct {
				CSR string `json:"csr"`
			}
			if err := json.NewDecoder(r.Body).Decode(&input); err != nil {
				t.Error(err)
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			certificate, _, signErr := agentpki.SignAgentCSR(newCA, newCAKey, []byte(input.CSR), clusterID, time.Now(), 24*time.Hour)
			if signErr != nil {
				t.Error(signErr)
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			_ = json.NewEncoder(w).Encode(map[string]string{"certificate": string(certificate), "caCertificate": string(bundle), "signingCaCertificate": string(newCA)})
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()
	client := &Client{cfg: Config{StateDirectory: state, AgentURL: server.URL, Version: "test"}, http: server.Client(), swarm: &fakeScheduler{}}
	if err := client.heartbeat(context.Background()); err != nil {
		t.Fatal(err)
	}
	if rotationCalls != 1 {
		t.Fatalf("rotation calls=%d, want 1", rotationCalls)
	}
	pair, err := tls.LoadX509KeyPair(certPath, certPath)
	if err != nil {
		t.Fatal(err)
	}
	rotated, err := x509.ParseCertificate(pair.Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	_, activeAuthorities, err := agentpki.ValidateTrustBundle(newCA, time.Now())
	if err != nil || rotated.CheckSignatureFrom(activeAuthorities[0]) != nil {
		t.Fatalf("replacement was not signed by the active CA: %v", err)
	}
	savedBundle, err := os.ReadFile(caPath)
	if err != nil {
		t.Fatal(err)
	}
	if _, authorities, err := agentpki.ValidateTrustBundle(savedBundle, time.Now()); err != nil || len(authorities) != 2 {
		t.Fatalf("saved trust authorities=%d err=%v", len(authorities), err)
	}
}

func (f *fakeScheduler) Status(context.Context, string) (deploy.StackStatus, error) {
	return f.status, nil
}

func (f *fakeScheduler) RunDatabaseTransfer(_ context.Context, job deploy.DatabaseTransferJob) (deploy.DatabaseTransferResult, error) {
	f.transfer = &job
	return deploy.DatabaseTransferResult{SHA256: strings.Repeat("a", 64), SizeBytes: 42, Output: "restored"}, nil
}

func (f *fakeScheduler) Deploy(_ context.Context, stack, compose string, environment map[string]string, registryCredential *deploy.Credential) (string, error) {
	f.stack, f.compose, f.environment, f.registryCredential = stack, compose, environment, registryCredential
	return "deployed", nil
}
func (*fakeScheduler) Remove(context.Context, string) (string, error)        { return "", nil }
func (*fakeScheduler) RemoveVolumes(context.Context, string) (string, error) { return "", nil }
func (*fakeScheduler) Logs(context.Context, string, int) (string, error)     { return "", nil }
func (f *fakeScheduler) Nodes(context.Context) ([]deploy.Node, error)        { return f.nodes, nil }
func (f *fakeScheduler) RunContainerJob(_ context.Context, _, _, mount string, _ map[string]string, command []string) (string, error) {
	f.containerCalls++
	if f.artifact != nil {
		return "dumped", os.WriteFile(filepath.Join(mount, command[len(command)-1]), f.artifact, 0600)
	}
	if f.wantArtifact != nil {
		actual, err := os.ReadFile(filepath.Join(mount, command[len(command)-1]))
		if err != nil {
			return "", err
		}
		if !bytes.Equal(actual, f.wantArtifact) {
			return "", errors.New("restored artifact mismatch")
		}
		return "restored", nil
	}
	return "", errors.New("unused")
}

func TestExecuteArtifactJobRejectsUnsafePlansBeforeFilesystemOrDocker(t *testing.T) {
	state := t.TempDir()
	key := base64.RawStdEncoding.EncodeToString(bytes.Repeat([]byte{7}, 32))
	tests := map[string]deploy.RemoteArtifactJob{
		"traversal":   {Mode: "upload", Network: "db_default", Image: "postgres:17", Command: []string{"pg_dump", "backup.dump"}, ArtifactName: "backup.dump", EncryptionKey: key, Files: map[string]string{"../../escape": "secret"}},
		"backslash":   {Mode: "upload", Network: "db_default", Image: "postgres:17", Command: []string{"pg_dump", "backup.dump"}, ArtifactName: "backup.dump", EncryptionKey: key, Files: map[string]string{`..\escape`: "secret"}},
		"environment": {Mode: "upload", Network: "db_default", Image: "postgres:17", Command: []string{"pg_dump", "backup.dump"}, ArtifactName: "backup.dump", EncryptionKey: key, Environment: map[string]string{"BAD-NAME": "secret"}},
		"command":     {Mode: "upload", Network: "db_default", Image: "postgres:17", Command: []string{"pg_dump", ""}, ArtifactName: "backup.dump", EncryptionKey: key},
	}
	for name, job := range tests {
		t.Run(name, func(t *testing.T) {
			scheduler := &fakeScheduler{}
			client := &Client{cfg: Config{StateDirectory: state}, swarm: scheduler}
			payload, _ := json.Marshal(job)
			if _, err := client.executeCommand(context.Background(), command{Kind: "database.utility", Payload: payload}); err == nil {
				t.Fatal("expected unsafe remote plan rejection")
			}
			if scheduler.containerCalls != 0 {
				t.Fatalf("Docker was called %d times", scheduler.containerCalls)
			}
			entries, err := os.ReadDir(state)
			if err != nil || len(entries) != 0 {
				t.Fatalf("remote plan touched agent filesystem: entries=%v err=%v", entries, err)
			}
		})
	}
}

func TestExecuteDatabaseTransferRejectsUnsafePlanBeforeDispatch(t *testing.T) {
	scheduler := &fakeScheduler{}
	job := deploy.DatabaseTransferJob{Network: "db_default", ArtifactName: "migration.dump", Backup: database.BackupPlan{Image: "postgres:17", Command: []string{"pg_dump"}, Files: map[string]string{"/escape": "secret"}}, Restore: database.RestorePlan{Image: "postgres:17", Command: []string{"pg_restore"}}}
	payload, _ := json.Marshal(job)
	if _, err := (&Client{swarm: scheduler}).executeCommand(context.Background(), command{Kind: "database.transfer", Payload: payload}); err == nil {
		t.Fatal("expected unsafe database transfer rejection")
	}
	if scheduler.transfer != nil {
		t.Fatal("unsafe transfer was dispatched")
	}
}

func TestExecuteArtifactJobEncryptsUploadAndDecryptsDownload(t *testing.T) {
	plaintxt := []byte("remote database backup")
	var stored []byte
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPut {
			stored, _ = io.ReadAll(r.Body)
			w.WriteHeader(http.StatusNoContent)
			return
		}
		_, _ = w.Write(stored)
	}))
	defer server.Close()
	key := bytes.Repeat([]byte{9}, 32)
	upload := deploy.RemoteArtifactJob{Mode: "upload", Network: "db_default", Image: "postgres", Command: []string{"pg_dump", "backup.dump"}, ArtifactName: "backup.dump", TransferURL: server.URL, EncryptionKey: base64.RawStdEncoding.EncodeToString(key), EncryptionAAD: "database-backup:test"}
	payload, _ := json.Marshal(upload)
	client := &Client{cfg: Config{StateDirectory: t.TempDir()}, swarm: &fakeScheduler{artifact: plaintxt}}
	encoded, err := client.executeCommand(context.Background(), command{Kind: "database.utility", Payload: payload})
	if err != nil || bytes.Contains(stored, plaintxt) {
		t.Fatalf("upload err=%v encrypted=%q", err, stored)
	}
	var result deploy.RemoteArtifactResult
	if err = json.Unmarshal([]byte(encoded), &result); err != nil || result.SHA256 == "" || result.PlaintextSHA256 == "" {
		t.Fatalf("result=%q err=%v", encoded, err)
	}

	download := upload
	download.Mode = "download"
	download.SHA256 = result.SHA256
	download.PlaintextSHA256 = result.PlaintextSHA256
	payload, _ = json.Marshal(download)
	client.swarm = &fakeScheduler{wantArtifact: plaintxt}
	if _, err = client.executeCommand(context.Background(), command{Kind: "database.utility", Payload: payload}); err != nil {
		t.Fatal(err)
	}
	box, _ := cryptox.New(key)
	var decoded bytes.Buffer
	if err = box.DecryptStream(&decoded, bytes.NewReader(stored), upload.EncryptionAAD); err != nil || !bytes.Equal(decoded.Bytes(), plaintxt) {
		t.Fatalf("decrypt err=%v value=%q", err, decoded.Bytes())
	}
}

func TestExecuteDeployCommand(t *testing.T) {
	scheduler := &fakeScheduler{}
	client := &Client{swarm: scheduler}
	output, err := client.executeCommand(context.Background(), command{Kind: "swarm.deploy", Payload: []byte(`{"stackName":"demo","compose":"services: {}","environment":{"TOKEN":"secret"},"registryCredential":{"kind":"registry","server":"registry.example.test","username":"robot","secret":"registry-secret"}}`)})
	if err != nil || output != "deployed" {
		t.Fatalf("output=%q err=%v", output, err)
	}
	if scheduler.stack != "demo" || scheduler.compose != "services: {}" || scheduler.environment["TOKEN"] != "secret" || scheduler.registryCredential == nil || scheduler.registryCredential.Secret != "registry-secret" {
		t.Fatalf("unexpected dispatch: %#v", scheduler)
	}
}

func TestExecuteStackStatusCommand(t *testing.T) {
	want := deploy.StackStatus{Exists: true, Services: 2, HealthyServices: 1, RunningTasks: 1, DesiredTasks: 2, Degraded: []string{"demo_web"}}
	client := &Client{swarm: &fakeScheduler{status: want}}
	output, err := client.executeCommand(context.Background(), command{Kind: "swarm.status", Payload: []byte(`{"stackName":"demo"}`)})
	if err != nil {
		t.Fatal(err)
	}
	var got deploy.StackStatus
	if err = json.Unmarshal([]byte(output), &got); err != nil || got.Services != want.Services || len(got.Degraded) != 1 || got.Degraded[0] != "demo_web" {
		t.Fatalf("status=%#v output=%q err=%v", got, output, err)
	}
}

func TestExecuteDatabaseTransferCommand(t *testing.T) {
	scheduler := &fakeScheduler{}
	client := &Client{swarm: scheduler}
	payload, _ := json.Marshal(deploy.DatabaseTransferJob{Network: "db_default", ArtifactName: "migration.dump", Backup: database.BackupPlan{Image: "postgres:17", Command: []string{"pg_dump"}}, Restore: database.RestorePlan{Image: "postgres:17", Command: []string{"pg_restore"}}})
	output, err := client.executeCommand(context.Background(), command{Kind: "database.transfer", Payload: payload})
	if err != nil {
		t.Fatal(err)
	}
	if scheduler.transfer == nil || scheduler.transfer.Network != "db_default" || scheduler.transfer.ArtifactName != "migration.dump" {
		t.Fatalf("transfer was not dispatched: %#v", scheduler.transfer)
	}
	var result deploy.DatabaseTransferResult
	if err = json.Unmarshal([]byte(output), &result); err != nil || result.SizeBytes != 42 {
		t.Fatalf("output=%q err=%v", output, err)
	}
}

func TestExecuteRejectsUnknownCommand(t *testing.T) {
	client := &Client{swarm: &fakeScheduler{}}
	if _, err := client.executeCommand(context.Background(), command{Kind: "shell.exec", Payload: []byte(`{}`)}); err == nil {
		t.Fatal("expected unknown command to be rejected")
	}
}

func TestExecuteAgentUpgradeRequiresDigestAndFixedService(t *testing.T) {
	directory := t.TempDir()
	logPath := filepath.Join(directory, "args")
	dockerBin := filepath.Join(directory, "docker")
	script := "#!/bin/sh\nprintf '%s\\n' \"$@\" > " + logPath + "\n"
	if err := os.WriteFile(dockerBin, []byte(script), 0700); err != nil {
		t.Fatal(err)
	}
	client := &Client{cfg: Config{DockerBin: dockerBin, ServiceName: "dockyard-agent_agent"}}
	image := "registry.example/dockyard@sha256:" + strings.Repeat("a", 64)
	payload, _ := json.Marshal(map[string]string{"image": image})
	if _, err := client.executeCommand(context.Background(), command{Kind: "agent.upgrade", Payload: payload}); err != nil {
		t.Fatal(err)
	}
	arguments, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatal(err)
	}
	want := "service\nupdate\n--detach=true\n--update-order\nstart-first\n--with-registry-auth\n--image\n" + image + "\ndockyard-agent_agent\n"
	if string(arguments) != want {
		t.Fatalf("docker arguments=%q want=%q", arguments, want)
	}
	if _, err := client.executeCommand(context.Background(), command{Kind: "agent.upgrade", Payload: []byte(`{"image":"registry.example/dockyard:latest"}`)}); err == nil {
		t.Fatal("expected mutable agent image tag to be rejected")
	}
}

func TestHeartbeatAggregatesActiveCapacity(t *testing.T) {
	var body struct {
		AgentImage       string         `json:"agentImage"`
		AgentUpdateState string         `json:"agentUpdateState"`
		Capacity         map[string]any `json:"capacity"`
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Error(err)
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()
	client := &Client{
		cfg:  Config{AgentURL: server.URL, Version: "1.2.3"},
		http: server.Client(),
		serviceState: func(context.Context) (string, string, error) {
			return "registry.example/dockyard@sha256:" + strings.Repeat("a", 64), "completed", nil
		},
		swarm: &fakeScheduler{nodes: []deploy.Node{
			{Status: "Ready", Availability: "Active", ManagerStatus: "Leader", EngineVersion: "29", NanoCPUs: 4_000_000_000, MemoryBytes: 8_000_000_000},
			{Status: "Down", Availability: "Active", EngineVersion: "29", NanoCPUs: 2_000_000_000, MemoryBytes: 4_000_000_000},
			{Status: "Ready", Availability: "Drain", EngineVersion: "29", NanoCPUs: 8_000_000_000, MemoryBytes: 16_000_000_000},
		}},
	}
	if err := client.heartbeat(context.Background()); err != nil {
		t.Fatal(err)
	}
	if body.Capacity["nodes"] != float64(3) || body.Capacity["readyNodes"] != float64(2) || body.Capacity["activeNodes"] != float64(2) || body.Capacity["schedulableNodes"] != float64(1) || body.Capacity["nanoCpus"] != float64(4_000_000_000) || body.Capacity["memoryBytes"] != float64(8_000_000_000) {
		t.Fatalf("unexpected capacity: %#v", body.Capacity)
	}
	if body.AgentUpdateState != "completed" || !strings.Contains(body.AgentImage, "@sha256:") {
		t.Fatalf("unexpected agent release state: image=%q state=%q", body.AgentImage, body.AgentUpdateState)
	}
}

func TestInspectServiceStateReportsImageAndRollout(t *testing.T) {
	directory := t.TempDir()
	dockerBin := filepath.Join(directory, "docker")
	image := "registry.example/dockyard@sha256:" + strings.Repeat("d", 64)
	script := "#!/bin/sh\nprintf '%s|%s\\n' '" + image + "' 'rollback_completed'\n"
	if err := os.WriteFile(dockerBin, []byte(script), 0700); err != nil {
		t.Fatal(err)
	}
	client := &Client{cfg: Config{DockerBin: dockerBin, ServiceName: "dockyard-agent_agent"}}
	gotImage, gotState, err := client.inspectServiceState(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if gotImage != image || gotState != "rollback_completed" {
		t.Fatalf("image=%q state=%q", gotImage, gotState)
	}
}
