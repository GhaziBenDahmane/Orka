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
	"github.com/bendahma/dokploy-go/internal/clustercontract"
	"github.com/bendahma/dokploy-go/internal/cryptox"
	"github.com/bendahma/dokploy-go/internal/database"
	"github.com/bendahma/dokploy-go/internal/deploy"
	"github.com/bendahma/dokploy-go/internal/netpolicy"
	"github.com/bendahma/dokploy-go/internal/volumeartifact"
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
	storageNode        string
	volumeNode         string
	volumeArtifact     *deploy.VolumeArtifactJob
}

func (f *fakeScheduler) RunVolumeArtifact(_ context.Context, job deploy.VolumeArtifactJob) (volumeartifact.Result, error) {
	f.volumeArtifact = &job
	return volumeartifact.Result{SHA256: strings.Repeat("a", 64), PlaintextSHA256: strings.Repeat("b", 64), SizeBytes: 42}, nil
}

func (f *fakeScheduler) ResolveStorageNode(context.Context, string) (string, error) {
	if f.storageNode == "" {
		return "node-a", nil
	}
	return f.storageNode, nil
}

func (f *fakeScheduler) ResolveVolumeNode(context.Context, string, string) (string, error) {
	if f.volumeNode == "" {
		return "node-volume", nil
	}
	return f.volumeNode, nil
}

func TestValidateAgentEndpointsRequireHTTPSOrigins(t *testing.T) {
	for _, endpoint := range []string{"https://control.example.test", "https://agents.example.test:8444/", "https://127.0.0.1", "https://[::1]:8444"} {
		if err := validateAgentEndpoint("test URL", endpoint); err != nil {
			t.Fatalf("valid endpoint %q rejected: %v", endpoint, err)
		}
	}
	for _, endpoint := range []string{"http://agents.example.test", "https://user@agents.example.test", "https://agents.example.test/path", "https://agents.example.test?token=value", "https://agents.example.test/#fragment", "//agents.example.test", " https://agents.example.test", "https://bad_label.example.test", "https://-bad.example.test", "https://agents.example.test:", "https://agents.example.test:0", "https://agents.example.test:65536"} {
		if err := validateAgentEndpoint("test URL", endpoint); err == nil {
			t.Errorf("unsafe endpoint %q accepted", endpoint)
		}
	}
}

func TestRunRejectsUnsafeEndpointBeforeWritingAgentState(t *testing.T) {
	for _, test := range []struct {
		name          string
		enrollmentURL string
		agentURL      string
	}{
		{name: "plaintext enrollment", enrollmentURL: "http://control.example.test", agentURL: "https://agents.example.test"},
		{name: "redirectable path origin", enrollmentURL: "https://control.example.test", agentURL: "https://agents.example.test/proxy"},
	} {
		t.Run(test.name, func(t *testing.T) {
			state := filepath.Join(t.TempDir(), "agent-state")
			err := Run(context.Background(), Config{EnrollmentURL: test.enrollmentURL, AgentURL: test.agentURL, StateDirectory: state, ServiceName: "dockyard-agent_agent"})
			if err == nil || !strings.Contains(err.Error(), "must be an HTTPS origin") {
				t.Fatalf("Run error=%v", err)
			}
			if _, statErr := os.Stat(state); !errors.Is(statErr, os.ErrNotExist) {
				t.Fatalf("unsafe configuration mutated state directory: %v", statErr)
			}
		})
	}
}

func TestAgentHTTPClientsRejectRedirects(t *testing.T) {
	targetCalls := 0
	target := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { targetCalls++ }))
	defer target.Close()
	redirect := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, target.URL, http.StatusTemporaryRedirect)
	}))
	defer redirect.Close()
	request, err := http.NewRequest(http.MethodPost, redirect.URL, strings.NewReader(`{"token":"secret"}`))
	if err != nil {
		t.Fatal(err)
	}
	client := &http.Client{Timeout: time.Second, CheckRedirect: rejectRedirect}
	if _, err = client.Do(request); err == nil || !strings.Contains(err.Error(), "redirects are disabled") {
		t.Fatalf("redirect error=%v", err)
	}
	if targetCalls != 0 {
		t.Fatalf("redirect target received %d credential-bearing requests", targetCalls)
	}
}

func TestArtifactTransferEnforcesPrivateEgressPolicy(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte("artifact")) }))
	defer server.Close()
	blockedPath := filepath.Join(t.TempDir(), "blocked")
	if err := transfer(context.Background(), http.MethodGet, server.URL, blockedPath, int64(len("artifact")), &netpolicy.Policy{}); err == nil || !strings.Contains(err.Error(), "egress policy blocks") {
		t.Fatalf("private artifact transfer error=%v", err)
	}
	allowed, err := netpolicy.ParseAllowedCIDRs("127.0.0.0/8")
	if err != nil {
		t.Fatal(err)
	}
	allowedPath := filepath.Join(t.TempDir(), "allowed")
	if err = transfer(context.Background(), http.MethodGet, server.URL, allowedPath, int64(len("artifact")), &netpolicy.Policy{Allowed: allowed}); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(allowedPath)
	if err != nil || string(data) != "artifact" {
		t.Fatalf("artifact=%q error=%v", data, err)
	}
}

func TestDecodeBoundedJSONRejectsOversizedAndTrailingResponses(t *testing.T) {
	var output map[string]string
	if err := decodeBoundedJSON(strings.NewReader(`{"status":"ok"}`), 32, &output); err != nil || output["status"] != "ok" {
		t.Fatalf("valid response output=%v error=%v", output, err)
	}
	if err := decodeBoundedJSON(strings.NewReader(`{"status":"ok"} {}`), 32, &output); err == nil || !strings.Contains(err.Error(), "multiple values") {
		t.Fatalf("trailing JSON error=%v", err)
	}
	if err := decodeBoundedJSON(strings.NewReader(`{"status":"ok"} trailing`), 32, &output); err == nil || !strings.Contains(err.Error(), "trailing data") {
		t.Fatalf("trailing data error=%v", err)
	}
	if err := decodeBoundedJSON(strings.NewReader(`{"status":"response exceeds limit"}`), 16, &output); err == nil || !strings.Contains(err.Error(), "exceeds") {
		t.Fatalf("oversized response error=%v", err)
	}
}

func TestArtifactDownloadEnforcesExpectedSizeAndCleansPartialFiles(t *testing.T) {
	tests := []struct {
		name        string
		serve       func(http.ResponseWriter)
		expected    int64
		wantErr     string
		wantContent string
	}{
		{name: "exact", expected: 8, wantContent: "artifact", serve: func(w http.ResponseWriter) { _, _ = w.Write([]byte("artifact")) }},
		{name: "content length mismatch", expected: 7, wantErr: "content length mismatch", serve: func(w http.ResponseWriter) { _, _ = w.Write([]byte("artifact")) }},
		{name: "oversized chunked", expected: 7, wantErr: "size mismatch", serve: func(w http.ResponseWriter) {
			w.(http.Flusher).Flush()
			_, _ = w.Write([]byte("artifact"))
		}},
		{name: "truncated chunked", expected: 9, wantErr: "size mismatch", serve: func(w http.ResponseWriter) {
			w.(http.Flusher).Flush()
			_, _ = w.Write([]byte("artifact"))
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { test.serve(w) }))
			defer server.Close()
			path := filepath.Join(t.TempDir(), "artifact.enc")
			err := transfer(context.Background(), http.MethodGet, server.URL, path, test.expected, nil)
			if test.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), test.wantErr) {
					t.Fatalf("error=%v, want %q", err, test.wantErr)
				}
				if _, statErr := os.Stat(path); !errors.Is(statErr, os.ErrNotExist) {
					t.Fatalf("partial artifact remains: %v", statErr)
				}
				return
			}
			content, readErr := os.ReadFile(path)
			if err != nil || readErr != nil || string(content) != test.wantContent {
				t.Fatalf("error=%v read=%v content=%q", err, readErr, content)
			}
		})
	}
}

func TestArtifactUploadSendsVerifiedContentLength(t *testing.T) {
	var contentLength int64
	var content []byte
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		contentLength = r.ContentLength
		content, _ = io.ReadAll(r.Body)
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()
	path := filepath.Join(t.TempDir(), "artifact.enc")
	if err := os.WriteFile(path, []byte("artifact"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := transfer(context.Background(), http.MethodPut, server.URL, path, 8, nil); err != nil {
		t.Fatal(err)
	}
	if contentLength != 8 || string(content) != "artifact" {
		t.Fatalf("content length=%d content=%q", contentLength, content)
	}
	if err := transfer(context.Background(), http.MethodPut, server.URL, path, 7, nil); err == nil || !strings.Contains(err.Error(), "upload size mismatch") {
		t.Fatalf("mismatched upload error=%v", err)
	}
}

func TestEnsureIdentityValidatesEnrollmentBeforePersistence(t *testing.T) {
	now := time.Now().UTC()
	caPEM, caKey, err := agentpki.NewCA(now, 24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	untrustedCA, _, err := agentpki.NewCA(now, 24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	clusterID := uuid.New()
	for _, test := range []struct {
		name        string
		mismatchKey bool
		returnedCA  []byte
		certificate string
		wantErr     string
	}{
		{name: "valid identity", returnedCA: caPEM},
		{name: "mismatched private key", mismatchKey: true, returnedCA: caPEM, wantErr: "does not match the generated private key"},
		{name: "untrusted certificate", returnedCA: untrustedCA, wantErr: "verify agent client certificate"},
		{name: "invalid certificate", returnedCA: caPEM, certificate: "not a certificate", wantErr: "invalid certificate"},
		{name: "invalid CA bundle", returnedCA: []byte("not a CA"), wantErr: "invalid agent CA trust bundle"},
	} {
		t.Run(test.name, func(t *testing.T) {
			directory := t.TempDir()
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				var input struct {
					CSR string `json:"csr"`
				}
				if decodeErr := json.NewDecoder(r.Body).Decode(&input); decodeErr != nil {
					t.Error(decodeErr)
					w.WriteHeader(http.StatusBadRequest)
					return
				}
				csr := []byte(input.CSR)
				if test.mismatchKey {
					otherKey, keyErr := rsa.GenerateKey(rand.Reader, 2048)
					if keyErr != nil {
						t.Error(keyErr)
						w.WriteHeader(http.StatusInternalServerError)
						return
					}
					otherCSR, csrErr := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{Subject: pkix.Name{CommonName: "other-agent"}}, otherKey)
					if csrErr != nil {
						t.Error(csrErr)
						w.WriteHeader(http.StatusInternalServerError)
						return
					}
					csr = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: otherCSR})
				}
				certificate := test.certificate
				if certificate == "" {
					issued, _, signErr := agentpki.SignAgentCSR(caPEM, caKey, csr, clusterID, time.Now(), time.Hour)
					if signErr != nil {
						t.Error(signErr)
						w.WriteHeader(http.StatusInternalServerError)
						return
					}
					certificate = string(issued)
				}
				_ = json.NewEncoder(w).Encode(map[string]string{"certificate": certificate, "caCertificate": string(test.returnedCA)})
			}))
			defer server.Close()

			err := ensureIdentity(context.Background(), Config{EnrollmentURL: server.URL, EnrollmentToken: "one-time-token", StateDirectory: directory})
			certPath, keyPath, caPath := identityPaths(directory)
			if test.wantErr == "" {
				if err != nil {
					t.Fatal(err)
				}
				if err = validateSavedAgentIdentity(certPath, keyPath, caPath, time.Now()); err != nil {
					t.Fatalf("saved identity is invalid: %v", err)
				}
				if _, statErr := os.Stat(enrollmentKeyPath(directory)); !errors.Is(statErr, os.ErrNotExist) {
					t.Fatalf("successful enrollment retained its pending key: %v", statErr)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), test.wantErr) {
				t.Fatalf("ensureIdentity error=%v, want substring %q", err, test.wantErr)
			}
			for _, path := range []string{certPath, caPath} {
				if _, statErr := os.Stat(path); !errors.Is(statErr, os.ErrNotExist) {
					t.Fatalf("rejected enrollment persisted %s: %v", filepath.Base(path), statErr)
				}
			}
			pendingInfo, statErr := os.Stat(enrollmentKeyPath(directory))
			if statErr != nil {
				t.Fatalf("rejected enrollment did not preserve its protected retry key: %v", statErr)
			}
			if pendingInfo.Mode().Perm() != 0600 {
				t.Fatalf("pending enrollment key mode=%o, want 600", pendingInfo.Mode().Perm())
			}
		})
	}
}

func TestEnsureIdentityRetriesWithTheSameCSR(t *testing.T) {
	now := time.Now().UTC()
	caPEM, caKey, err := agentpki.NewCA(now, 24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	untrustedCA, _, err := agentpki.NewCA(now, 24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	var requests []string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var input struct {
			CSR string `json:"csr"`
		}
		if decodeErr := json.NewDecoder(r.Body).Decode(&input); decodeErr != nil {
			t.Error(decodeErr)
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		requests = append(requests, input.CSR)
		certificate, _, signErr := agentpki.SignAgentCSR(caPEM, caKey, []byte(input.CSR), uuid.NewSHA1(uuid.Nil, []byte("retry-cluster")), time.Now(), time.Hour)
		if signErr != nil {
			t.Error(signErr)
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		returnedCA := caPEM
		if len(requests) == 1 {
			returnedCA = untrustedCA
		}
		_ = json.NewEncoder(w).Encode(map[string]string{"certificate": string(certificate), "caCertificate": string(returnedCA)})
	}))
	defer server.Close()
	directory := t.TempDir()
	cfg := Config{EnrollmentURL: server.URL, EnrollmentToken: "one-time-token", StateDirectory: directory}
	if err = ensureIdentity(context.Background(), cfg); err == nil || !strings.Contains(err.Error(), "verify agent client certificate") {
		t.Fatalf("first enrollment error=%v", err)
	}
	if err = ensureIdentity(context.Background(), cfg); err != nil {
		t.Fatal(err)
	}
	if len(requests) != 2 || requests[0] != requests[1] {
		t.Fatalf("enrollment retry changed CSR: requests=%d equal=%t", len(requests), len(requests) == 2 && requests[0] == requests[1])
	}
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

func (f *fakeScheduler) Deploy(_ context.Context, stack, compose string, environment map[string]string, registryCredential *deploy.Credential) (deploy.DeploymentResult, error) {
	f.stack, f.compose, f.environment, f.registryCredential = stack, compose, environment, registryCredential
	return deploy.DeploymentResult{Output: "deployed", ResolvedImages: map[string]string{}}, nil
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
	download.SizeBytes = result.SizeBytes
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
	var result deploy.DeploymentResult
	decodeErr := json.Unmarshal([]byte(output), &result)
	if err != nil || decodeErr != nil || result.Output != "deployed" || result.ResolvedImages == nil {
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

func TestExecuteStorageNodeCommand(t *testing.T) {
	client := &Client{swarm: &fakeScheduler{storageNode: "node-persisted"}}
	output, err := client.executeCommand(context.Background(), command{Kind: "swarm.storage-node", Payload: []byte(`{"stackName":"database"}`)})
	if err != nil || output != "node-persisted" {
		t.Fatalf("output=%q err=%v", output, err)
	}
}

func TestExecuteVolumeNodeCommand(t *testing.T) {
	client := &Client{swarm: &fakeScheduler{volumeNode: "node-persisted"}}
	output, err := client.executeCommand(context.Background(), command{Kind: "swarm.volume-node", Payload: []byte(`{"stackName":"application","volumeName":"application_data"}`)})
	if err != nil || output != "node-persisted" {
		t.Fatalf("output=%q err=%v", output, err)
	}
}

func TestExecuteVolumeArtifactCommand(t *testing.T) {
	scheduler := &fakeScheduler{}
	client := &Client{swarm: scheduler}
	payload, _ := json.Marshal(deploy.VolumeArtifactJob{Job: volumeartifact.Job{Mode: "backup", TransferURL: "https://objects.example.test/upload", EncryptionKey: base64.RawStdEncoding.EncodeToString(make([]byte, 32)), EncryptionAAD: "volume-backup:test"}, VolumeName: "stack_data", NodeID: "nodeabc123", StackName: "application"})
	output, err := client.executeCommand(context.Background(), command{Kind: "swarm.volume-artifact", Payload: payload})
	if err != nil || scheduler.volumeArtifact == nil || scheduler.volumeArtifact.VolumeName != "stack_data" {
		t.Fatalf("job=%#v output=%q err=%v", scheduler.volumeArtifact, output, err)
	}
	var result volumeartifact.Result
	if err = json.Unmarshal([]byte(output), &result); err != nil || result.SizeBytes != 42 {
		t.Fatalf("result=%#v output=%q err=%v", result, output, err)
	}
}

func TestExecuteOfflineVolumeArtifactCommandPreservesSafetyMode(t *testing.T) {
	scheduler := &fakeScheduler{}
	client := &Client{swarm: scheduler}
	payload, _ := json.Marshal(deploy.VolumeArtifactJob{Job: volumeartifact.Job{Mode: "restore", TransferURL: "https://objects.example.test/download", EncryptionKey: base64.RawStdEncoding.EncodeToString(make([]byte, 32)), EncryptionAAD: "volume-backup:test", SHA256: strings.Repeat("a", 64), PlaintextSHA256: strings.Repeat("b", 64), SizeBytes: 42}, VolumeName: "stack_data", NodeID: "nodeabc123", StackName: "application", Offline: true})
	if _, err := client.executeCommand(context.Background(), command{Kind: "swarm.volume-artifact", Payload: payload}); err != nil {
		t.Fatal(err)
	}
	if scheduler.volumeArtifact == nil || !scheduler.volumeArtifact.Offline || scheduler.volumeArtifact.Quiesce {
		t.Fatalf("offline restore mode was not preserved: %#v", scheduler.volumeArtifact)
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
		AgentImage       string                       `json:"agentImage"`
		AgentUpdateState string                       `json:"agentUpdateState"`
		Capacity         map[string]any               `json:"capacity"`
		Capabilities     clustercontract.Capabilities `json:"capabilities"`
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
	if body.Capabilities.ProtocolVersion != clustercontract.ProtocolVersion || !body.Capabilities.DockerSwarm || !body.Capabilities.DockerCompose {
		t.Fatalf("unexpected capabilities: %#v", body.Capabilities)
	}
}

func TestCapabilitiesFailClosedUntilTraefikContractIsObserved(t *testing.T) {
	directory := t.TempDir()
	dockerBin := filepath.Join(directory, "docker")
	script := `#!/bin/sh
case "$1 $2" in
  "service inspect") printf '%s' '[{"Spec":{"TaskTemplate":{"ContainerSpec":{"Args":["--providers.file.directory=/etc/traefik/dynamic"]},"Networks":[{"Target":"network-id"}]}}}]' ;;
  "network inspect") printf '%s\n' 'network-id' ;;
  *) exit 1 ;;
esac
`
	if err := os.WriteFile(dockerBin, []byte(script), 0700); err != nil {
		t.Fatal(err)
	}
	client := &Client{cfg: Config{DockerBin: dockerBin, Network: "dockyard-public", EdgeProxyServiceName: "edge_traefik", EdgeProxyDynamicConfigurationPath: "/etc/traefik/dynamic"}}
	capabilities := client.capabilities(context.Background())
	if err := clustercontract.Validate(capabilities); err != nil {
		t.Fatal(err)
	}
	if capabilities.EdgeProxy == nil || !capabilities.EdgeProxy.Ready || !capabilities.EdgeProxy.SupportsCustomCertificates {
		t.Fatalf("expected ready edge proxy contract, got %#v", capabilities.EdgeProxy)
	}

	client.cfg.EdgeProxyDynamicConfigurationPath = "/etc/traefik/other"
	capabilities = client.capabilities(context.Background())
	if capabilities.EdgeProxy == nil || capabilities.EdgeProxy.Status != "file_provider_missing" || capabilities.EdgeProxy.SupportsCustomCertificates {
		t.Fatalf("expected fail-closed file-provider status, got %#v", capabilities.EdgeProxy)
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

func TestAgentDockerCommandOutputIsBounded(t *testing.T) {
	directory := t.TempDir()
	dockerBin := filepath.Join(directory, "docker")
	if err := os.WriteFile(dockerBin, []byte("#!/bin/sh\nyes x | head -c 1100000\n"), 0700); err != nil {
		t.Fatal(err)
	}
	output, err := boundedAgentCommandOutput(context.Background(), dockerBin, "info")
	if err == nil || !strings.Contains(err.Error(), "output exceeded 1 MiB") || len(output) != maxAgentDockerOutputBytes {
		t.Fatalf("output bytes=%d err=%v", len(output), err)
	}
}
