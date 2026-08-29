package config

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/bendahma/dokploy-go/internal/agentpki"
)

func TestLoadRequiresRemoteBackupsWhenConfigured(t *testing.T) {
	t.Setenv("DOCKYARD_DATABASE_URL", "postgres://dockyard@example.test/dockyard")
	t.Setenv("DOCKYARD_MASTER_KEY", "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=")
	t.Setenv("DOCKYARD_REQUIRE_REMOTE_BACKUPS", "true")
	cfg, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if !cfg.RequireRemoteBackups {
		t.Fatal("remote backup requirement was not enabled")
	}
}

func TestLoadRejectsInvalidRemoteBackupPolicy(t *testing.T) {
	t.Setenv("DOCKYARD_DATABASE_URL", "postgres://dockyard@example.test/dockyard")
	t.Setenv("DOCKYARD_MASTER_KEY", "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=")
	t.Setenv("DOCKYARD_REQUIRE_REMOTE_BACKUPS", "sometimes")
	_, err := Load()
	if err == nil || !strings.Contains(err.Error(), "DOCKYARD_REQUIRE_REMOTE_BACKUPS") {
		t.Fatalf("error=%v", err)
	}
}

func TestLoadRequiresVerifiedDatabaseTLSWhenConfigured(t *testing.T) {
	t.Setenv("DOCKYARD_MASTER_KEY", "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=")
	t.Setenv("DOCKYARD_REQUIRE_DATABASE_TLS", "true")
	for _, databaseURL := range []string{
		"postgres://dockyard@example.test/dockyard",
		"postgres://dockyard@example.test/dockyard?sslmode=disable",
		"postgres://dockyard@example.test/dockyard?sslmode=require",
		"host=example.test dbname=dockyard sslmode=verify-full",
	} {
		t.Run(databaseURL, func(t *testing.T) {
			t.Setenv("DOCKYARD_DATABASE_URL", databaseURL)
			if _, err := Load(); err == nil || !strings.Contains(err.Error(), "sslmode=verify-full") {
				t.Fatalf("error=%v", err)
			}
		})
	}
	t.Setenv("DOCKYARD_DATABASE_URL", "postgresql://dockyard@example.test/dockyard?sslmode=verify-full")
	cfg, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if !cfg.RequireDatabaseTLS {
		t.Fatal("database TLS requirement was not enabled")
	}
}

func TestLoadValidatesAgentTLSCredentialsAndRecordsExpiry(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	caPEM, caKeyPEM, certFile, keyFile, caExpiry, serverExpiry := testAgentCredentials(t, now.Add(-time.Minute), now.Add(24*time.Hour))
	setRequiredConfig(t)
	t.Setenv("DOCKYARD_AGENT_CA_CERT", string(caPEM))
	t.Setenv("DOCKYARD_AGENT_CA_KEY", string(caKeyPEM))
	t.Setenv("DOCKYARD_AGENT_LISTEN_ADDR", ":8444")
	t.Setenv("DOCKYARD_AGENT_SERVER_CERT_FILE", certFile)
	t.Setenv("DOCKYARD_AGENT_SERVER_KEY_FILE", keyFile)

	cfg, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if !cfg.AgentCAExpiresAt.Equal(caExpiry) || !cfg.AgentServerCertExpiresAt.Equal(serverExpiry) {
		t.Fatalf("CA expiry=%v server expiry=%v", cfg.AgentCAExpiresAt, cfg.AgentServerCertExpiresAt)
	}
}

func TestLoadRejectsInvalidAgentTLSCredentials(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	t.Run("mismatched server key", func(t *testing.T) {
		caPEM, caKeyPEM, certFile, keyFile, _, _ := testAgentCredentials(t, now.Add(-time.Minute), now.Add(24*time.Hour))
		otherKey, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			t.Fatal(err)
		}
		if err = os.WriteFile(keyFile, pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(otherKey)}), 0o600); err != nil {
			t.Fatal(err)
		}
		setAgentConfig(t, caPEM, caKeyPEM, certFile, keyFile)
		if _, err = Load(); err == nil || !strings.Contains(err.Error(), "validate agent TLS credentials") {
			t.Fatalf("error=%v", err)
		}
	})

	t.Run("expired server certificate", func(t *testing.T) {
		caPEM, caKeyPEM, certFile, keyFile, _, _ := testAgentCredentials(t, now.Add(-2*time.Hour), now.Add(-time.Hour))
		setAgentConfig(t, caPEM, caKeyPEM, certFile, keyFile)
		if _, err := Load(); err == nil || !strings.Contains(err.Error(), "validate agent TLS credentials") {
			t.Fatalf("error=%v", err)
		}
	})

	t.Run("mismatched authority key without listener", func(t *testing.T) {
		caPEM, _, _, _, _, _ := testAgentCredentials(t, now.Add(-time.Minute), now.Add(24*time.Hour))
		_, otherCAKey, err := agentpki.NewCA(now, 30*24*time.Hour)
		if err != nil {
			t.Fatal(err)
		}
		setRequiredConfig(t)
		t.Setenv("DOCKYARD_AGENT_CA_CERT", string(caPEM))
		t.Setenv("DOCKYARD_AGENT_CA_KEY", string(otherCAKey))
		if _, err = Load(); err == nil || !strings.Contains(err.Error(), "validate agent CA") {
			t.Fatalf("error=%v", err)
		}
	})
}

func setRequiredConfig(t *testing.T) {
	t.Helper()
	t.Setenv("DOCKYARD_DATABASE_URL", "postgres://dockyard@example.test/dockyard")
	t.Setenv("DOCKYARD_MASTER_KEY", "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=")
}

func setAgentConfig(t *testing.T, caPEM, caKeyPEM []byte, certFile, keyFile string) {
	t.Helper()
	setRequiredConfig(t)
	t.Setenv("DOCKYARD_AGENT_CA_CERT", string(caPEM))
	t.Setenv("DOCKYARD_AGENT_CA_KEY", string(caKeyPEM))
	t.Setenv("DOCKYARD_AGENT_LISTEN_ADDR", ":8444")
	t.Setenv("DOCKYARD_AGENT_SERVER_CERT_FILE", certFile)
	t.Setenv("DOCKYARD_AGENT_SERVER_KEY_FILE", keyFile)
}

func testAgentCredentials(t *testing.T, notBefore, notAfter time.Time) ([]byte, []byte, string, string, time.Time, time.Time) {
	t.Helper()
	caPEM, caKeyPEM, err := agentpki.NewCA(time.Now().UTC(), 30*24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	caBlock, _ := pem.Decode(caPEM)
	keyBlock, _ := pem.Decode(caKeyPEM)
	ca, err := x509.ParseCertificate(caBlock.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	caKey, err := x509.ParsePKCS1PrivateKey(keyBlock.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	serverKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: "agents.example.test"},
		DNSNames:     []string{"agents.example.test"},
		NotBefore:    notBefore,
		NotAfter:     notAfter,
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	encoded, err := x509.CreateCertificate(rand.Reader, template, ca, &serverKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	directory := t.TempDir()
	certFile := filepath.Join(directory, "agent-server.crt")
	keyFile := filepath.Join(directory, "agent-server.key")
	if err = os.WriteFile(certFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: encoded}), 0o600); err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(keyFile, pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(serverKey)}), 0o600); err != nil {
		t.Fatal(err)
	}
	return caPEM, caKeyPEM, certFile, keyFile, ca.NotAfter, template.NotAfter
}
