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

func TestLoadRejectsUnsafeSessionLifetime(t *testing.T) {
	for _, value := range []string{"invalid", "0s", "4m59s", "721h"} {
		t.Run(value, func(t *testing.T) {
			setRequiredConfig(t)
			t.Setenv("DOCKYARD_SESSION_TTL", value)
			if _, err := Load(); err == nil || !strings.Contains(err.Error(), "DOCKYARD_SESSION_TTL") {
				t.Fatalf("error=%v", err)
			}
		})
	}
	for _, value := range []string{"5m", "24h", "720h"} {
		t.Run("valid_"+value, func(t *testing.T) {
			setRequiredConfig(t)
			t.Setenv("DOCKYARD_SESSION_TTL", value)
			if _, err := Load(); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestLoadValidatesPublicOrigin(t *testing.T) {
	for _, value := range []string{
		"localhost:8080", "ftp://example.test", "https://user@example.test",
		"https://example.test/path", "https://example.test?debug=true", "https://example.test/#fragment",
	} {
		t.Run(value, func(t *testing.T) {
			setRequiredConfig(t)
			t.Setenv("DOCKYARD_PUBLIC_URL", value)
			if _, err := Load(); err == nil || !strings.Contains(err.Error(), "DOCKYARD_PUBLIC_URL") {
				t.Fatalf("error=%v", err)
			}
		})
	}
	setRequiredConfig(t)
	t.Setenv("DOCKYARD_PUBLIC_URL", " https://dockyard.example.test/ ")
	cfg, err := Load()
	if err != nil || cfg.PublicURL != "https://dockyard.example.test" {
		t.Fatalf("public URL=%q error=%v", cfg.PublicURL, err)
	}
}

func TestLoadRejectsAmbiguousSecretSources(t *testing.T) {
	directory := t.TempDir()
	path := filepath.Join(directory, "secret")
	if err := os.WriteFile(path, []byte("postgres://from-file.example.test/dockyard"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("DOCKYARD_DATABASE_URL", "postgres://from-env.example.test/dockyard")
	t.Setenv("DOCKYARD_DATABASE_URL_FILE", path)
	t.Setenv("DOCKYARD_MASTER_KEY", "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=")
	if _, err := Load(); err == nil || !strings.Contains(err.Error(), "cannot both be configured") {
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
