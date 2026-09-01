package config

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/GhaziBenDahmane/Orka/internal/agentpki"
)

func TestLoadRequiresRemoteBackupsWhenConfigured(t *testing.T) {
	setRequiredConfig(t)
	t.Setenv("DOCKYARD_REQUIRE_REMOTE_BACKUPS", "true")
	cfg, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if !cfg.RequireRemoteBackups {
		t.Fatal("remote backup requirement was not enabled")
	}
}

func TestLoadValidatesBuildWorkspaceLimit(t *testing.T) {
	setRequiredConfig(t)
	cfg, err := Load()
	if err != nil || cfg.MaxBuildWorkspaceBytes != 2<<30 {
		t.Fatalf("default build workspace limit=%d error=%v", cfg.MaxBuildWorkspaceBytes, err)
	}
	setRequiredConfig(t)
	t.Setenv("DOCKYARD_MAX_BUILD_WORKSPACE_BYTES", "805306368")
	cfg, err = Load()
	if err != nil || cfg.MaxBuildWorkspaceBytes != 805306368 {
		t.Fatalf("configured build workspace limit=%d error=%v", cfg.MaxBuildWorkspaceBytes, err)
	}
	for _, value := range []string{"invalid", "0", "67108863", "1099511627777"} {
		t.Run(value, func(t *testing.T) {
			setRequiredConfig(t)
			t.Setenv("DOCKYARD_MAX_BUILD_WORKSPACE_BYTES", value)
			if _, err := Load(); err == nil || !strings.Contains(err.Error(), "DOCKYARD_MAX_BUILD_WORKSPACE_BYTES") {
				t.Fatalf("error=%v", err)
			}
		})
	}
}

func TestLoadRejectsInvalidRemoteBackupPolicy(t *testing.T) {
	setRequiredConfig(t)
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
		"http://example.test", "http://10.20.30.40:8080",
		"https://bad_label.example.test", "https://-bad.example.test", "https://bad-.example.test",
		"https://example.test.", "https://example.test:", "https://example.test:0", "https://example.test:65536",
		"https://example.test//", "https://[not-an-ip]",
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
	for _, value := range []string{"https://dockyard.example.test:8443", "https://127.0.0.1", "https://[2001:db8::1]:443"} {
		t.Run("https_"+value, func(t *testing.T) {
			setRequiredConfig(t)
			t.Setenv("DOCKYARD_PUBLIC_URL", value)
			if _, err := Load(); err != nil {
				t.Fatal(err)
			}
		})
	}
	for _, value := range []string{"http://localhost:8080", "http://dev.localhost:8080", "http://127.0.0.1:8080", "http://[::1]:8080"} {
		t.Run("loopback_"+value, func(t *testing.T) {
			setRequiredConfig(t)
			t.Setenv("DOCKYARD_PUBLIC_URL", value)
			if _, err := Load(); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestLoadValidatesTraefikNetwork(t *testing.T) {
	for _, value := range []string{"Public", "-public", "public/network", strings.Repeat("a", 64)} {
		t.Run(value, func(t *testing.T) {
			setRequiredConfig(t)
			t.Setenv("DOCKYARD_TRAEFIK_NETWORK", value)
			if _, err := Load(); err == nil || !strings.Contains(err.Error(), "DOCKYARD_TRAEFIK_NETWORK") {
				t.Fatalf("error=%v", err)
			}
		})
	}
	setRequiredConfig(t)
	t.Setenv("DOCKYARD_TRAEFIK_NETWORK", "tenant_public.network")
	if cfg, err := Load(); err != nil || cfg.TraefikNetwork != "tenant_public.network" {
		t.Fatalf("network=%q error=%v", cfg.TraefikNetwork, err)
	}
}

func TestLoadValidatesSwarmServiceName(t *testing.T) {
	setRequiredConfig(t)
	t.Setenv("DOCKYARD_SWARM_SERVICE_NAME", "custom_dockyard")
	if cfg, err := Load(); err != nil || cfg.SwarmServiceName != "custom_dockyard" {
		t.Fatalf("service=%q error=%v", cfg.SwarmServiceName, err)
	}
	for _, value := range []string{"-service", "service/name", strings.Repeat("a", 129)} {
		t.Run(value, func(t *testing.T) {
			setRequiredConfig(t)
			t.Setenv("DOCKYARD_SWARM_SERVICE_NAME", value)
			if _, err := Load(); err == nil || !strings.Contains(err.Error(), "DOCKYARD_SWARM_SERVICE_NAME") {
				t.Fatalf("error=%v", err)
			}
		})
	}
}

func TestLoadValidatesExpectedControllerReplicas(t *testing.T) {
	setRequiredConfig(t)
	t.Setenv("DOCKYARD_EXPECTED_CONTROLLER_REPLICAS", "3")
	t.Setenv("DOCKYARD_REQUIRE_DATABASE_TLS", "true")
	t.Setenv("DOCKYARD_REQUIRE_REMOTE_BACKUPS", "true")
	t.Setenv("DOCKYARD_DATABASE_URL", "postgresql://dockyard@example.test/dockyard?sslmode=verify-full")
	if cfg, err := Load(); err != nil || cfg.ExpectedControllerReplicas != 3 {
		t.Fatalf("replicas=%d error=%v", cfg.ExpectedControllerReplicas, err)
	}
	for _, value := range []string{"0", "100", "not-a-number"} {
		t.Run(value, func(t *testing.T) {
			setRequiredConfig(t)
			t.Setenv("DOCKYARD_EXPECTED_CONTROLLER_REPLICAS", value)
			if _, err := Load(); err == nil || !strings.Contains(err.Error(), "DOCKYARD_EXPECTED_CONTROLLER_REPLICAS") {
				t.Fatalf("error=%v", err)
			}
		})
	}
}

func TestLoadRequiresDurableEncryptedStateForMultipleControllers(t *testing.T) {
	setRequiredConfig(t)
	t.Setenv("DOCKYARD_EXPECTED_CONTROLLER_REPLICAS", "3")
	if _, err := Load(); err == nil || !strings.Contains(err.Error(), "DOCKYARD_REQUIRE_DATABASE_TLS") {
		t.Fatalf("database TLS error=%v", err)
	}

	t.Setenv("DOCKYARD_REQUIRE_DATABASE_TLS", "true")
	t.Setenv("DOCKYARD_DATABASE_URL", "postgresql://dockyard@example.test/dockyard?sslmode=verify-full")
	if _, err := Load(); err == nil || !strings.Contains(err.Error(), "DOCKYARD_REQUIRE_REMOTE_BACKUPS") {
		t.Fatalf("remote backup error=%v", err)
	}

	t.Setenv("DOCKYARD_REQUIRE_REMOTE_BACKUPS", "true")
	cfg, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if cfg.ExpectedControllerReplicas != 3 || !cfg.RequireDatabaseTLS || !cfg.RequireRemoteBackups {
		t.Fatalf("HA safety configuration was not preserved: %#v", cfg)
	}
}

func TestLoadValidatesTrustedProxyNetworks(t *testing.T) {
	setRequiredConfig(t)
	t.Setenv("DOCKYARD_TRUSTED_PROXY_CIDRS", "10.255.250.0/24, 2001:db8::/64")
	cfg, err := Load()
	if err != nil || len(cfg.TrustedProxyCIDRs) != 2 || !cfg.TrustedProxyCIDRs[0].Contains(net.ParseIP("10.255.250.42")) || !cfg.TrustedProxyCIDRs[1].Contains(net.ParseIP("2001:db8::1")) {
		t.Fatalf("trusted proxies=%v error=%v", cfg.TrustedProxyCIDRs, err)
	}
	for _, value := range []string{"not-a-network", "10.0.0.1", strings.Repeat("10.0.0.0/8,", 33)} {
		t.Run(value, func(t *testing.T) {
			setRequiredConfig(t)
			t.Setenv("DOCKYARD_TRUSTED_PROXY_CIDRS", value)
			if _, err := Load(); err == nil || !strings.Contains(err.Error(), "DOCKYARD_TRUSTED_PROXY_CIDRS") {
				t.Fatalf("error=%v", err)
			}
		})
	}
}

func TestLoadValidatesPrivateEgressNetworks(t *testing.T) {
	setRequiredConfig(t)
	t.Setenv("DOCKYARD_EGRESS_PRIVATE_CIDRS", "10.40.0.0/16, fd00:1234::/48")
	cfg, err := Load()
	if err != nil || len(cfg.EgressPrivateCIDRs) != 2 || !cfg.EgressPrivateCIDRs[0].Contains(netip.MustParseAddr("10.40.2.3")) || !cfg.EgressPrivateCIDRs[1].Contains(netip.MustParseAddr("fd00:1234::2")) {
		t.Fatalf("private egress networks=%v error=%v", cfg.EgressPrivateCIDRs, err)
	}
	for _, value := range []string{"not-a-network", "10.0.0.1", "10.0.0.0/8,10.0.0.0/8"} {
		t.Run(value, func(t *testing.T) {
			setRequiredConfig(t)
			t.Setenv("DOCKYARD_EGRESS_PRIVATE_CIDRS", value)
			if _, err := Load(); err == nil || !strings.Contains(err.Error(), "DOCKYARD_EGRESS_PRIVATE_CIDRS") {
				t.Fatalf("error=%v", err)
			}
		})
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
	t.Setenv("DOCKYARD_METRICS_TOKEN", "test-metrics-token-at-least-32-bytes")
	if _, err := Load(); err == nil || !strings.Contains(err.Error(), "cannot both be configured") {
		t.Fatalf("error=%v", err)
	}
}

func TestSecretEnvRejectsUnsafeSecretFiles(t *testing.T) {
	for _, test := range []struct {
		name string
		make func(*testing.T, string) string
		want string
	}{
		{
			name: "symbolic link",
			make: func(t *testing.T, directory string) string {
				target := filepath.Join(directory, "target")
				link := filepath.Join(directory, "secret")
				if err := os.WriteFile(target, []byte("secret"), 0o600); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(target, link); err != nil {
					t.Fatal(err)
				}
				return link
			},
			want: "regular file",
		},
		{
			name: "directory",
			make: func(_ *testing.T, directory string) string { return directory },
			want: "regular file",
		},
		{
			name: "oversized",
			make: func(t *testing.T, directory string) string {
				path := filepath.Join(directory, "secret")
				if err := os.WriteFile(path, []byte(strings.Repeat("x", int(maxConfigSecretFileBytes)+1)), 0o600); err != nil {
					t.Fatal(err)
				}
				return path
			},
			want: "between 1 and",
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Setenv("DOCKYARD_TEST_SECRET", "")
			t.Setenv("DOCKYARD_TEST_SECRET_FILE", test.make(t, t.TempDir()))
			if _, err := secretEnv("DOCKYARD_TEST_SECRET"); err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("error=%v, want %q", err, test.want)
			}
		})
	}
}

func TestLoadRequiresBoundedMetricsToken(t *testing.T) {
	for name, value := range map[string]string{
		"missing":   "",
		"short":     strings.Repeat("x", 31),
		"oversized": strings.Repeat("x", 4097),
		"multiline": strings.Repeat("x", 32) + "\nsecret",
	} {
		t.Run(name, func(t *testing.T) {
			setRequiredConfig(t)
			t.Setenv("DOCKYARD_METRICS_TOKEN", value)
			if _, err := Load(); err == nil || !strings.Contains(err.Error(), "DOCKYARD_METRICS_TOKEN") {
				t.Fatalf("error=%v", err)
			}
		})
	}
}

func TestLoadReadsMetricsTokenFromFileAndRejectsAmbiguousSources(t *testing.T) {
	path := filepath.Join(t.TempDir(), "metrics-token")
	const token = "metrics-token-from-a-secure-file-123456"
	if err := os.WriteFile(path, []byte(token+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	setRequiredConfig(t)
	t.Setenv("DOCKYARD_METRICS_TOKEN", "")
	t.Setenv("DOCKYARD_METRICS_TOKEN_FILE", path)
	cfg, err := Load()
	if err != nil || cfg.MetricsToken != token {
		t.Fatalf("metrics token=%q error=%v", cfg.MetricsToken, err)
	}
	t.Setenv("DOCKYARD_METRICS_TOKEN", "another-metrics-token-at-least-32-bytes")
	if _, err = Load(); err == nil || !strings.Contains(err.Error(), "cannot both be configured") {
		t.Fatalf("error=%v", err)
	}
}

func TestLoadRequiresVerifiedDatabaseTLSWhenConfigured(t *testing.T) {
	setRequiredConfig(t)
	t.Setenv("DOCKYARD_REQUIRE_DATABASE_TLS", "true")
	for _, databaseURL := range []string{
		"postgres://dockyard@example.test/dockyard",
		"postgres://dockyard@example.test/dockyard?sslmode=disable",
		"postgres://dockyard@example.test/dockyard?sslmode=require",
		"postgres://dockyard@example.test/dockyard?sslmode=verify-full&sslmode=disable",
		"postgres://dockyard@example.test/dockyard?sslmode=disable&sslmode=verify-full",
		"postgres://dockyard@example.test/dockyard?sslmode=verify-full&sslmode=verify-full",
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

func TestValidateBundledDatabaseCredentials(t *testing.T) {
	const password = "correct horse battery staple"
	for _, databaseURL := range []string{
		"postgres://dockyard:correct%20horse%20battery%20staple@postgres/dockyard?sslmode=disable",
		"postgresql://dockyard:correct%20horse%20battery%20staple@POSTGRES:5432/dockyard?connect_timeout=5&sslmode=disable",
	} {
		if err := ValidateBundledDatabaseCredentials(password, databaseURL); err != nil {
			t.Fatalf("valid bundled URL %q rejected: %v", databaseURL, err)
		}
	}
	for _, test := range []struct {
		password    string
		databaseURL string
	}{
		{password: "short", databaseURL: "postgres://dockyard:short@postgres/dockyard?sslmode=disable"},
		{password: password + "\n", databaseURL: "postgres://dockyard:correct%20horse%20battery%20staple@postgres/dockyard?sslmode=disable"},
		{password: password, databaseURL: "postgres://dockyard:wrong@postgres/dockyard?sslmode=disable"},
		{password: password, databaseURL: "postgres://other:correct%20horse%20battery%20staple@postgres/dockyard?sslmode=disable"},
		{password: password, databaseURL: "postgres://dockyard:correct%20horse%20battery%20staple@database/dockyard?sslmode=disable"},
		{password: password, databaseURL: "postgres://dockyard:correct%20horse%20battery%20staple@postgres/other?sslmode=disable"},
		{password: password, databaseURL: "postgres://dockyard:correct%20horse%20battery%20staple@postgres:5433/dockyard?sslmode=disable"},
		{password: password, databaseURL: "postgres://dockyard:correct%20horse%20battery%20staple@postgres/dockyard"},
		{password: password, databaseURL: "postgres://dockyard:correct%20horse%20battery%20staple@postgres/dockyard?sslmode=require"},
	} {
		if err := ValidateBundledDatabaseCredentials(test.password, test.databaseURL); err == nil {
			t.Errorf("password length=%d URL %q was accepted", len(test.password), test.databaseURL)
		}
	}
}

func TestLoadRejectsMalformedDatabaseURLWithoutTLSRequirement(t *testing.T) {
	for _, databaseURL := range []string{
		"",
		"host=example.test dbname=dockyard",
		"http://example.test/dockyard",
		"postgres:///dockyard",
		"postgres://example.test",
		"postgres://example.test/",
		"postgres://example.test:0/dockyard",
		"postgres://example.test:65536/dockyard",
		"postgres://example.test/dockyard#fragment",
		"postgres://example.test/dockyard?sslmode=require&sslmode=disable",
	} {
		t.Run(databaseURL, func(t *testing.T) {
			setRequiredConfig(t)
			t.Setenv("DOCKYARD_DATABASE_URL", databaseURL)
			if _, err := Load(); err == nil || !strings.Contains(err.Error(), "DOCKYARD_DATABASE_URL") {
				t.Fatalf("error=%v", err)
			}
		})
	}
	for _, databaseURL := range []string{
		"postgres://dockyard@example.test/dockyard",
		"postgresql://dockyard:secret@example.test:5432/dockyard?sslmode=disable",
	} {
		t.Run("valid_"+databaseURL, func(t *testing.T) {
			setRequiredConfig(t)
			t.Setenv("DOCKYARD_DATABASE_URL", databaseURL)
			if _, err := Load(); err != nil {
				t.Fatal(err)
			}
		})
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

func TestLoadSupportsDualTrustAgentCARollover(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	oldCA, _, certFile, keyFile, oldExpiry, serverExpiry := testAgentCredentials(t, now.Add(-time.Minute), now.Add(24*time.Hour))
	newCA, newKey, err := agentpki.NewCA(now, 30*24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	setAgentConfig(t, newCA, newKey, certFile, keyFile)
	t.Setenv("DOCKYARD_AGENT_PREVIOUS_CA_CERT", string(oldCA))
	cfg, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if cfg.AgentPreviousCAExpiresAt.IsZero() || !cfg.AgentPreviousCAExpiresAt.Equal(oldExpiry) || !cfg.AgentServerCertExpiresAt.Equal(serverExpiry) {
		t.Fatalf("previous CA expiry=%v server expiry=%v", cfg.AgentPreviousCAExpiresAt, cfg.AgentServerCertExpiresAt)
	}
	if _, authorities, err := agentpki.ValidateTrustBundle(cfg.AgentCATrustBundle, now); err != nil || len(authorities) != 2 {
		t.Fatalf("trust authorities=%d err=%v", len(authorities), err)
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
	t.Setenv("DOCKYARD_METRICS_TOKEN", "test-metrics-token-at-least-32-bytes")
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
