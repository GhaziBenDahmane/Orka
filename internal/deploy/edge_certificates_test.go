package deploy

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
)

func TestReconcileEdgeCertificatesUsesVersionedSecretsAndAtomicServiceUpdate(t *testing.T) {
	directory := t.TempDir()
	dockerBin := filepath.Join(directory, "docker")
	logPath := filepath.Join(directory, "commands")
	script := `#!/bin/sh
set -eu
printf '%s\n' "$*" >>"$EDGE_TEST_LOG"
case "$1 $2" in
  "service inspect")
    case "$*" in
      *ContainerSpec.Secrets*) printf '%s\n' 'null' ;;
      *ContainerSpec.Configs*) printf '%s\n' 'null' ;;
      *UpdateStatus*) printf '%s\n' '{"State":"completed"}' ;;
      *) printf '%s' '[{"Spec":{"TaskTemplate":{"ContainerSpec":{"Args":["--providers.file.directory=/etc/traefik/dynamic"]},"Networks":[{"Target":"network-id"}]}}}]' ;;
    esac ;;
  "network inspect") printf '%s\n' 'network-id' ;;
  "secret inspect"|"config inspect") exit 1 ;;
  "secret create"|"config create")
    destination="$EDGE_TEST_DIR/$1-$7"
    dd of="$destination" 2>/dev/null ;;
  "service update") ;;
  "secret ls"|"config ls") ;;
  *) exit 1 ;;
esac
`
	if err := os.WriteFile(dockerBin, []byte(script), 0700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("EDGE_TEST_LOG", logPath)
	t.Setenv("EDGE_TEST_DIR", directory)
	certificatePEM, privateKeyPEM, fingerprint := edgeTestCertificate(t)
	manager := Swarm{DockerBin: dockerBin, Network: "dockyard-public", Timeout: time.Second}
	material := EdgeCertificateMaterial{ID: uuid.MustParse("aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"), Revision: 1, Fingerprint: fingerprint, CertificatePEM: certificatePEM, PrivateKeyPEM: privateKeyPEM}
	if err := manager.ReconcileEdgeCertificates(context.Background(), EdgeProxySpec{ServiceName: "edge_traefik", DynamicConfigurationPath: "/etc/traefik/dynamic"}, []EdgeCertificateMaterial{material}); err != nil {
		t.Fatal(err)
	}
	commands, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(commands), "PRIVATE KEY") || !strings.Contains(string(commands), "service update --detach=true --update-order stop-first --update-failure-action rollback") || !strings.Contains(string(commands), "--secret-add") || !strings.Contains(string(commands), "--config-add") {
		t.Fatalf("unexpected or secret-bearing Docker command log: %s", commands)
	}
	configFiles, _ := filepath.Glob(filepath.Join(directory, "config-dockyard-edge-tls-*"))
	if len(configFiles) != 1 {
		t.Fatalf("dynamic configs=%v", configFiles)
	}
	configuration, err := os.ReadFile(configFiles[0])
	if err != nil || !strings.Contains(string(configuration), "certFile: /run/secrets/dockyard-tls-") || !strings.Contains(string(configuration), "keyFile: /run/secrets/dockyard-tls-") {
		t.Fatalf("dynamic configuration=%q error=%v", configuration, err)
	}
}

func edgeTestCertificate(t *testing.T) (string, string, string) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	template := &x509.Certificate{SerialNumber: big.NewInt(42), Subject: pkix.Name{CommonName: "edge.example.test"}, DNSNames: []string{"edge.example.test"}, NotBefore: now.Add(-time.Minute), NotAfter: now.Add(48 * time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	raw, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	fingerprint := sha256.Sum256(raw)
	certificatePEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: raw})
	privateKeyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
	return string(certificatePEM), string(privateKeyPEM), "sha256:" + hex.EncodeToString(fingerprint[:])
}
