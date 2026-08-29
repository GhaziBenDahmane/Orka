package agentpki

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"testing"
	"time"

	"github.com/google/uuid"
)

func TestSignAgentCSRBindsClusterIdentity(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	caPEM, caKey, err := NewCA(now, 365*24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{Subject: pkix.Name{CommonName: "untrusted-name"}}, key)
	if err != nil {
		t.Fatal(err)
	}
	clusterID := uuid.New()
	certPEM, cert, err := SignAgentCSR(caPEM, caKey, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrDER}), clusterID, now, 24*time.Hour)
	if err != nil || len(certPEM) == 0 {
		t.Fatalf("sign: %v", err)
	}
	if got, err := ClusterIdentity(cert); err != nil || got != clusterID {
		t.Fatalf("identity=%s err=%v", got, err)
	}
	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(caPEM)
	if _, err := cert.Verify(x509.VerifyOptions{Roots: pool, CurrentTime: now, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}); err != nil {
		t.Fatal(err)
	}
}

func TestSignAgentCSRRejectsTampering(t *testing.T) {
	now := time.Now()
	caPEM, caKey, _ := NewCA(now, 24*time.Hour)
	if _, _, err := SignAgentCSR(caPEM, caKey, []byte("not a csr"), uuid.New(), now, time.Hour); err == nil {
		t.Fatal("expected malformed CSR rejection")
	}
}

func TestSignAgentCSRRejectsCAWithoutMinimumRemainingLifetime(t *testing.T) {
	now := time.Now()
	caPEM, caKey, err := NewCA(now, 24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{}, key)
	if err != nil {
		t.Fatal(err)
	}
	nearCAExpiry := now.Add(24*time.Hour - 4*time.Minute)
	if _, _, err = SignAgentCSR(caPEM, caKey, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrDER}), uuid.New(), nearCAExpiry, time.Hour); err == nil {
		t.Fatal("expected certificate issuance to fail near CA expiry")
	}
}
