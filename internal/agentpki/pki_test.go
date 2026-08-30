package agentpki

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
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

func TestValidateServerCredentials(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	caPEM, caKeyPEM, err := NewCA(now, 24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	ca, caKey, err := parseCA(caPEM, caKeyPEM)
	if err != nil {
		t.Fatal(err)
	}
	serverKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	serial, err := randomSerial()
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{SerialNumber: serial, Subject: pkix.Name{CommonName: "agents.example.test"}, DNSNames: []string{"agents.example.test"}, NotBefore: now.Add(-time.Minute), NotAfter: now.Add(12 * time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	encoded, err := x509.CreateCertificate(rand.Reader, template, ca, &serverKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	serverPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: encoded})
	serverKeyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(serverKey)})
	validatedCA, validatedServer, err := ValidateServerCredentials(caPEM, caKeyPEM, serverPEM, serverKeyPEM, now)
	if err != nil || !validatedCA.NotAfter.Equal(ca.NotAfter) || !validatedServer.NotAfter.Equal(template.NotAfter) {
		t.Fatalf("CA=%v server=%v err=%v", validatedCA, validatedServer, err)
	}
	otherKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	otherKeyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(otherKey)})
	if _, _, err = ValidateServerCredentials(caPEM, caKeyPEM, serverPEM, otherKeyPEM, now); err == nil {
		t.Fatal("mismatched server private key was accepted")
	}
	if _, _, err = ValidateServerCredentials(caPEM, caKeyPEM, serverPEM, serverKeyPEM, now.Add(13*time.Hour)); err == nil {
		t.Fatal("expired server certificate was accepted")
	}
}

func TestValidateServerCredentialsWithDualTrust(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	oldCA, oldKey, err := NewCA(now, 48*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	newCA, newKey, err := NewCA(now, 48*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	oldCertificate, oldPrivateKey, err := parseCA(oldCA, oldKey)
	if err != nil {
		t.Fatal(err)
	}
	serverKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{SerialNumber: big.NewInt(42), Subject: pkix.Name{CommonName: "agents.example.test"}, DNSNames: []string{"agents.example.test"}, NotBefore: now.Add(-time.Minute), NotAfter: now.Add(24 * time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	encoded, err := x509.CreateCertificate(rand.Reader, template, oldCertificate, &serverKey.PublicKey, oldPrivateKey)
	if err != nil {
		t.Fatal(err)
	}
	serverPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: encoded})
	serverKeyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(serverKey)})
	bundle := append(append([]byte{}, newCA...), oldCA...)
	if _, _, err = ValidateServerCredentialsWithTrust(newCA, newKey, bundle, serverPEM, serverKeyPEM, now); err != nil {
		t.Fatalf("old listener under dual trust: %v", err)
	}
	if _, _, err = ValidateServerCredentialsWithTrust(newCA, newKey, newCA, serverPEM, serverKeyPEM, now); err == nil {
		t.Fatal("old listener certificate was accepted after removing the old CA")
	}
	if _, _, err = ValidateTrustBundle(append(bundle, []byte("not pem")...), now); err == nil {
		t.Fatal("malformed trailing trust data was accepted")
	}
}
