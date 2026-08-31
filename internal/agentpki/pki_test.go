package agentpki

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"strings"
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

func TestSignAgentCSRRejectsOversizedAndTrailingInput(t *testing.T) {
	now := time.Now().UTC()
	caPEM, caKey, err := NewCA(now, 24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	for _, csr := range [][]byte{
		bytes.Repeat([]byte("x"), MaxCSRPEMBytes+1),
		[]byte("-----BEGIN CERTIFICATE REQUEST-----\nAA==\n-----END CERTIFICATE REQUEST-----\ntrailing"),
	} {
		if _, _, err = SignAgentCSR(caPEM, caKey, csr, uuid.New(), now, time.Hour); err == nil {
			t.Fatal("invalid CSR input was accepted")
		}
	}
}

func TestSignAgentCSRRejectsWeakPublicKey(t *testing.T) {
	now := time.Now().UTC()
	caPEM, caKey, err := NewCA(now, 24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	weakKey, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatal(err)
	}
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{}, weakKey)
	if err != nil {
		t.Fatal(err)
	}
	csrPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrDER})
	if _, _, err = SignAgentCSR(caPEM, caKey, csrPEM, uuid.New(), now, time.Hour); err == nil {
		t.Fatal("weak agent public key was accepted")
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

func TestSignAgentCSRRejectsNotYetValidCA(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	caPEM, caKey, err := NewCA(now.Add(time.Hour), 24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	agentKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{}, agentKey)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err = SignAgentCSR(caPEM, caKey, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrDER}), uuid.New(), now, time.Hour); err == nil || !strings.Contains(err.Error(), "not currently valid") {
		t.Fatalf("not-yet-valid CA error=%v", err)
	}
}

func TestValidateAuthorityAcceptsPKCS8RSAKey(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	certificatePEM, pkcs1PEM, err := NewCA(now, 24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	block, rest := pem.Decode(pkcs1PEM)
	if block == nil || len(rest) != 0 {
		t.Fatal("decode generated CA private key")
	}
	key, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	pkcs8PEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: encoded})
	if _, err = ValidateAuthority(certificatePEM, pkcs8PEM, now); err != nil {
		t.Fatalf("validate PKCS#8 RSA authority: %v", err)
	}
}

func TestSignAgentCSRSupportsECDSAAndEd25519Authorities(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	ecdsaKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	ecdsaDER, err := x509.MarshalECPrivateKey(ecdsaKey)
	if err != nil {
		t.Fatal(err)
	}
	_, ed25519Key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	ed25519DER, err := x509.MarshalPKCS8PrivateKey(ed25519Key)
	if err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name     string
		signer   crypto.Signer
		keyBlock *pem.Block
	}{
		{name: "ECDSA SEC1", signer: ecdsaKey, keyBlock: &pem.Block{Type: "EC PRIVATE KEY", Bytes: ecdsaDER}},
		{name: "Ed25519 PKCS#8", signer: ed25519Key, keyBlock: &pem.Block{Type: "PRIVATE KEY", Bytes: ed25519DER}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			serial, serialErr := randomSerial()
			if serialErr != nil {
				t.Fatal(serialErr)
			}
			template := &x509.Certificate{SerialNumber: serial, Subject: pkix.Name{CommonName: "Test Agent CA"}, NotBefore: now.Add(-time.Minute), NotAfter: now.Add(24 * time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature}
			certificateDER, createErr := x509.CreateCertificate(rand.Reader, template, template, test.signer.Public(), test.signer)
			if createErr != nil {
				t.Fatal(createErr)
			}
			certificatePEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certificateDER})
			keyPEM := pem.EncodeToMemory(test.keyBlock)
			if _, validateErr := ValidateAuthority(certificatePEM, keyPEM, now); validateErr != nil {
				t.Fatalf("validate authority: %v", validateErr)
			}

			agentKey, generateErr := rsa.GenerateKey(rand.Reader, 2048)
			if generateErr != nil {
				t.Fatal(generateErr)
			}
			csrDER, createErr := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{}, agentKey)
			if createErr != nil {
				t.Fatal(createErr)
			}
			agentCertificatePEM, _, signErr := SignAgentCSR(certificatePEM, keyPEM, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrDER}), uuid.New(), now, time.Hour)
			if signErr != nil {
				t.Fatalf("sign agent CSR: %v", signErr)
			}
			agentBlock, _ := pem.Decode(agentCertificatePEM)
			agentCertificate, parseErr := x509.ParseCertificate(agentBlock.Bytes)
			if parseErr != nil {
				t.Fatal(parseErr)
			}
			roots := x509.NewCertPool()
			roots.AppendCertsFromPEM(certificatePEM)
			if _, verifyErr := agentCertificate.Verify(x509.VerifyOptions{Roots: roots, CurrentTime: now, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}); verifyErr != nil {
				t.Fatalf("verify signed agent certificate: %v", verifyErr)
			}

			serverSerial, serialErr := randomSerial()
			if serialErr != nil {
				t.Fatal(serialErr)
			}
			serverTemplate := &x509.Certificate{SerialNumber: serverSerial, Subject: pkix.Name{CommonName: "agents.example.test"}, DNSNames: []string{"agents.example.test"}, NotBefore: now.Add(-time.Minute), NotAfter: now.Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
			serverDER, createErr := x509.CreateCertificate(rand.Reader, serverTemplate, template, &agentKey.PublicKey, test.signer)
			if createErr != nil {
				t.Fatal(createErr)
			}
			serverPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: serverDER})
			serverKeyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(agentKey)})
			if _, _, validateErr := ValidateServerCredentials(certificatePEM, keyPEM, serverPEM, serverKeyPEM, now); validateErr != nil {
				t.Fatalf("validate server credentials: %v", validateErr)
			}
		})
	}
}

func TestValidateAuthorityRejectsAmbiguousPEM(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	certificatePEM, keyPEM, err := NewCA(now, 24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = ValidateAuthority(append(append([]byte{}, certificatePEM...), certificatePEM...), keyPEM, now); err == nil {
		t.Fatal("accepted multiple CA certificates")
	}
	if _, err = ValidateAuthority(certificatePEM, append(append([]byte{}, keyPEM...), keyPEM...), now); err == nil {
		t.Fatal("accepted multiple CA private keys")
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
