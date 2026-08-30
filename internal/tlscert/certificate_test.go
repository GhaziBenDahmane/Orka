package tlscert

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"testing"
	"time"
)

func TestValidateAndHostnameCoverage(t *testing.T) {
	now := time.Now().UTC()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "app.example.test"}, DNSNames: []string{"app.example.test", "*.apps.example.test"}, NotBefore: now.Add(-time.Minute), NotAfter: now.Add(48 * time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	raw, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	certificatePEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: raw})
	privateKeyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
	metadata, err := Validate(certificatePEM, privateKeyPEM, now)
	if err != nil || metadata.Fingerprint == "" || len(metadata.DNSNames) != 2 {
		t.Fatalf("metadata=%#v error=%v", metadata, err)
	}
	if !CoversHostname(certificatePEM, "one.apps.example.test") || CoversHostname(certificatePEM, "nested.one.apps.example.test") {
		t.Fatal("wildcard hostname coverage did not follow X.509 rules")
	}
	if _, err = Validate(certificatePEM, privateKeyPEM, now.Add(47*time.Hour)); err == nil {
		t.Fatal("expected nearly expired certificate to be rejected")
	}
}
