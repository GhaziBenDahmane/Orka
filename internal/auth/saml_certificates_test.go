package auth

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"math/big"
	"testing"
	"time"

	"github.com/crewjam/saml"
)

func TestSAMLCertificateExpiryValidationAndRollover(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	currentPEM, currentDER := testSAMLCertificate(t, now.Add(-time.Hour), now.Add(24*time.Hour))
	_, replacementDER := testSAMLCertificate(t, now.Add(-time.Hour), now.Add(30*24*time.Hour))
	_, expiredDER := testSAMLCertificate(t, now.Add(-48*time.Hour), now.Add(-24*time.Hour))

	if expiry, err := SAMLServiceProviderCertificateExpiry(currentPEM, now); err != nil || !expiry.Equal(now.Add(24*time.Hour)) {
		t.Fatalf("service-provider expiry=%s err=%v", expiry, err)
	}
	if _, err := SAMLServiceProviderCertificateExpiry("not a certificate", now); err == nil {
		t.Fatal("invalid service-provider certificate accepted")
	}

	metadataExpiry := now.Add(14 * 24 * time.Hour)
	metadata := &saml.EntityDescriptor{ValidUntil: metadataExpiry, IDPSSODescriptors: []saml.IDPSSODescriptor{{SSODescriptor: saml.SSODescriptor{RoleDescriptor: saml.RoleDescriptor{KeyDescriptors: []saml.KeyDescriptor{
		{Use: "signing", KeyInfo: saml.KeyInfo{X509Data: saml.X509Data{X509Certificates: []saml.X509Certificate{{Data: base64.StdEncoding.EncodeToString(expiredDER)}}}}},
		{Use: "signing", KeyInfo: saml.KeyInfo{X509Data: saml.X509Data{X509Certificates: []saml.X509Certificate{{Data: base64.StdEncoding.EncodeToString(currentDER)}, {Data: base64.StdEncoding.EncodeToString(replacementDER)}}}}},
	}}}}}}
	if expiry, err := SAMLIdentityProviderCertificateExpiry(metadata, now); err != nil || !expiry.Equal(metadataExpiry) {
		t.Fatalf("identity-provider rollover expiry=%s err=%v", expiry, err)
	}

	metadata.ValidUntil = now.Add(-time.Minute)
	if expiry, err := SAMLIdentityProviderCertificateExpiry(metadata, now); err == nil || !expiry.Equal(metadata.ValidUntil) {
		t.Fatalf("expired metadata expiry=%s err=%v", expiry, err)
	}
}

func testSAMLCertificate(t *testing.T, notBefore, notAfter time.Time) (string, []byte) {
	t.Helper()
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.CreateCertificate(rand.Reader, &x509.Certificate{SerialNumber: big.NewInt(notAfter.UnixNano()), Subject: pkix.Name{CommonName: "saml.test"}, NotBefore: notBefore, NotAfter: notAfter, KeyUsage: x509.KeyUsageDigitalSignature}, &x509.Certificate{SerialNumber: big.NewInt(notAfter.UnixNano()), Subject: pkix.Name{CommonName: "saml.test"}, NotBefore: notBefore, NotAfter: notAfter, KeyUsage: x509.KeyUsageDigitalSignature}, publicKey, privateKey)
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})), der
}
