package httpapi

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"testing"

	"github.com/crewjam/saml"
)

func TestNewSAMLCertificateAndAttributeLookup(t *testing.T) {
	key, certificatePEM, keyPEM, err := newSAMLCertificate("Workforce")
	if err != nil {
		t.Fatal(err)
	}
	certificateBlock, _ := pem.Decode(certificatePEM)
	if certificateBlock == nil {
		t.Fatal("certificate is not PEM encoded")
	}
	certificate, err := x509.ParseCertificate(certificateBlock.Bytes)
	if err != nil || certificate.Subject.CommonName != "Workforce" {
		t.Fatalf("certificate subject = %q, err = %v", certificate.Subject.CommonName, err)
	}
	keyBlock, _ := pem.Decode(keyPEM)
	parsedKey, err := x509.ParsePKCS8PrivateKey(keyBlock.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	if parsedKey.(*rsa.PrivateKey).PublicKey.N.Cmp(key.PublicKey.N) != 0 {
		t.Fatal("encoded private key does not match certificate key")
	}

	assertion := &saml.Assertion{AttributeStatements: []saml.AttributeStatement{{Attributes: []saml.Attribute{
		{Name: "urn:email", FriendlyName: "mail", Values: []saml.AttributeValue{{Value: " person@example.test "}}},
	}}}}
	if value := samlAttribute(assertion, "MAIL"); value != "person@example.test" {
		t.Fatalf("attribute value = %q", value)
	}
}
