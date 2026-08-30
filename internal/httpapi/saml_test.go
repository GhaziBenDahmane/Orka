package httpapi

import (
	"bytes"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"testing"

	"github.com/bendahma/dokploy-go/internal/cryptox"
	"github.com/crewjam/saml"
	"github.com/google/uuid"
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
	box, err := cryptox.New(bytes.Repeat([]byte{9}, 32))
	if err != nil {
		t.Fatal(err)
	}
	providerID := uuid.New()
	encryptedKey, err := box.Encrypt(keyPEM, "saml-private-key:"+providerID.String())
	if err != nil {
		t.Fatal(err)
	}
	server := &Server{Box: box}
	if _, _, err = server.samlSigningMaterial(providerID, string(certificatePEM), encryptedKey); err != nil {
		t.Fatalf("matching SAML key rejected: %v", err)
	}
	_, _, otherKeyPEM, err := newSAMLCertificate("Other")
	if err != nil {
		t.Fatal(err)
	}
	encryptedOtherKey, err := box.Encrypt(otherKeyPEM, "saml-private-key:"+providerID.String())
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err = server.samlSigningMaterial(providerID, string(certificatePEM), encryptedOtherKey); err == nil {
		t.Fatal("mismatched SAML key was accepted")
	}

	assertion := &saml.Assertion{AttributeStatements: []saml.AttributeStatement{{Attributes: []saml.Attribute{
		{Name: "urn:email", FriendlyName: "mail", Values: []saml.AttributeValue{{Value: " person@example.test "}}},
	}}}}
	if value := samlAttribute(assertion, "MAIL"); value != "person@example.test" {
		t.Fatalf("attribute value = %q", value)
	}
}
