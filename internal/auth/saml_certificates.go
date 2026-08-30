package auth

import (
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"strings"
	"time"

	"github.com/crewjam/saml"
)

// SAMLServiceProviderCertificateExpiry parses and validates the certificate
// Dockyard uses to sign SAML requests. The expiry is returned even when the
// certificate is outside its validity window so operators can report it.
func SAMLServiceProviderCertificateExpiry(certificatePEM string, now time.Time) (time.Time, error) {
	block, _ := pem.Decode([]byte(certificatePEM))
	if block == nil || block.Type != "CERTIFICATE" {
		return time.Time{}, errors.New("invalid SAML service-provider certificate")
	}
	certificate, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return time.Time{}, errors.New("invalid SAML service-provider certificate")
	}
	if now.Before(certificate.NotBefore) || !now.Before(certificate.NotAfter) {
		return certificate.NotAfter, errors.New("SAML service-provider certificate is not currently valid")
	}
	return certificate.NotAfter, nil
}

// SAMLIdentityProviderCertificateExpiry returns the latest effective expiry
// among currently valid signing certificates. This permits normal IdP
// rollover metadata containing both old and new signing keys. Entity and role
// descriptor validUntil bounds are honored when they expire first.
func SAMLIdentityProviderCertificateExpiry(metadata *saml.EntityDescriptor, now time.Time) (time.Time, error) {
	if metadata == nil || len(metadata.IDPSSODescriptors) == 0 {
		return time.Time{}, errors.New("SAML metadata has no identity-provider descriptor")
	}
	var latest, latestUsable time.Time
	var found bool
	for _, descriptor := range metadata.IDPSSODescriptors {
		for _, key := range descriptor.KeyDescriptors {
			if key.Use != "" && key.Use != "signing" {
				continue
			}
			for _, encoded := range key.KeyInfo.X509Data.X509Certificates {
				found = true
				der, err := base64.StdEncoding.DecodeString(strings.Join(strings.Fields(encoded.Data), ""))
				if err != nil {
					return time.Time{}, errors.New("SAML metadata contains an invalid signing certificate")
				}
				certificate, err := x509.ParseCertificate(der)
				if err != nil {
					return time.Time{}, errors.New("SAML metadata contains an invalid signing certificate")
				}
				expiresAt := certificate.NotAfter
				if !metadata.ValidUntil.IsZero() && metadata.ValidUntil.Before(expiresAt) {
					expiresAt = metadata.ValidUntil
				}
				if descriptor.ValidUntil != nil && descriptor.ValidUntil.Before(expiresAt) {
					expiresAt = *descriptor.ValidUntil
				}
				if expiresAt.After(latest) {
					latest = expiresAt
				}
				if !now.Before(certificate.NotBefore) && now.Before(expiresAt) && expiresAt.After(latestUsable) {
					latestUsable = expiresAt
				}
			}
		}
	}
	if !found {
		return time.Time{}, errors.New("SAML metadata has no signing certificate")
	}
	if latestUsable.IsZero() {
		return latest, errors.New("SAML metadata has no currently valid signing certificate")
	}
	return latestUsable, nil
}
