package agentpki

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net/url"
	"time"

	"github.com/google/uuid"
)

const identityPrefix = "spiffe://dockyard/cluster/"

func NewCA(now time.Time, lifetime time.Duration) ([]byte, []byte, error) {
	if lifetime < 24*time.Hour {
		return nil, nil, errors.New("CA lifetime must be at least 24 hours")
	}
	key, err := rsa.GenerateKey(rand.Reader, 3072)
	if err != nil {
		return nil, nil, err
	}
	serial, err := randomSerial()
	if err != nil {
		return nil, nil, err
	}
	template := &x509.Certificate{SerialNumber: serial, Subject: pkix.Name{CommonName: "Dockyard Agent CA"}, NotBefore: now.Add(-5 * time.Minute), NotAfter: now.Add(lifetime), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		return nil, nil, err
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
	return certPEM, keyPEM, nil
}

func SignAgentCSR(caCertPEM, caKeyPEM, csrPEM []byte, clusterID uuid.UUID, now time.Time, lifetime time.Duration) ([]byte, *x509.Certificate, error) {
	if lifetime < 5*time.Minute || lifetime > 30*24*time.Hour {
		return nil, nil, errors.New("agent certificate lifetime must be between 5 minutes and 30 days")
	}
	ca, key, err := parseCA(caCertPEM, caKeyPEM)
	if err != nil {
		return nil, nil, err
	}
	block, _ := pem.Decode(csrPEM)
	if block == nil || block.Type != "CERTIFICATE REQUEST" {
		return nil, nil, errors.New("invalid PEM certificate request")
	}
	csr, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil || csr.CheckSignature() != nil {
		return nil, nil, errors.New("invalid certificate request signature")
	}
	serial, err := randomSerial()
	if err != nil {
		return nil, nil, err
	}
	identity, _ := url.Parse(identityPrefix + clusterID.String())
	notAfter := now.Add(lifetime)
	if notAfter.After(ca.NotAfter) {
		notAfter = ca.NotAfter
	}
	if !notAfter.After(now.Add(5 * time.Minute)) {
		return nil, nil, errors.New("agent CA expires too soon to issue a certificate")
	}
	template := &x509.Certificate{SerialNumber: serial, Subject: pkix.Name{CommonName: "dockyard-agent-" + clusterID.String()}, URIs: []*url.URL{identity}, NotBefore: now.Add(-time.Minute), NotAfter: notAfter, KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}
	der, err := x509.CreateCertificate(rand.Reader, template, ca, csr.PublicKey, key)
	if err != nil {
		return nil, nil, err
	}
	cert, err := x509.ParseCertificate(der)
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), cert, err
}

func ClusterIdentity(cert *x509.Certificate) (uuid.UUID, error) {
	if cert == nil || len(cert.URIs) != 1 || cert.URIs[0].Scheme != "spiffe" || cert.URIs[0].Host != "dockyard" {
		return uuid.Nil, errors.New("certificate does not contain a Dockyard cluster identity")
	}
	prefix := "/cluster/"
	if len(cert.URIs[0].Path) <= len(prefix) || cert.URIs[0].Path[:len(prefix)] != prefix {
		return uuid.Nil, errors.New("certificate has an invalid Dockyard cluster identity")
	}
	id, err := uuid.Parse(cert.URIs[0].Path[len(prefix):])
	if err != nil {
		return uuid.Nil, fmt.Errorf("parse cluster identity: %w", err)
	}
	return id, nil
}

func CertificateFingerprint(certificatePEM []byte) (string, error) {
	block, rest := pem.Decode(certificatePEM)
	if block == nil || block.Type != "CERTIFICATE" || len(bytes.TrimSpace(rest)) != 0 {
		return "", errors.New("invalid certificate PEM")
	}
	if _, err := x509.ParseCertificate(block.Bytes); err != nil {
		return "", errors.New("invalid certificate")
	}
	sum := sha256.Sum256(block.Bytes)
	return fmt.Sprintf("sha256:%x", sum[:]), nil
}

func ValidateServerCredentials(caCertPEM, caKeyPEM, serverCertPEM, serverKeyPEM []byte, now time.Time) (*x509.Certificate, *x509.Certificate, error) {
	return ValidateServerCredentialsWithTrust(caCertPEM, caKeyPEM, caCertPEM, serverCertPEM, serverKeyPEM, now)
}

// ValidateServerCredentialsWithTrust verifies that the active signing CA and
// key match while allowing the listener certificate to chain to any currently
// trusted CA. This enables a bounded dual-trust CA rollover.
func ValidateServerCredentialsWithTrust(caCertPEM, caKeyPEM, trustBundlePEM, serverCertPEM, serverKeyPEM []byte, now time.Time) (*x509.Certificate, *x509.Certificate, error) {
	ca, err := ValidateAuthority(caCertPEM, caKeyPEM, now)
	if err != nil {
		return nil, nil, err
	}

	pair, err := tls.X509KeyPair(serverCertPEM, serverKeyPEM)
	if err != nil || len(pair.Certificate) == 0 {
		return nil, nil, errors.New("invalid agent server certificate or private key")
	}
	server, err := x509.ParseCertificate(pair.Certificate[0])
	if err != nil {
		return nil, nil, errors.New("invalid agent server certificate")
	}
	roots, _, err := ValidateTrustBundle(trustBundlePEM, now)
	if err != nil {
		return nil, nil, err
	}
	intermediates := x509.NewCertPool()
	for _, encoded := range pair.Certificate[1:] {
		certificate, parseErr := x509.ParseCertificate(encoded)
		if parseErr != nil {
			return nil, nil, errors.New("invalid agent server certificate chain")
		}
		intermediates.AddCert(certificate)
	}
	if _, err = server.Verify(x509.VerifyOptions{Roots: roots, Intermediates: intermediates, CurrentTime: now, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}); err != nil {
		return nil, nil, fmt.Errorf("verify agent server certificate: %w", err)
	}
	return ca, server, nil
}

// ValidateTrustBundle accepts one or more currently valid, self-signed CA
// certificates and returns a pool suitable for mutual TLS verification.
func ValidateTrustBundle(bundle []byte, now time.Time) (*x509.CertPool, []*x509.Certificate, error) {
	pool := x509.NewCertPool()
	certificates := []*x509.Certificate{}
	rest := bundle
	for len(bytes.TrimSpace(rest)) != 0 {
		block, remaining := pem.Decode(rest)
		if block == nil || block.Type != "CERTIFICATE" {
			return nil, nil, errors.New("invalid agent CA trust bundle")
		}
		certificate, err := x509.ParseCertificate(block.Bytes)
		if err != nil || !certificate.IsCA || certificate.KeyUsage&x509.KeyUsageCertSign == 0 || now.Before(certificate.NotBefore) || !now.Before(certificate.NotAfter) || certificate.CheckSignatureFrom(certificate) != nil {
			return nil, nil, errors.New("agent CA trust bundle contains an invalid authority")
		}
		pool.AddCert(certificate)
		certificates = append(certificates, certificate)
		rest = remaining
	}
	if len(certificates) == 0 {
		return nil, nil, errors.New("agent CA trust bundle is empty")
	}
	return pool, certificates, nil
}

func ValidateAuthority(caCertPEM, caKeyPEM []byte, now time.Time) (*x509.Certificate, error) {
	ca, _, err := parseCA(caCertPEM, caKeyPEM)
	if err != nil {
		return nil, err
	}
	if now.Before(ca.NotBefore) || !now.Before(ca.NotAfter) || ca.KeyUsage&x509.KeyUsageCertSign == 0 {
		return nil, errors.New("agent CA certificate is not currently valid for signing")
	}
	if err = ca.CheckSignatureFrom(ca); err != nil {
		return nil, errors.New("agent CA certificate is not self-signed")
	}
	return ca, nil
}

func parseCA(certPEM, keyPEM []byte) (*x509.Certificate, *rsa.PrivateKey, error) {
	certBlock, certRest := pem.Decode(certPEM)
	keyBlock, keyRest := pem.Decode(keyPEM)
	if certBlock == nil || certBlock.Type != "CERTIFICATE" || len(bytes.TrimSpace(certRest)) != 0 || keyBlock == nil || len(bytes.TrimSpace(keyRest)) != 0 {
		return nil, nil, errors.New("invalid CA PEM")
	}
	cert, err := x509.ParseCertificate(certBlock.Bytes)
	if err != nil || !cert.IsCA {
		return nil, nil, errors.New("invalid CA certificate")
	}
	var key *rsa.PrivateKey
	switch keyBlock.Type {
	case "RSA PRIVATE KEY":
		key, err = x509.ParsePKCS1PrivateKey(keyBlock.Bytes)
	case "PRIVATE KEY":
		var parsed any
		parsed, err = x509.ParsePKCS8PrivateKey(keyBlock.Bytes)
		if err == nil {
			var ok bool
			key, ok = parsed.(*rsa.PrivateKey)
			if !ok {
				err = errors.New("private key is not RSA")
			}
		}
	default:
		err = errors.New("unsupported private key PEM type")
	}
	if err != nil || key == nil || key.Validate() != nil {
		return nil, nil, errors.New("invalid CA private key")
	}
	publicKey, ok := cert.PublicKey.(*rsa.PublicKey)
	if !ok || !publicKey.Equal(&key.PublicKey) {
		return nil, nil, errors.New("CA certificate and key do not match")
	}
	return cert, key, nil
}

func randomSerial() (*big.Int, error) {
	limit := new(big.Int).Lsh(big.NewInt(1), 128)
	return rand.Int(rand.Reader, limit)
}
