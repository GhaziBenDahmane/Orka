package agentpki

import (
	"crypto/rand"
	"crypto/rsa"
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

func parseCA(certPEM, keyPEM []byte) (*x509.Certificate, *rsa.PrivateKey, error) {
	certBlock, _ := pem.Decode(certPEM)
	keyBlock, _ := pem.Decode(keyPEM)
	if certBlock == nil || keyBlock == nil {
		return nil, nil, errors.New("invalid CA PEM")
	}
	cert, err := x509.ParseCertificate(certBlock.Bytes)
	if err != nil || !cert.IsCA {
		return nil, nil, errors.New("invalid CA certificate")
	}
	key, err := x509.ParsePKCS1PrivateKey(keyBlock.Bytes)
	if err != nil {
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
