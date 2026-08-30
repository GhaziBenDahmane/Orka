package tlscert

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"sort"
	"strings"
	"time"
)

const (
	MaxCertificatePEMBytes = 128 << 10
	MaxPrivateKeyPEMBytes  = 64 << 10
)

type Metadata struct {
	Fingerprint string
	CommonName  string
	DNSNames    []string
	NotBefore   time.Time
	NotAfter    time.Time
}

func Validate(certificatePEM, privateKeyPEM []byte, now time.Time) (Metadata, error) {
	if len(certificatePEM) == 0 || len(certificatePEM) > MaxCertificatePEMBytes || len(privateKeyPEM) == 0 || len(privateKeyPEM) > MaxPrivateKeyPEMBytes {
		return Metadata{}, errors.New("certificate or private key size is invalid")
	}
	pair, err := tls.X509KeyPair(certificatePEM, privateKeyPEM)
	if err != nil || len(pair.Certificate) == 0 {
		return Metadata{}, errors.New("certificate chain and private key do not form a valid key pair")
	}
	certificates := make([]*x509.Certificate, 0, len(pair.Certificate))
	for _, raw := range pair.Certificate {
		certificate, parseErr := x509.ParseCertificate(raw)
		if parseErr != nil {
			return Metadata{}, errors.New("certificate chain contains an invalid certificate")
		}
		certificates = append(certificates, certificate)
	}
	if err = validateCertificatePEM(certificatePEM, len(certificates)); err != nil {
		return Metadata{}, err
	}
	if err = validatePrivateKey(pair.PrivateKey); err != nil {
		return Metadata{}, err
	}
	if err = validatePrivateKeyPEM(privateKeyPEM); err != nil {
		return Metadata{}, err
	}
	leaf := certificates[0]
	if leaf.IsCA || len(leaf.DNSNames) == 0 || leaf.NotBefore.After(now.Add(5*time.Minute)) || !leaf.NotAfter.After(now.Add(24*time.Hour)) {
		return Metadata{}, errors.New("certificate must be a currently valid non-CA server certificate with DNS SANs and more than 24 hours remaining")
	}
	if len(leaf.ExtKeyUsage) > 0 && !hasServerAuth(leaf.ExtKeyUsage) {
		return Metadata{}, errors.New("certificate is not valid for TLS server authentication")
	}
	for index := 0; index+1 < len(certificates); index++ {
		if err = certificates[index].CheckSignatureFrom(certificates[index+1]); err != nil {
			return Metadata{}, errors.New("certificate chain is not ordered leaf-first")
		}
	}
	names := append([]string(nil), leaf.DNSNames...)
	for index := range names {
		names[index] = strings.ToLower(strings.TrimSuffix(names[index], "."))
	}
	sort.Strings(names)
	names = compact(names)
	if len(names) > 100 {
		return Metadata{}, errors.New("certificate has more than 100 DNS SANs")
	}
	fingerprint := sha256.Sum256(leaf.Raw)
	return Metadata{Fingerprint: "sha256:" + hex.EncodeToString(fingerprint[:]), CommonName: leaf.Subject.CommonName, DNSNames: names, NotBefore: leaf.NotBefore, NotAfter: leaf.NotAfter}, nil
}

func validatePrivateKeyPEM(value []byte) error {
	block, remaining := pem.Decode(value)
	if block == nil || !strings.Contains(block.Type, "PRIVATE KEY") || len(block.Headers) != 0 || strings.TrimSpace(string(remaining)) != "" {
		return errors.New("private key PEM must contain exactly one unencrypted private-key block")
	}
	return nil
}

func CoversHostname(certificatePEM []byte, hostname string) bool {
	block, _ := pem.Decode(certificatePEM)
	if block == nil || block.Type != "CERTIFICATE" {
		return false
	}
	certificate, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return false
	}
	return certificate.VerifyHostname(strings.TrimSuffix(strings.ToLower(strings.TrimSpace(hostname)), ".")) == nil
}

func validateCertificatePEM(value []byte, expected int) error {
	remaining := value
	count := 0
	for {
		block, rest := pem.Decode(remaining)
		if block == nil {
			if strings.TrimSpace(string(remaining)) != "" {
				return errors.New("certificate PEM contains non-PEM data")
			}
			break
		}
		if block.Type != "CERTIFICATE" || len(block.Headers) != 0 {
			return errors.New("certificate PEM may contain only certificate blocks")
		}
		count++
		remaining = rest
	}
	if count != expected {
		return errors.New("certificate PEM chain is invalid")
	}
	return nil
}

func validatePrivateKey(key any) error {
	switch value := key.(type) {
	case *rsa.PrivateKey:
		if value.N.BitLen() < 2048 {
			return errors.New("RSA private key must be at least 2048 bits")
		}
	case *ecdsa.PrivateKey:
		if value.Curve.Params().BitSize < 256 {
			return errors.New("ECDSA private key curve is too small")
		}
	case ed25519.PrivateKey:
	default:
		return errors.New("private key algorithm must be RSA, ECDSA, or Ed25519")
	}
	return nil
}

func hasServerAuth(usages []x509.ExtKeyUsage) bool {
	for _, usage := range usages {
		if usage == x509.ExtKeyUsageServerAuth || usage == x509.ExtKeyUsageAny {
			return true
		}
	}
	return false
}

func compact(values []string) []string {
	if len(values) < 2 {
		return values
	}
	result := values[:1]
	for _, value := range values[1:] {
		if value != result[len(result)-1] {
			result = append(result, value)
		}
	}
	return result
}
