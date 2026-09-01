package controlplanerecovery

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"os"
	"regexp"
	"time"

	"github.com/GhaziBenDahmane/Orka/internal/agentpki"
	"github.com/GhaziBenDahmane/Orka/internal/ociref"
)

const (
	MaxManifestBytes  = 64 << 10
	MaxSignatureBytes = ed25519.SignatureSize
	MaxKeyBytes       = 32 << 10
	MasterKeyBytes    = 32
)

var (
	stackPattern    = regexp.MustCompile(`^[A-Za-z0-9_.-]{1,255}$`)
	databasePattern = regexp.MustCompile(`^[A-Za-z0-9_]{1,63}$`)
	schemaPattern   = regexp.MustCompile(`^[A-Za-z0-9._-]{1,255}$`)
	hashPattern     = regexp.MustCompile(`^[a-f0-9]{64}$`)
)

type Manifest struct {
	FormatVersion            int    `json:"formatVersion"`
	CreatedAt                string `json:"createdAt"`
	Stack                    string `json:"stack"`
	Database                 string `json:"database"`
	SchemaVersion            string `json:"schemaVersion"`
	ControllerImage          string `json:"controllerImage"`
	DatabaseSHA256           string `json:"databaseSha256"`
	DatabaseBytes            int64  `json:"databaseBytes"`
	MasterKeySHA256          string `json:"masterKeySha256"`
	AgentCASHA256            string `json:"agentCaSha256"`
	RecoverySigningKeySHA256 string `json:"recoverySigningKeySha256"`
}

type Expected struct {
	Stack, Database, ControllerImage string
}

func ReadRegularFile(path string, maximum int64) ([]byte, error) {
	if maximum <= 0 {
		return nil, errors.New("positive file size limit is required")
	}
	before, err := os.Lstat(path)
	if err != nil || !before.Mode().IsRegular() {
		return nil, fmt.Errorf("%s must be a regular file, not a symbolic link", path)
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	opened, err := file.Stat()
	if err != nil || !opened.Mode().IsRegular() || !os.SameFile(before, opened) {
		return nil, fmt.Errorf("%s changed while it was opened", path)
	}
	data, err := io.ReadAll(io.LimitReader(file, maximum+1))
	if err != nil {
		return nil, err
	}
	after, err := file.Stat()
	if err != nil || !os.SameFile(opened, after) || after.Size() != int64(len(data)) {
		return nil, fmt.Errorf("%s changed while it was read", path)
	}
	if len(data) == 0 || int64(len(data)) > maximum {
		return nil, fmt.Errorf("%s has an invalid size", path)
	}
	return data, nil
}

func Verify(manifestData, signature, publicKeyData, masterKey, agentCACertificate, agentCAKey []byte, expected Expected, now time.Time) (Manifest, error) {
	var manifest Manifest
	if len(manifestData) == 0 || len(manifestData) > MaxManifestBytes || len(signature) != ed25519.SignatureSize {
		return manifest, errors.New("recovery bundle metadata has an invalid size")
	}
	if len(masterKey) != MasterKeyBytes {
		return manifest, errors.New("master key must contain exactly 32 bytes")
	}
	publicKey, err := parsePublicKey(publicKeyData)
	if err != nil {
		return manifest, err
	}
	if !ed25519.Verify(publicKey, manifestData, signature) {
		return manifest, errors.New("recovery bundle manifest signature is invalid")
	}
	decoder := json.NewDecoder(bytes.NewReader(manifestData))
	decoder.DisallowUnknownFields()
	if err = decoder.Decode(&manifest); err != nil {
		return Manifest{}, fmt.Errorf("decode recovery bundle manifest: %w", err)
	}
	var trailing any
	if err = decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return Manifest{}, errors.New("recovery bundle manifest must contain exactly one JSON object")
	}
	if manifest.FormatVersion != 2 {
		return Manifest{}, errors.New("unsupported recovery bundle format")
	}
	createdAt, err := time.Parse(time.RFC3339, manifest.CreatedAt)
	if err != nil || createdAt.Format(time.RFC3339) != manifest.CreatedAt || createdAt.After(now.UTC().Add(5*time.Minute)) {
		return Manifest{}, errors.New("recovery bundle createdAt is invalid")
	}
	if !stackPattern.MatchString(manifest.Stack) || !databasePattern.MatchString(manifest.Database) || !schemaPattern.MatchString(manifest.SchemaVersion) {
		return Manifest{}, errors.New("recovery bundle stack, database, or schema identity is invalid")
	}
	if !ociref.IsDigestPinned(manifest.ControllerImage) {
		return Manifest{}, errors.New("recovery bundle controller image is not digest-pinned")
	}
	for _, value := range []string{manifest.DatabaseSHA256, manifest.MasterKeySHA256, manifest.RecoverySigningKeySHA256} {
		if !hashPattern.MatchString(value) {
			return Manifest{}, errors.New("recovery bundle contains an invalid SHA-256 value")
		}
	}
	if manifest.AgentCASHA256 != "" && !hashPattern.MatchString(manifest.AgentCASHA256) {
		return Manifest{}, errors.New("recovery bundle contains an invalid agent CA SHA-256 value")
	}
	if manifest.DatabaseBytes <= 0 {
		return Manifest{}, errors.New("recovery bundle database size must be positive")
	}
	if manifest.Stack != expected.Stack || manifest.Database != expected.Database || manifest.ControllerImage != expected.ControllerImage {
		return Manifest{}, errors.New("recovery bundle does not match the requested deployment")
	}
	masterKeyHash := sha256.Sum256(masterKey)
	if hex.EncodeToString(masterKeyHash[:]) != manifest.MasterKeySHA256 {
		return Manifest{}, errors.New("master key does not match the recovery bundle")
	}
	encodedPublicKey, err := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil {
		return Manifest{}, err
	}
	publicKeyHash := sha256.Sum256(encodedPublicKey)
	if hex.EncodeToString(publicKeyHash[:]) != manifest.RecoverySigningKeySHA256 {
		return Manifest{}, errors.New("recovery verification key does not match the signed bundle")
	}
	if manifest.AgentCASHA256 == "" {
		if len(agentCACertificate) != 0 || len(agentCAKey) != 0 {
			return Manifest{}, errors.New("recovery bundle does not declare an agent CA")
		}
	} else {
		if len(agentCACertificate) == 0 || len(agentCAKey) == 0 {
			return Manifest{}, errors.New("recovery bundle requires the matching agent CA certificate and private key")
		}
		authority, validationErr := agentpki.ValidateAuthority(agentCACertificate, agentCAKey, now)
		if validationErr != nil {
			return Manifest{}, fmt.Errorf("validate recovery agent CA keypair: %w", validationErr)
		}
		authorityHash := sha256.Sum256(authority.Raw)
		if hex.EncodeToString(authorityHash[:]) != manifest.AgentCASHA256 {
			return Manifest{}, errors.New("agent CA certificate does not match the recovery bundle")
		}
	}
	return manifest, nil
}

func parsePublicKey(data []byte) (ed25519.PublicKey, error) {
	block, rest := pem.Decode(data)
	if block == nil || len(bytes.TrimSpace(rest)) != 0 {
		return nil, errors.New("recovery verification key must contain one PEM public key")
	}
	parsed, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, errors.New("recovery verification key is invalid")
	}
	key, ok := parsed.(ed25519.PublicKey)
	if !ok {
		return nil, errors.New("recovery verification key is not Ed25519")
	}
	return key, nil
}
