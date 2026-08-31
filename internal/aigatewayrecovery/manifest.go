package aigatewayrecovery

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
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/bendahma/dokploy-go/internal/ociref"
)

const (
	MaxManifestBytes  = 64 << 10
	MaxSignatureBytes = ed25519.SignatureSize
	MaxKeyBytes       = 32 << 10
)

var (
	safeNamePattern = regexp.MustCompile(`^[A-Za-z0-9_.-]+$`)
	nodeIDPattern   = regexp.MustCompile(`^[a-z0-9]{1,64}$`)
	hashPattern     = regexp.MustCompile(`^[a-f0-9]{64}$`)
)

type Manifest struct {
	FormatVersion            int    `json:"formatVersion"`
	CreatedAt                string `json:"createdAt"`
	Stack                    string `json:"stack"`
	Service                  string `json:"service"`
	Volume                   string `json:"volume"`
	StorageNodeID            string `json:"storageNodeId"`
	RouterImage              string `json:"routerImage"`
	HelperImage              string `json:"helperImage"`
	ObjectRef                string `json:"objectRef"`
	EncryptionAAD            string `json:"encryptionAad"`
	EncryptionKeySHA256      string `json:"encryptionKeySha256"`
	SHA256                   string `json:"sha256"`
	PlaintextSHA256          string `json:"plaintextSha256"`
	SizeBytes                int64  `json:"sizeBytes"`
	RecoverySigningKeySHA256 string `json:"recoverySigningKeySha256"`
}

type Expected struct {
	Stack, Service, Volume, StorageNodeID, RouterImage, HelperImage, ObjectRef string
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
	after, err := file.Stat()
	if err != nil || !after.Mode().IsRegular() || !os.SameFile(before, after) {
		return nil, fmt.Errorf("%s changed while it was opened", path)
	}
	data, err := io.ReadAll(io.LimitReader(file, maximum+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) == 0 || int64(len(data)) > maximum {
		return nil, fmt.Errorf("%s has an invalid size", path)
	}
	return data, nil
}

func Verify(manifestData, signature, publicKeyData, encryptionKey []byte, expected Expected, now time.Time) (Manifest, error) {
	var manifest Manifest
	if len(manifestData) == 0 || len(manifestData) > MaxManifestBytes || len(signature) != ed25519.SignatureSize {
		return manifest, errors.New("recovery metadata has an invalid size")
	}
	publicKey, err := parsePublicKey(publicKeyData)
	if err != nil {
		return manifest, err
	}
	if !ed25519.Verify(publicKey, manifestData, signature) {
		return manifest, errors.New("recovery metadata signature is invalid")
	}
	decoder := json.NewDecoder(bytes.NewReader(manifestData))
	decoder.DisallowUnknownFields()
	if err = decoder.Decode(&manifest); err != nil {
		return Manifest{}, fmt.Errorf("decode recovery metadata: %w", err)
	}
	var trailing any
	if err = decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return Manifest{}, errors.New("recovery metadata must contain exactly one JSON object")
	}
	if manifest.FormatVersion != 1 {
		return Manifest{}, errors.New("unsupported recovery metadata format")
	}
	createdAt, err := time.Parse(time.RFC3339, manifest.CreatedAt)
	if err != nil || createdAt.Format(time.RFC3339) != manifest.CreatedAt || createdAt.After(now.UTC().Add(5*time.Minute)) {
		return Manifest{}, errors.New("recovery metadata createdAt is invalid")
	}
	for label, value := range map[string]string{"stack": manifest.Stack, "service": manifest.Service, "volume": manifest.Volume} {
		if len(value) > 255 || !safeNamePattern.MatchString(value) {
			return Manifest{}, fmt.Errorf("recovery metadata %s is invalid", label)
		}
	}
	if !nodeIDPattern.MatchString(manifest.StorageNodeID) || !ociref.IsDigestPinned(manifest.RouterImage) || !ociref.IsDigestPinned(manifest.HelperImage) {
		return Manifest{}, errors.New("recovery metadata node or image identity is invalid")
	}
	if invalidText(manifest.ObjectRef, 2048) || manifest.EncryptionAAD != "orka-ai-gateway:"+manifest.Stack+":"+manifest.CreatedAt {
		return Manifest{}, errors.New("recovery metadata object reference or encryption context is invalid")
	}
	for _, value := range []string{manifest.EncryptionKeySHA256, manifest.SHA256, manifest.PlaintextSHA256, manifest.RecoverySigningKeySHA256} {
		if !hashPattern.MatchString(value) {
			return Manifest{}, errors.New("recovery metadata contains an invalid SHA-256 value")
		}
	}
	if manifest.SizeBytes <= 0 {
		return Manifest{}, errors.New("recovery metadata artifact size must be positive")
	}
	if manifest.Stack != expected.Stack || manifest.Service != expected.Service || manifest.Volume != expected.Volume || manifest.StorageNodeID != expected.StorageNodeID || manifest.RouterImage != expected.RouterImage || manifest.HelperImage != expected.HelperImage || manifest.ObjectRef != expected.ObjectRef {
		return Manifest{}, errors.New("recovery metadata does not match the requested deployment")
	}
	keyHash := sha256.Sum256(encryptionKey)
	if hex.EncodeToString(keyHash[:]) != manifest.EncryptionKeySHA256 {
		return Manifest{}, errors.New("backup encryption key does not match the signed metadata")
	}
	encodedPublicKey, err := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil {
		return Manifest{}, err
	}
	publicKeyHash := sha256.Sum256(encodedPublicKey)
	if hex.EncodeToString(publicKeyHash[:]) != manifest.RecoverySigningKeySHA256 {
		return Manifest{}, errors.New("recovery verification key does not match the signed metadata")
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

func invalidText(value string, maximum int) bool {
	return value == "" || value != strings.TrimSpace(value) || len(value) > maximum || !utf8.ValidString(value) || strings.IndexFunc(value, unicode.IsControl) >= 0
}
