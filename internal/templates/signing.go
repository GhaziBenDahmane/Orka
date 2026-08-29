package templates

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
)

const manifestName = "catalog.manifest.json"
const signatureName = "catalog.manifest.sig"

type ManifestEntry struct {
	Path   string `json:"path"`
	SHA256 string `json:"sha256"`
}

type CatalogManifest struct {
	Version int             `json:"version"`
	Files   []ManifestEntry `json:"files"`
}

func BuildCatalogManifest(root string) ([]byte, error) {
	entries, err := os.ReadDir(filepath.Join(root, "blueprints"))
	if err != nil {
		return nil, err
	}
	manifest := CatalogManifest{Version: 1, Files: []ManifestEntry{}}
	for _, entry := range entries {
		if !entry.IsDir() || entry.Type()&os.ModeSymlink != 0 {
			continue
		}
		for _, name := range []string{"docker-compose.yml", "meta.json", "template.toml"} {
			relative := filepath.ToSlash(filepath.Join("blueprints", entry.Name(), name))
			path := filepath.Join(root, filepath.FromSlash(relative))
			info, statErr := os.Lstat(path)
			if statErr != nil {
				return nil, fmt.Errorf("catalog file %s: %w", relative, statErr)
			}
			if !info.Mode().IsRegular() {
				return nil, fmt.Errorf("catalog file %s is not a regular file", relative)
			}
			contents, readErr := os.ReadFile(path)
			if readErr != nil {
				return nil, readErr
			}
			digest := sha256.Sum256(contents)
			manifest.Files = append(manifest.Files, ManifestEntry{Path: relative, SHA256: hex.EncodeToString(digest[:])})
		}
	}
	sort.Slice(manifest.Files, func(i, j int) bool { return manifest.Files[i].Path < manifest.Files[j].Path })
	return json.Marshal(manifest)
}

func SignCatalog(root string, privateKey ed25519.PrivateKey) error {
	manifest, err := BuildCatalogManifest(root)
	if err != nil {
		return err
	}
	signature := ed25519.Sign(privateKey, manifest)
	if err := os.WriteFile(filepath.Join(root, manifestName), append(manifest, '\n'), 0644); err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(root, signatureName), []byte(base64.StdEncoding.EncodeToString(signature)+"\n"), 0644)
}

func VerifyCatalog(root string, publicKey ed25519.PublicKey) error {
	recorded, err := os.ReadFile(filepath.Join(root, manifestName))
	if err != nil {
		return fmt.Errorf("read catalog manifest: %w", err)
	}
	canonical, err := BuildCatalogManifest(root)
	if err != nil {
		return err
	}
	var expected, actual CatalogManifest
	if json.Unmarshal(recorded, &expected) != nil || json.Unmarshal(canonical, &actual) != nil || expected.Version != 1 || len(expected.Files) == 0 {
		return errors.New("invalid catalog manifest")
	}
	expectedBytes, _ := json.Marshal(expected)
	if string(expectedBytes) != string(canonical) {
		return errors.New("catalog contents do not match manifest")
	}
	encoded, err := os.ReadFile(filepath.Join(root, signatureName))
	if err != nil {
		return fmt.Errorf("read catalog signature: %w", err)
	}
	signature, err := base64.StdEncoding.DecodeString(string(bytesTrimSpace(encoded)))
	if err != nil || !ed25519.Verify(publicKey, expectedBytes, signature) {
		return errors.New("invalid catalog signature")
	}
	return nil
}

func LoadPublicKey(path string) (ed25519.PublicKey, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return ParsePublicKey(data)
}

// ParsePublicKey accepts the same PEM or base64 representation used by the
// catalog CLI without requiring the key to be written to disk.
func ParsePublicKey(data []byte) (ed25519.PublicKey, error) {
	data = bytesTrimSpace(data)
	if block, rest := pem.Decode(data); block != nil {
		if len(bytesTrimSpace(rest)) != 0 {
			return nil, errors.New("catalog public key PEM contains trailing data")
		}
		key, parseErr := x509.ParsePKIXPublicKey(block.Bytes)
		if parseErr != nil {
			return nil, parseErr
		}
		publicKey, ok := key.(ed25519.PublicKey)
		if !ok {
			return nil, errors.New("catalog public key is not Ed25519")
		}
		return publicKey, nil
	}
	decoded, err := base64.StdEncoding.DecodeString(string(data))
	if err != nil || len(decoded) != ed25519.PublicKeySize {
		return nil, errors.New("catalog public key must be Ed25519 PEM or base64 raw key")
	}
	return ed25519.PublicKey(decoded), nil
}

func PublicKeyFingerprint(key ed25519.PublicKey) string {
	digest := sha256.Sum256(key)
	return "SHA256:" + base64.RawStdEncoding.EncodeToString(digest[:])
}

func LoadPrivateKey(path string) (ed25519.PrivateKey, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	if block, _ := pem.Decode(data); block != nil {
		key, parseErr := x509.ParsePKCS8PrivateKey(block.Bytes)
		if parseErr != nil {
			return nil, parseErr
		}
		privateKey, ok := key.(ed25519.PrivateKey)
		if !ok {
			return nil, errors.New("catalog private key is not Ed25519")
		}
		return privateKey, nil
	}
	decoded, err := base64.StdEncoding.DecodeString(string(bytesTrimSpace(data)))
	if err != nil || len(decoded) != ed25519.PrivateKeySize {
		return nil, errors.New("catalog private key must be Ed25519 PKCS#8 PEM or base64 raw key")
	}
	return ed25519.PrivateKey(decoded), nil
}

func GenerateCatalogKey() (ed25519.PublicKey, ed25519.PrivateKey, error) {
	return ed25519.GenerateKey(rand.Reader)
}

func bytesTrimSpace(value []byte) []byte {
	start, end := 0, len(value)
	for start < end && (value[start] == ' ' || value[start] == '\n' || value[start] == '\r' || value[start] == '\t') {
		start++
	}
	for end > start && (value[end-1] == ' ' || value[end-1] == '\n' || value[end-1] == '\r' || value[end-1] == '\t') {
		end--
	}
	return value[start:end]
}
