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
	"io"
	"os"
	"path/filepath"
	"sort"
)

const manifestName = "catalog.manifest.json"
const signatureName = "catalog.manifest.sig"
const maxCatalogKeyBytes int64 = 64 << 10
const maxCatalogSignatureBytes int64 = 1024

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
			contents, readErr := readRegularCatalogFile(path, maxCatalogFileBytes)
			if readErr != nil {
				return nil, fmt.Errorf("catalog file %s: %w", relative, readErr)
			}
			digest := sha256.Sum256(contents)
			manifest.Files = append(manifest.Files, ManifestEntry{Path: relative, SHA256: hex.EncodeToString(digest[:])})
		}
	}
	sort.Slice(manifest.Files, func(i, j int) bool { return manifest.Files[i].Path < manifest.Files[j].Path })
	return json.Marshal(manifest)
}

func SignCatalog(root string, privateKey ed25519.PrivateKey) error {
	if len(privateKey) != ed25519.PrivateKeySize || !privateKey.Equal(ed25519.NewKeyFromSeed(privateKey.Seed())) {
		return errors.New("catalog private key is invalid")
	}
	manifest, err := BuildCatalogManifest(root)
	if err != nil {
		return err
	}
	signature := ed25519.Sign(privateKey, manifest)
	manifestStaged, err := stageCatalogArtifact(root, manifestName, append(manifest, '\n'))
	if err != nil {
		return err
	}
	defer os.Remove(manifestStaged)
	signatureStaged, err := stageCatalogArtifact(root, signatureName, []byte(base64.StdEncoding.EncodeToString(signature)+"\n"))
	if err != nil {
		return err
	}
	defer os.Remove(signatureStaged)
	if err = os.Rename(signatureStaged, filepath.Join(root, signatureName)); err != nil {
		return fmt.Errorf("publish catalog signature: %w", err)
	}
	if err = os.Rename(manifestStaged, filepath.Join(root, manifestName)); err != nil {
		return fmt.Errorf("publish catalog manifest: %w", err)
	}
	directory, err := os.Open(root)
	if err != nil {
		return err
	}
	syncErr := directory.Sync()
	closeErr := directory.Close()
	return errors.Join(syncErr, closeErr)
}

func stageCatalogArtifact(root, name string, contents []byte) (path string, err error) {
	file, err := os.CreateTemp(root, "."+name+".")
	if err != nil {
		return "", err
	}
	path = file.Name()
	defer func() {
		if err != nil {
			_ = file.Close()
			_ = os.Remove(path)
		}
	}()
	if err = file.Chmod(0644); err == nil {
		_, err = file.Write(contents)
	}
	if err == nil {
		err = file.Sync()
	}
	if closeErr := file.Close(); err == nil {
		err = closeErr
	}
	return path, err
}

func VerifyCatalog(root string, publicKey ed25519.PublicKey) error {
	recorded, err := readRegularCatalogFile(filepath.Join(root, manifestName), maxCatalogFileBytes)
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
	encoded, err := readRegularCatalogFile(filepath.Join(root, signatureName), maxCatalogSignatureBytes)
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
	data, err := readCatalogKeyFile(path, false)
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
	data, err := readCatalogKeyFile(path, true)
	if err != nil {
		return nil, err
	}
	data = bytesTrimSpace(data)
	if block, rest := pem.Decode(data); block != nil {
		if block.Type != "PRIVATE KEY" || len(bytesTrimSpace(rest)) != 0 {
			return nil, errors.New("catalog private key PEM contains an invalid type or trailing data")
		}
		key, parseErr := x509.ParsePKCS8PrivateKey(block.Bytes)
		if parseErr != nil {
			return nil, parseErr
		}
		privateKey, ok := key.(ed25519.PrivateKey)
		if !ok {
			return nil, errors.New("catalog private key is not Ed25519")
		}
		if !privateKey.Equal(ed25519.NewKeyFromSeed(privateKey.Seed())) {
			return nil, errors.New("catalog private key is inconsistent")
		}
		return privateKey, nil
	}
	decoded, err := base64.StdEncoding.DecodeString(string(data))
	if err != nil || len(decoded) != ed25519.PrivateKeySize {
		return nil, errors.New("catalog private key must be Ed25519 PKCS#8 PEM or base64 raw key")
	}
	privateKey := ed25519.PrivateKey(decoded)
	if !privateKey.Equal(ed25519.NewKeyFromSeed(privateKey.Seed())) {
		return nil, errors.New("catalog private key is inconsistent")
	}
	return privateKey, nil
}

func readCatalogKeyFile(path string, private bool) ([]byte, error) {
	before, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if !before.Mode().IsRegular() {
		return nil, errors.New("catalog key must be a regular file, not a symbolic link")
	}
	if private && before.Mode().Perm()&0077 != 0 {
		return nil, errors.New("catalog private key must not be accessible by group or other users")
	}
	if before.Size() < 1 || before.Size() > maxCatalogKeyBytes {
		return nil, errors.New("catalog key size is outside the allowed range")
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	after, err := file.Stat()
	if err != nil || !after.Mode().IsRegular() || !os.SameFile(before, after) {
		return nil, errors.New("catalog key changed while it was opened")
	}
	data, err := io.ReadAll(io.LimitReader(file, maxCatalogKeyBytes+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > maxCatalogKeyBytes {
		return nil, errors.New("catalog key size is outside the allowed range")
	}
	return data, nil
}

func readRegularCatalogFile(path string, maximum int64) ([]byte, error) {
	before, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if !before.Mode().IsRegular() {
		return nil, errors.New("must be a regular file, not a symbolic link")
	}
	if before.Size() < 0 || before.Size() > maximum {
		return nil, fmt.Errorf("size exceeds %d bytes", maximum)
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	after, err := file.Stat()
	if err != nil || !after.Mode().IsRegular() || !os.SameFile(before, after) {
		return nil, errors.New("file changed while it was opened")
	}
	data, err := io.ReadAll(io.LimitReader(file, maximum+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > maximum {
		return nil, fmt.Errorf("size exceeds %d bytes", maximum)
	}
	return data, nil
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
