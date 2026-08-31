package volumeartifact

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/bendahma/dokploy-go/internal/cryptox"
	"github.com/bendahma/dokploy-go/internal/netpolicy"
)

const (
	maxTransferURLBytes   = 32 << 10
	maxEncryptionAADBytes = 1024
	transferHeaderTimeout = 30 * time.Second
)

type Job struct {
	Mode            string `json:"mode"`
	TransferURL     string `json:"transferUrl"`
	EncryptionKey   string `json:"encryptionKey"`
	EncryptionAAD   string `json:"encryptionAad"`
	SHA256          string `json:"sha256,omitempty"`
	PlaintextSHA256 string `json:"plaintextSha256,omitempty"`
	SizeBytes       int64  `json:"sizeBytes,omitempty"`
}

type Result struct {
	SHA256          string `json:"sha256"`
	PlaintextSHA256 string `json:"plaintextSha256"`
	SizeBytes       int64  `json:"sizeBytes"`
}

func ReadJob(filename string) (Job, error) {
	file, err := os.Open(filename)
	if err != nil {
		return Job{}, err
	}
	defer file.Close()
	var job Job
	decoder := json.NewDecoder(io.LimitReader(file, 64*1024))
	decoder.DisallowUnknownFields()
	if err = decoder.Decode(&job); err != nil {
		return Job{}, err
	}
	var trailing any
	if err = decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		if err == nil {
			err = errors.New("job file contains multiple JSON values")
		}
		return Job{}, err
	}
	return job, nil
}

func Run(ctx context.Context, job Job, volumeRoot, workRoot string) (Result, error) {
	var result Result
	if err := ValidateJob(job); err != nil {
		return result, err
	}
	key, _ := base64.RawStdEncoding.DecodeString(job.EncryptionKey)
	defer clear(key)
	box, err := cryptox.New(key)
	if err != nil {
		return result, err
	}
	work, err := os.MkdirTemp(workRoot, "volume-artifact-")
	if err != nil {
		return result, err
	}
	defer os.RemoveAll(work)
	encryptedPath := filepath.Join(work, "volume.tar.gz.enc")
	if job.Mode == "backup" {
		result, err = backupToFile(box, volumeRoot, encryptedPath, job.EncryptionAAD)
		if err == nil {
			err = transfer(ctx, http.MethodPut, job.TransferURL, encryptedPath, result.SizeBytes)
		}
		return result, err
	}
	if err = transfer(ctx, http.MethodGet, job.TransferURL, encryptedPath, job.SizeBytes); err != nil {
		return result, err
	}
	return restoreFromFile(box, volumeRoot, encryptedPath, job)
}

// RunLocal reads or writes an authenticated encrypted artifact on a mounted
// local path. It shares the archive and verification path used by remote
// volume jobs so operator recovery tooling cannot drift to a weaker format.
func RunLocal(job Job, volumeRoot, artifactPath string) (Result, error) {
	if err := validateCryptographicJob(job); err != nil {
		return Result{}, err
	}
	volumeRoot = filepath.Clean(volumeRoot)
	artifactPath = filepath.Clean(artifactPath)
	if !filepath.IsAbs(volumeRoot) || volumeRoot == string(filepath.Separator) {
		return Result{}, errors.New("volume root must be an absolute non-root directory")
	}
	if !filepath.IsAbs(artifactPath) || artifactPath == string(filepath.Separator) {
		return Result{}, errors.New("artifact path must be an absolute file path")
	}
	if relative, err := filepath.Rel(volumeRoot, artifactPath); err != nil || relative == "." || relative != ".." && !strings.HasPrefix(relative, ".."+string(filepath.Separator)) {
		return Result{}, errors.New("artifact path must be outside the volume root")
	}
	key, _ := base64.RawStdEncoding.DecodeString(job.EncryptionKey)
	defer clear(key)
	box, err := cryptox.New(key)
	if err != nil {
		return Result{}, err
	}
	if job.Mode == "backup" {
		return backupToFile(box, volumeRoot, artifactPath, job.EncryptionAAD)
	}
	info, err := os.Lstat(artifactPath)
	if err != nil || !info.Mode().IsRegular() {
		return Result{}, errors.New("restore artifact must be a regular file, not a symbolic link")
	}
	return restoreFromFile(box, volumeRoot, artifactPath, job)
}

func backupToFile(box *cryptox.Box, volumeRoot, encryptedPath, aad string) (result Result, err error) {
	encrypted, err := os.OpenFile(encryptedPath, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return result, err
	}
	keep := false
	defer func() {
		if !keep {
			_ = os.Remove(encryptedPath)
		}
	}()
	plainHash := sha256.New()
	archiveReader, archiveWriter := io.Pipe()
	archiveDone := make(chan error, 1)
	go func() {
		archiveErr := WriteArchive(io.MultiWriter(archiveWriter, plainHash), volumeRoot)
		_ = archiveWriter.CloseWithError(archiveErr)
		archiveDone <- archiveErr
	}()
	err = box.EncryptStream(encrypted, archiveReader, aad)
	if err != nil {
		_ = archiveReader.CloseWithError(err)
	}
	archiveErr := <-archiveDone
	if err == nil {
		err = archiveErr
	}
	if syncErr := encrypted.Sync(); err == nil {
		err = syncErr
	}
	if closeErr := encrypted.Close(); err == nil {
		err = closeErr
	}
	if err != nil {
		return result, err
	}
	result.PlaintextSHA256 = hex.EncodeToString(plainHash.Sum(nil))
	result.SHA256, result.SizeBytes, err = hashFile(encryptedPath)
	keep = err == nil
	return result, err
}

func restoreFromFile(box *cryptox.Box, volumeRoot, encryptedPath string, job Job) (result Result, err error) {
	result.SHA256, result.SizeBytes, err = hashFile(encryptedPath)
	if err != nil || result.SHA256 != job.SHA256 || result.SizeBytes != job.SizeBytes {
		return result, errors.New("encrypted volume artifact checksum or size mismatch")
	}
	plainHash := sha256.New()
	err = decryptAndConsume(box, encryptedPath, job.EncryptionAAD, func(src io.Reader) error {
		tee := io.TeeReader(src, plainHash)
		if validateErr := validateArchive(tee); validateErr != nil {
			return validateErr
		}
		_, drainErr := io.Copy(io.Discard, tee)
		return drainErr
	})
	if err != nil {
		return result, err
	}
	result.PlaintextSHA256 = hex.EncodeToString(plainHash.Sum(nil))
	if result.PlaintextSHA256 != job.PlaintextSHA256 {
		return result, errors.New("plaintext volume artifact checksum mismatch")
	}
	err = decryptAndConsume(box, encryptedPath, job.EncryptionAAD, func(src io.Reader) error {
		return restoreValidatedArchive(src, filepath.Clean(volumeRoot))
	})
	return result, err
}

func ValidateJob(job Job) error {
	if job.Mode != "backup" && job.Mode != "restore" {
		return errors.New("volume artifact mode must be backup or restore")
	}
	if _, err := netpolicy.ValidateHTTPURL(job.TransferURL, maxTransferURLBytes); err != nil {
		return errors.New("volume artifact transfer URL must be HTTP(S) without credentials")
	}
	return validateCryptographicJob(job)
}

func validateCryptographicJob(job Job) error {
	if job.Mode != "backup" && job.Mode != "restore" {
		return errors.New("volume artifact mode must be backup or restore")
	}
	key, err := base64.RawStdEncoding.DecodeString(job.EncryptionKey)
	if err != nil || len(key) != 32 || job.EncryptionAAD == "" || len(job.EncryptionAAD) > maxEncryptionAADBytes || strings.ContainsAny(job.EncryptionAAD, "\x00\r\n") {
		return errors.New("invalid volume artifact encryption parameters")
	}
	if job.Mode == "restore" {
		sha256Bytes, sha256Err := hex.DecodeString(job.SHA256)
		plaintextBytes, plaintextErr := hex.DecodeString(job.PlaintextSHA256)
		if job.SizeBytes <= 0 || sha256Err != nil || len(sha256Bytes) != 32 || plaintextErr != nil || len(plaintextBytes) != 32 {
			return errors.New("restore requires SHA-256 checksums and size")
		}
	}
	return nil
}

func decryptAndConsume(box *cryptox.Box, source, aad string, consume func(io.Reader) error) error {
	input, err := os.Open(source)
	if err != nil {
		return err
	}
	reader, writer := io.Pipe()
	done := make(chan error, 1)
	go func() {
		decryptErr := box.DecryptStream(writer, input, aad)
		closeErr := input.Close()
		_ = writer.CloseWithError(decryptErr)
		done <- errors.Join(decryptErr, closeErr)
	}()
	consumeErr := consume(reader)
	_ = reader.CloseWithError(consumeErr)
	return errors.Join(consumeErr, <-done)
}

func transfer(ctx context.Context, method, rawURL, filename string, expectedSize int64) error {
	if expectedSize <= 0 {
		return errors.New("volume artifact transfer requires a positive expected size")
	}
	var body io.ReadCloser
	if method == http.MethodPut {
		file, err := os.Open(filename)
		if err != nil {
			return err
		}
		body = file
	}
	request, err := http.NewRequestWithContext(ctx, method, rawURL, body)
	if err != nil {
		if body != nil {
			_ = body.Close()
		}
		return err
	}
	if body != nil {
		info, statErr := os.Stat(filename)
		if statErr != nil {
			_ = body.Close()
			return statErr
		}
		if info.Size() != expectedSize {
			_ = body.Close()
			return errors.New("volume artifact upload size mismatch")
		}
		request.ContentLength = expectedSize
		defer body.Close()
	}
	client := volumeArtifactHTTPClient()
	response, err := client.Do(request)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, 4096))
		return fmt.Errorf("volume artifact transfer returned HTTP %d", response.StatusCode)
	}
	if method != http.MethodGet {
		return nil
	}
	if response.ContentLength >= 0 && response.ContentLength != expectedSize {
		return errors.New("volume artifact download content length mismatch")
	}
	file, err := os.OpenFile(filename, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	keep := false
	defer func() {
		if !keep {
			_ = os.Remove(filename)
		}
	}()
	written, copyErr := io.Copy(file, io.LimitReader(response.Body, expectedSize+1))
	closeErr := file.Close()
	if copyErr != nil {
		return copyErr
	}
	if closeErr != nil {
		return closeErr
	}
	if written != expectedSize {
		return errors.New("volume artifact download size mismatch")
	}
	keep = true
	return nil
}

func volumeArtifactHTTPClient() *http.Client {
	transport := http.DefaultTransport.(*http.Transport).Clone()
	// Recovery URLs are capabilities. Never disclose them to a proxy inherited
	// from the helper image or its runtime environment.
	transport.Proxy = nil
	transport.ResponseHeaderTimeout = transferHeaderTimeout
	return &http.Client{Transport: transport, CheckRedirect: func(*http.Request, []*http.Request) error {
		return errors.New("volume artifact redirects are disabled")
	}}
}

func hashFile(filename string) (string, int64, error) {
	file, err := os.Open(filename)
	if err != nil {
		return "", 0, err
	}
	defer file.Close()
	hash := sha256.New()
	size, err := io.Copy(hash, file)
	return hex.EncodeToString(hash.Sum(nil)), size, err
}
