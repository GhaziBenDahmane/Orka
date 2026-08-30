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
	"net/url"
	"os"
	"path/filepath"

	"github.com/bendahma/dokploy-go/internal/cryptox"
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
	if job.Mode != "backup" && job.Mode != "restore" {
		return result, errors.New("volume artifact mode must be backup or restore")
	}
	parsed, err := url.Parse(job.TransferURL)
	if err != nil || parsed.Host == "" || (parsed.Scheme != "http" && parsed.Scheme != "https") || parsed.User != nil {
		return result, errors.New("volume artifact transfer URL must be HTTP(S) without credentials")
	}
	key, err := base64.RawStdEncoding.DecodeString(job.EncryptionKey)
	if err != nil || len(key) != 32 || job.EncryptionAAD == "" {
		return result, errors.New("invalid volume artifact encryption parameters")
	}
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
	plainPath, encryptedPath := filepath.Join(work, "volume.tar.gz"), filepath.Join(work, "volume.tar.gz.enc")
	if job.Mode == "backup" {
		plain, createErr := os.OpenFile(plainPath, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
		if createErr != nil {
			return result, createErr
		}
		err = WriteArchive(plain, volumeRoot)
		if closeErr := plain.Close(); err == nil {
			err = closeErr
		}
		if err != nil {
			return result, err
		}
		result.PlaintextSHA256, _, err = hashFile(plainPath)
		if err == nil {
			err = transform(box, plainPath, encryptedPath, job.EncryptionAAD, true)
		}
		if err == nil {
			result.SHA256, result.SizeBytes, err = hashFile(encryptedPath)
		}
		if err == nil {
			err = transfer(ctx, http.MethodPut, job.TransferURL, encryptedPath, result.SizeBytes)
		}
		return result, err
	}
	if len(job.SHA256) != 64 || len(job.PlaintextSHA256) != 64 || job.SizeBytes <= 0 {
		return result, errors.New("restore requires artifact checksums and size")
	}
	if err = transfer(ctx, http.MethodGet, job.TransferURL, encryptedPath, job.SizeBytes); err != nil {
		return result, err
	}
	result.SHA256, result.SizeBytes, err = hashFile(encryptedPath)
	if err != nil || result.SHA256 != job.SHA256 || result.SizeBytes != job.SizeBytes {
		return result, errors.New("encrypted volume artifact checksum or size mismatch")
	}
	if err = transform(box, encryptedPath, plainPath, job.EncryptionAAD, false); err != nil {
		return result, err
	}
	result.PlaintextSHA256, _, err = hashFile(plainPath)
	if err != nil || result.PlaintextSHA256 != job.PlaintextSHA256 {
		return result, errors.New("plaintext volume artifact checksum mismatch")
	}
	archive, err := os.Open(plainPath)
	if err != nil {
		return result, err
	}
	err = RestoreArchive(archive, volumeRoot)
	closeErr := archive.Close()
	if err == nil {
		err = closeErr
	}
	return result, err
}

func transform(box *cryptox.Box, source, destination, aad string, encrypt bool) (err error) {
	input, err := os.Open(source)
	if err != nil {
		return err
	}
	defer input.Close()
	output, err := os.OpenFile(destination, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	defer func() {
		if err != nil {
			_ = os.Remove(destination)
		}
		_ = output.Close()
	}()
	if encrypt {
		err = box.EncryptStream(output, input, aad)
	} else {
		err = box.DecryptStream(output, input, aad)
	}
	if err == nil {
		err = output.Sync()
	}
	return err
}

func transfer(ctx context.Context, method, rawURL, filename string, expectedSize int64) error {
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
		request.ContentLength = expectedSize
		defer body.Close()
	}
	client := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error {
		return errors.New("volume artifact redirects are disabled")
	}}
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
	file, err := os.OpenFile(filename, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
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
	return nil
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
