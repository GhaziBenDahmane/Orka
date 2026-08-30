package backup

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"path"
	"strings"
	"time"

	"github.com/minio/minio-go/v7"
	"github.com/minio/minio-go/v7/pkg/credentials"
)

type S3Config struct {
	Endpoint, Region, Bucket, Prefix   string
	AccessKey, SecretKey, SessionToken string
	UseTLS                             bool
	Transport                          http.RoundTripper
}

type S3 struct {
	client *minio.Client
	bucket string
	prefix string
}

func NewS3(config S3Config) (*S3, error) {
	parsed, err := url.Parse(config.Endpoint)
	if err != nil || parsed.Host == "" || parsed.Hostname() == "" || (parsed.Scheme != "http" && parsed.Scheme != "https") || parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" || parsed.Opaque != "" || parsed.Path != "" && parsed.Path != "/" {
		return nil, errors.New("S3 endpoint must be an HTTP(S) origin without a path")
	}
	if config.UseTLS && parsed.Scheme != "https" || !config.UseTLS && parsed.Scheme != "http" {
		return nil, errors.New("S3 endpoint scheme does not match useTls")
	}
	if strings.TrimSpace(config.Bucket) == "" || strings.Contains(config.Prefix, "..") || config.AccessKey == "" || config.SecretKey == "" {
		return nil, errors.New("invalid S3 bucket or prefix")
	}
	client, err := minio.New(parsed.Host, &minio.Options{Creds: credentials.NewStaticV4(config.AccessKey, config.SecretKey, config.SessionToken), Secure: config.UseTLS, Region: config.Region, Transport: config.Transport})
	if err != nil {
		return nil, err
	}
	return &S3{client: client, bucket: config.Bucket, prefix: strings.Trim(strings.TrimSpace(config.Prefix), "/")}, nil
}

func (s *S3) Check(ctx context.Context) error {
	exists, err := s.client.BucketExists(ctx, s.bucket)
	if err != nil {
		return err
	}
	if !exists {
		return errors.New("S3 bucket does not exist or is inaccessible")
	}
	return nil
}

func (s *S3) CheckObjectLock(ctx context.Context) error {
	enabled, _, _, _, err := s.client.GetObjectLockConfig(ctx, s.bucket)
	if err != nil {
		return err
	}
	if enabled != "Enabled" {
		return errors.New("S3 bucket object lock is not enabled")
	}
	return nil
}

func (s *S3) ObjectKey(name string) string {
	if s.prefix == "" {
		return name
	}
	return path.Join(s.prefix, name)
}

func (s *S3) Put(ctx context.Context, key, filename string) error {
	_, err := s.client.FPutObject(ctx, s.bucket, key, filename, minio.PutObjectOptions{ContentType: "application/octet-stream"})
	return err
}

func (s *S3) PutImmutable(ctx context.Context, key string, contents []byte, digest string, retainUntil time.Time) error {
	options := minio.PutObjectOptions{ContentType: "application/x-ndjson", Mode: minio.Compliance, RetainUntilDate: retainUntil.UTC(), UserMetadata: map[string]string{"dockyard-sha256": digest}}
	options.SetMatchETagExcept("*")
	_, err := s.client.PutObject(ctx, s.bucket, s.ObjectKey(key), bytes.NewReader(contents), int64(len(contents)), options)
	if err == nil {
		return nil
	}
	response := minio.ToErrorResponse(err)
	if response.Code != "PreconditionFailed" && response.Code != "ConditionalRequestConflict" {
		return err
	}
	object, statErr := s.client.GetObject(ctx, s.bucket, s.ObjectKey(key), minio.GetObjectOptions{})
	if statErr != nil {
		return err
	}
	defer object.Close()
	hash := sha256sumReader(object)
	if hash != digest {
		return fmt.Errorf("immutable audit object already exists with a different digest")
	}
	return nil
}

func sha256sumReader(reader io.Reader) string {
	hash := sha256.New()
	if _, err := io.Copy(hash, reader); err != nil {
		return ""
	}
	return hex.EncodeToString(hash.Sum(nil))
}

func (s *S3) Get(ctx context.Context, key, filename string) error {
	return s.client.FGetObject(ctx, s.bucket, key, filename, minio.GetObjectOptions{})
}

func (s *S3) Delete(ctx context.Context, key string) error {
	return s.client.RemoveObject(ctx, s.bucket, key, minio.RemoveObjectOptions{})
}

func (s *S3) PresignedPut(ctx context.Context, key string, expiry time.Duration) (string, error) {
	u, err := s.client.PresignedPutObject(ctx, s.bucket, key, expiry)
	if err != nil {
		return "", err
	}
	return u.String(), nil
}

func (s *S3) PresignedGet(ctx context.Context, key string, expiry time.Duration) (string, error) {
	u, err := s.client.PresignedGetObject(ctx, s.bucket, key, expiry, nil)
	if err != nil {
		return "", err
	}
	return u.String(), nil
}
