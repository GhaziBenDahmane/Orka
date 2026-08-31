package backup

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path"
	"regexp"
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/minio/minio-go/v7"
	"github.com/minio/minio-go/v7/pkg/credentials"
	"github.com/minio/minio-go/v7/pkg/s3utils"
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

var s3HostnameLabelPattern = regexp.MustCompile(`^[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?$`)
var s3RegionPattern = regexp.MustCompile(`^[A-Za-z0-9._-]*$`)

const (
	maxS3EndpointBytes     = 2048
	maxS3RegionBytes       = 128
	maxS3BucketBytes       = 63
	maxS3PrefixBytes       = 1024
	maxS3AccessKeyBytes    = 1024
	maxS3SecretKeyBytes    = 16 << 10
	maxS3SessionTokenBytes = 16 << 10
	maxS3ObjectKeyBytes    = 1024
)

func NewS3(config S3Config) (*S3, error) {
	if len(config.Endpoint) == 0 || len(config.Endpoint) > maxS3EndpointBytes || config.Endpoint != strings.TrimSpace(config.Endpoint) {
		return nil, errors.New("S3 endpoint is empty or exceeds its supported limit")
	}
	parsed, err := url.Parse(config.Endpoint)
	if err != nil || (parsed.Scheme != "http" && parsed.Scheme != "https") || !validS3EndpointHost(parsed) || parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" || parsed.Opaque != "" || parsed.Path != "" && parsed.Path != "/" {
		return nil, errors.New("S3 endpoint must be an HTTP(S) origin without a path")
	}
	if config.UseTLS && parsed.Scheme != "https" || !config.UseTLS && parsed.Scheme != "http" {
		return nil, errors.New("S3 endpoint scheme does not match useTls")
	}
	if len(config.Region) > maxS3RegionBytes || !s3RegionPattern.MatchString(config.Region) || s3utils.CheckValidBucketName(config.Bucket) != nil || len(config.Bucket) > maxS3BucketBytes || config.Bucket != strings.TrimSpace(config.Bucket) || len(config.Prefix) > maxS3PrefixBytes || unsafeS3Text(config.Prefix) || strings.Contains(config.Prefix, "..") || strings.Contains(config.Prefix, "\\") || len(config.AccessKey) == 0 || len(config.AccessKey) > maxS3AccessKeyBytes || len(config.SecretKey) == 0 || len(config.SecretKey) > maxS3SecretKeyBytes || len(config.SessionToken) > maxS3SessionTokenBytes || strings.ContainsAny(config.AccessKey+config.SecretKey+config.SessionToken, "\x00\r\n") {
		return nil, errors.New("invalid or oversized S3 destination configuration")
	}
	prefix := strings.Trim(strings.TrimSpace(config.Prefix), "/")
	if prefix != "" {
		if err = validateS3Key(prefix); err != nil {
			return nil, errors.New("invalid or oversized S3 destination configuration")
		}
	}
	client, err := minio.New(parsed.Host, &minio.Options{Creds: credentials.NewStaticV4(config.AccessKey, config.SecretKey, config.SessionToken), Secure: config.UseTLS, Region: config.Region, Transport: config.Transport})
	if err != nil {
		return nil, err
	}
	return &S3{client: client, bucket: config.Bucket, prefix: prefix}, nil
}

func validS3EndpointHost(endpoint *url.URL) bool {
	host := endpoint.Hostname()
	if strings.HasPrefix(endpoint.Host, "[") && net.ParseIP(host) == nil {
		return false
	}
	if net.ParseIP(host) == nil {
		if len(host) == 0 || len(host) > 253 {
			return false
		}
		for _, label := range strings.Split(host, ".") {
			if len(label) == 0 || len(label) > 63 || !s3HostnameLabelPattern.MatchString(label) {
				return false
			}
		}
	}
	if strings.HasSuffix(endpoint.Host, ":") {
		return false
	}
	if port := endpoint.Port(); port != "" {
		value, err := strconv.Atoi(port)
		if err != nil || value < 1 || value > 65535 {
			return false
		}
	}
	return true
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

func (s *S3) ObjectKey(name string) (string, error) {
	if err := validateS3Key(name); err != nil {
		return "", err
	}
	key := name
	if s.prefix != "" {
		key = path.Join(s.prefix, name)
	}
	if err := s.validateObjectKey(key); err != nil {
		return "", err
	}
	return key, nil
}

func (s *S3) Put(ctx context.Context, key, filename string) error {
	if err := s.validateObjectKey(key); err != nil {
		return err
	}
	_, err := s.client.FPutObject(ctx, s.bucket, key, filename, minio.PutObjectOptions{ContentType: "application/octet-stream"})
	return err
}

func (s *S3) PutImmutable(ctx context.Context, key string, contents []byte, digest string, retainUntil time.Time) error {
	objectKey, err := s.ObjectKey(key)
	if err != nil {
		return err
	}
	options := minio.PutObjectOptions{ContentType: "application/x-ndjson", Mode: minio.Compliance, RetainUntilDate: retainUntil.UTC(), UserMetadata: map[string]string{"dockyard-sha256": digest}}
	options.SetMatchETagExcept("*")
	_, err = s.client.PutObject(ctx, s.bucket, objectKey, bytes.NewReader(contents), int64(len(contents)), options)
	if err == nil {
		return nil
	}
	response := minio.ToErrorResponse(err)
	if response.Code != "PreconditionFailed" && response.Code != "ConditionalRequestConflict" {
		return err
	}
	object, statErr := s.client.GetObject(ctx, s.bucket, objectKey, minio.GetObjectOptions{})
	if statErr != nil {
		return statErr
	}
	defer object.Close()
	info, statErr := object.Stat()
	if statErr != nil {
		return statErr
	}
	if info.Size != int64(len(contents)) {
		return errors.New("immutable audit object already exists with a different size")
	}
	hash, size, hashErr := sha256sumReader(object, int64(len(contents)))
	if hashErr != nil {
		return hashErr
	}
	if size != int64(len(contents)) || hash != digest {
		return fmt.Errorf("immutable audit object already exists with a different digest")
	}
	return nil
}

func sha256sumReader(reader io.Reader, expectedSize int64) (string, int64, error) {
	if expectedSize < 0 {
		return "", 0, errors.New("invalid expected object size")
	}
	hash := sha256.New()
	size, err := io.Copy(hash, io.LimitReader(reader, expectedSize+1))
	if err != nil {
		return "", size, err
	}
	if size != expectedSize {
		return "", size, errors.New("object body size does not match metadata")
	}
	return hex.EncodeToString(hash.Sum(nil)), size, nil
}

func (s *S3) Get(ctx context.Context, key, filename string, expectedSize int64) error {
	if err := s.validateObjectKey(key); err != nil {
		return err
	}
	if expectedSize <= 0 {
		return errors.New("S3 download requires a positive expected size")
	}
	object, err := s.client.GetObject(ctx, s.bucket, key, minio.GetObjectOptions{})
	if err != nil {
		return err
	}
	defer object.Close()
	info, err := object.Stat()
	if err != nil {
		return err
	}
	if info.Size != expectedSize {
		return errors.New("S3 object size does not match backup metadata")
	}
	return copyExactFile(filename, object, expectedSize)
}

func copyExactFile(filename string, source io.Reader, expectedSize int64) error {
	if expectedSize <= 0 {
		return errors.New("download requires a positive expected size")
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
	written, copyErr := io.Copy(file, io.LimitReader(source, expectedSize+1))
	closeErr := file.Close()
	if copyErr != nil {
		return copyErr
	}
	if closeErr != nil {
		return closeErr
	}
	if written != expectedSize {
		return errors.New("download size mismatch")
	}
	keep = true
	return nil
}

func (s *S3) Delete(ctx context.Context, key string) error {
	if err := s.validateObjectKey(key); err != nil {
		return err
	}
	return s.client.RemoveObject(ctx, s.bucket, key, minio.RemoveObjectOptions{})
}

func (s *S3) PresignedPut(ctx context.Context, key string, expiry time.Duration) (string, error) {
	if err := s.validateObjectKey(key); err != nil {
		return "", err
	}
	u, err := s.client.PresignedPutObject(ctx, s.bucket, key, expiry)
	if err != nil {
		return "", err
	}
	return u.String(), nil
}

func (s *S3) PresignedGet(ctx context.Context, key string, expiry time.Duration) (string, error) {
	if err := s.validateObjectKey(key); err != nil {
		return "", err
	}
	u, err := s.client.PresignedGetObject(ctx, s.bucket, key, expiry, nil)
	if err != nil {
		return "", err
	}
	return u.String(), nil
}

func (s *S3) validateObjectKey(key string) error {
	if err := validateS3Key(key); err != nil {
		return err
	}
	if s.prefix != "" && key != s.prefix && !strings.HasPrefix(key, s.prefix+"/") {
		return errors.New("S3 object key is outside the configured prefix")
	}
	return nil
}

func validateS3Key(key string) error {
	if key == "" || len(key) > maxS3ObjectKeyBytes || key != strings.TrimSpace(key) || unsafeS3Text(key) || strings.Contains(key, "\\") || strings.HasPrefix(key, "/") {
		return errors.New("invalid or oversized S3 object key")
	}
	for _, segment := range strings.Split(key, "/") {
		if segment == "" || segment == "." || segment == ".." {
			return errors.New("invalid or oversized S3 object key")
		}
	}
	return nil
}

func unsafeS3Text(value string) bool {
	return !utf8.ValidString(value) || strings.IndexFunc(value, func(character rune) bool {
		return unicode.IsControl(character) || unicode.Is(unicode.Cf, character) || unicode.In(character, unicode.Zl, unicode.Zp)
	}) >= 0
}
