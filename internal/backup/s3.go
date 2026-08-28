package backup

import (
	"context"
	"errors"
	"net/url"
	"path"
	"strings"

	"github.com/minio/minio-go/v7"
	"github.com/minio/minio-go/v7/pkg/credentials"
)

type S3Config struct {
	Endpoint, Region, Bucket, Prefix   string
	AccessKey, SecretKey, SessionToken string
	UseTLS                             bool
}

type S3 struct {
	client *minio.Client
	bucket string
	prefix string
}

func NewS3(config S3Config) (*S3, error) {
	parsed, err := url.Parse(config.Endpoint)
	if err != nil || parsed.Host == "" || (parsed.Scheme != "http" && parsed.Scheme != "https") || parsed.Path != "" && parsed.Path != "/" {
		return nil, errors.New("S3 endpoint must be an HTTP(S) origin without a path")
	}
	if config.UseTLS && parsed.Scheme != "https" || !config.UseTLS && parsed.Scheme != "http" {
		return nil, errors.New("S3 endpoint scheme does not match useTls")
	}
	if strings.TrimSpace(config.Bucket) == "" || strings.Contains(config.Prefix, "..") || config.AccessKey == "" || config.SecretKey == "" {
		return nil, errors.New("invalid S3 bucket or prefix")
	}
	client, err := minio.New(parsed.Host, &minio.Options{Creds: credentials.NewStaticV4(config.AccessKey, config.SecretKey, config.SessionToken), Secure: config.UseTLS, Region: config.Region})
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

func (s *S3) Get(ctx context.Context, key, filename string) error {
	return s.client.FGetObject(ctx, s.bucket, key, filename, minio.GetObjectOptions{})
}

func (s *S3) Delete(ctx context.Context, key string) error {
	return s.client.RemoveObject(ctx, s.bucket, key, minio.RemoveObjectOptions{})
}
