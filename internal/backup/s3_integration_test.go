package backup

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/minio/minio-go/v7"
)

func TestS3RoundTrip(t *testing.T) {
	endpoint := os.Getenv("DOCKYARD_TEST_S3_ENDPOINT")
	if endpoint == "" {
		t.Skip("DOCKYARD_TEST_S3_ENDPOINT is not set")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	client, err := NewS3(S3Config{Endpoint: endpoint, Bucket: "dockyard-test", Prefix: "integration", AccessKey: os.Getenv("DOCKYARD_TEST_S3_ACCESS_KEY"), SecretKey: os.Getenv("DOCKYARD_TEST_S3_SECRET_KEY")})
	if err != nil {
		t.Fatal(err)
	}
	exists, err := client.client.BucketExists(ctx, client.bucket)
	if err != nil {
		t.Fatal(err)
	}
	if !exists {
		if err = client.client.MakeBucket(ctx, client.bucket, minio.MakeBucketOptions{}); err != nil {
			t.Fatal(err)
		}
	}
	key, err := client.ObjectKey("round-trip.txt")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = client.Delete(context.Background(), key) })
	source := filepath.Join(t.TempDir(), "source")
	if err = os.WriteFile(source, []byte("verified backup"), 0600); err != nil {
		t.Fatal(err)
	}
	if err = client.Put(ctx, key, source); err != nil {
		t.Fatal(err)
	}
	destination := filepath.Join(t.TempDir(), "destination")
	if err = client.Get(ctx, key, destination, int64(len("verified backup"))); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(destination)
	if err != nil || string(data) != "verified backup" {
		t.Fatalf("download = %q, err = %v", data, err)
	}
}
