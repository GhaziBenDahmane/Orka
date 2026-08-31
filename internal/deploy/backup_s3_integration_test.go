package deploy

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/bendahma/dokploy-go/internal/cryptox"
	"github.com/bendahma/dokploy-go/internal/database"
	"github.com/bendahma/dokploy-go/internal/store"
	"github.com/google/uuid"
	"github.com/minio/minio-go/v7"
	"github.com/minio/minio-go/v7/pkg/credentials"
)

func TestWorkerBacksUpAndRestoresThroughS3(t *testing.T) {
	databaseURL, endpoint := os.Getenv("DOCKYARD_TEST_DATABASE_URL"), os.Getenv("DOCKYARD_TEST_S3_ENDPOINT")
	if databaseURL == "" || endpoint == "" {
		t.Skip("DOCKYARD_TEST_DATABASE_URL and DOCKYARD_TEST_S3_ENDPOINT are required")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	db, err := store.Open(ctx, databaseURL)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(db.Pool.Close)
	box, err := cryptox.New([]byte("0123456789abcdef0123456789abcdef"))
	if err != nil {
		t.Fatal(err)
	}

	parsedEndpoint, err := url.Parse(endpoint)
	if err != nil {
		t.Fatal(err)
	}
	accessKey, secretKey := os.Getenv("DOCKYARD_TEST_S3_ACCESS_KEY"), os.Getenv("DOCKYARD_TEST_S3_SECRET_KEY")
	minioClient, err := minio.New(parsedEndpoint.Host, &minio.Options{Creds: credentials.NewStaticV4(accessKey, secretKey, ""), Secure: parsedEndpoint.Scheme == "https"})
	if err != nil {
		t.Fatal(err)
	}
	bucket := "dockyard-worker-" + strings.ReplaceAll(uuid.NewString(), "-", "")[:12]
	if err = minioClient.MakeBucket(ctx, bucket, minio.MakeBucketOptions{}); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = minioClient.RemoveBucket(context.Background(), bucket) })

	orgID, userID := uuid.New(), uuid.New()
	projectID, environmentID, serviceID, databaseID := uuid.New(), uuid.New(), uuid.New(), uuid.New()
	databaseCredentials, _ := json.Marshal(map[string]string{"username": "dockyard", "password": "secret", "database": "app"})
	encryptedDatabaseCredentials, err := box.Encrypt(databaseCredentials, cryptox.ResourceContext("database-credentials", databaseID.String()))
	if err != nil {
		t.Fatal(err)
	}
	tx, err := db.Pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(ctx)
	_, err = tx.Exec(ctx, `INSERT INTO organizations(id,name,slug) VALUES($1,'S3 Worker',$2)`, orgID, "s3-worker-"+orgID.String())
	if err == nil {
		_, err = tx.Exec(ctx, `INSERT INTO users(id,email,password_hash) VALUES($1,$2,'!test')`, userID, userID.String()+"@example.test")
	}
	if err == nil {
		_, err = tx.Exec(ctx, `INSERT INTO projects(id,organization_id,name,slug) VALUES($1,$2,'Project','project')`, projectID, orgID)
	}
	if err == nil {
		_, err = tx.Exec(ctx, `INSERT INTO environments(id,project_id,name,slug) VALUES($1,$2,'Production','production')`, environmentID, projectID)
	}
	if err == nil {
		_, err = tx.Exec(ctx, `INSERT INTO compose_services(id,environment_id,name,slug,stack_name,compose_yaml) VALUES($1,$2,'PostgreSQL','postgres',$3,'services: {}')`, serviceID, environmentID, "s3-worker-"+serviceID.String())
	}
	if err == nil {
		_, err = tx.Exec(ctx, `INSERT INTO database_instances(id,environment_id,name,slug,engine,version,compose_service_id,encrypted_credentials) VALUES($1,$2,'PostgreSQL','postgres','postgres','17',$3,$4)`, databaseID, environmentID, serviceID, encryptedDatabaseCredentials)
	}
	if err == nil {
		err = tx.Commit(ctx)
	}
	if err != nil {
		t.Fatal(err)
	}

	var backupID, restoreID uuid.UUID
	t.Cleanup(func() {
		if backupID != uuid.Nil {
			_, _ = db.Pool.Exec(context.Background(), `DELETE FROM jobs WHERE payload->>'backupId'=$1 OR payload->>'restoreId'=$2`, backupID.String(), restoreID.String())
		}
		_, _ = db.Pool.Exec(context.Background(), `DELETE FROM organizations WHERE id=$1`, orgID)
		_, _ = db.Pool.Exec(context.Background(), `DELETE FROM users WHERE id=$1`, userID)
	})

	s3Credentials, _ := json.Marshal(map[string]string{"accessKey": accessKey, "secretKey": secretKey, "sessionToken": ""})
	destinationID := uuid.New()
	encryptedS3Credentials, err := box.Encrypt(s3Credentials, cryptox.ResourceContext("backup-destination", destinationID.String()))
	if err != nil {
		t.Fatal(err)
	}
	destination, err := db.CreateBackupDestination(ctx, store.BackupDestination{ID: destinationID, OrganizationID: orgID, Name: "minio", Endpoint: endpoint, Bucket: bucket, Prefix: "worker", UseTLS: parsedEndpoint.Scheme == "https", EncryptedCredentials: encryptedS3Credentials})
	if err != nil {
		t.Fatal(err)
	}

	work := t.TempDir()
	restoreLog := filepath.Join(work, "restore.log")
	dockerBin := filepath.Join(work, "docker")
	script := `#!/bin/sh
if [ "$1" = "pull" ]; then exit 0; fi
if [ "$1" = "image" ] && [ "$2" = "inspect" ]; then printf '["postgres@sha256:` + strings.Repeat("a", 64) + `"]\n'; exit 0; fi
mount=""
entrypoint=""
filename=""
while [ "$#" -gt 0 ]; do
  case "$1" in
    --volume) shift; mount="${1%%:*}" ;;
    --entrypoint) shift; entrypoint="$1" ;;
    /backup/*) filename="${1#/backup/}" ;;
  esac
  shift
done
case "$entrypoint" in
  pg_dump) printf 'verified worker backup' > "$mount/$filename" ;;
  pg_restore) test "$(cat "$mount/$filename")" = 'verified worker backup' && printf 'restored\n' >> ` + strconv.Quote(restoreLog) + ` ;;
  *) exit 1 ;;
esac
`
	if err = os.WriteFile(dockerBin, []byte(script), 0700); err != nil {
		t.Fatal(err)
	}
	worker := Worker{Store: db, Box: box, Swarm: Swarm{DockerBin: dockerBin}, Databases: database.NewRegistry(), BackupDirectory: filepath.Join(work, "backups"), Logger: slog.New(slog.NewTextHandler(io.Discard, nil))}

	backup, err := db.QueueDatabaseBackup(ctx, orgID, databaseID, userID, &destination.ID)
	if err != nil {
		t.Fatal(err)
	}
	backupID = backup.ID
	backupJob := leaseResourceJob(t, ctx, db, "backup.database", "backupId", backup.ID)
	if err = worker.backupDatabase(ctx, backupJob); err != nil {
		t.Fatal(err)
	}
	if err = worker.finish(ctx, backupJob, nil); err != nil {
		t.Fatal(err)
	}
	backup, err = db.GetDatabaseBackup(ctx, orgID, backup.ID)
	if err != nil || backup.Status != "succeeded" || backup.Path != "" || backup.ObjectKey == "" || backup.SHA256 == "" || !backup.Encrypted || backup.PlaintextSHA256 == "" || backup.EncryptedDataKey == "" || !strings.HasSuffix(backup.ObjectKey, ".enc") || !strings.Contains(backup.UtilityImage, "@sha256:") {
		t.Fatalf("remote backup = %#v, err = %v", backup, err)
	}
	t.Cleanup(func() {
		_ = minioClient.RemoveObject(context.Background(), bucket, backup.ObjectKey, minio.RemoveObjectOptions{})
	})
	if _, err = minioClient.StatObject(ctx, bucket, backup.ObjectKey, minio.StatObjectOptions{}); err != nil {
		t.Fatalf("stat uploaded backup: %v", err)
	}
	object, err := minioClient.GetObject(ctx, bucket, backup.ObjectKey, minio.GetObjectOptions{})
	if err != nil {
		t.Fatal(err)
	}
	remoteBytes, err := io.ReadAll(object)
	_ = object.Close()
	if err != nil || bytes.Contains(remoteBytes, []byte("verified worker backup")) {
		t.Fatalf("remote artifact is not encrypted: err=%v", err)
	}

	restore, err := db.QueueDatabaseRestore(ctx, orgID, backup.ID, userID, "postgres")
	if err != nil {
		t.Fatal(err)
	}
	restoreID = restore.ID
	restoreJob := leaseResourceJob(t, ctx, db, "restore.database", "restoreId", restore.ID)
	if err = worker.restoreDatabase(ctx, restoreJob); err != nil {
		t.Fatal(err)
	}
	if err = worker.finish(ctx, restoreJob, nil); err != nil {
		t.Fatal(err)
	}
	restore, err = db.GetDatabaseRestore(ctx, orgID, restore.ID)
	if err != nil || restore.Status != "succeeded" || restore.UtilityImage != backup.UtilityImage {
		t.Fatalf("restore = %#v, err = %v", restore, err)
	}
	if restored, readErr := os.ReadFile(restoreLog); readErr != nil || string(restored) != "restored\n" {
		t.Fatalf("restore invocation = %q, err = %v", restored, readErr)
	}
}
