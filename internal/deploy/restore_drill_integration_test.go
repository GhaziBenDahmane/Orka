package deploy

import (
	"bytes"
	"context"
	"crypto/rand"
	"io"
	"log/slog"
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
)

func TestRestoreDrillUsesIsolatedStackAndEncryptedArtifact(t *testing.T) {
	databaseURL := os.Getenv("DOCKYARD_TEST_DATABASE_URL")
	if databaseURL == "" {
		t.Skip("DOCKYARD_TEST_DATABASE_URL is not set")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	db, err := store.Open(ctx, databaseURL)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(db.Pool.Close)
	box, _ := cryptox.New(bytes.Repeat([]byte{4}, 32))
	orgID, projectID, environmentID, serviceID, databaseID, backupID := uuid.New(), uuid.New(), uuid.New(), uuid.New(), uuid.New(), uuid.New()
	var restoreID uuid.UUID
	directory := t.TempDir()
	plainPath := filepath.Join(directory, backupID.String()+".dump")
	encryptedPath := plainPath + ".enc"
	if err = os.WriteFile(plainPath, []byte("drill backup"), 0600); err != nil {
		t.Fatal(err)
	}
	plainHash, _, _ := checksumFile(plainPath)
	dataKey := make([]byte, 32)
	_, _ = rand.Read(dataKey)
	artifactBox, _ := cryptox.New(dataKey)
	wrappedKey, _ := box.Encrypt(dataKey, "backup-data-key:"+backupID.String())
	if err = encryptBackupFile(artifactBox, plainPath, encryptedPath, backupID); err != nil {
		t.Fatal(err)
	}
	cipherHash, cipherSize, _ := checksumFile(encryptedPath)
	for _, statement := range []struct {
		query string
		args  []any
	}{
		{`INSERT INTO organizations(id,name,slug) VALUES($1,'Drill',$2)`, []any{orgID, "drill-" + orgID.String()}},
		{`INSERT INTO projects(id,organization_id,name,slug) VALUES($1,$2,'P','p')`, []any{projectID, orgID}},
		{`INSERT INTO environments(id,project_id,name,slug) VALUES($1,$2,'E','e')`, []any{environmentID, projectID}},
		{`INSERT INTO compose_services(id,environment_id,name,slug,stack_name,compose_yaml) VALUES($1,$2,'DB','db',$3,'services: {}')`, []any{serviceID, environmentID, "production-" + serviceID.String()}},
		{`INSERT INTO database_instances(id,environment_id,name,slug,engine,version,compose_service_id,encrypted_credentials) VALUES($1,$2,'DB','db','postgres','17',$3,'unused')`, []any{databaseID, environmentID, serviceID}},
		{`INSERT INTO database_backups(id,database_instance_id,status,format,path,size_bytes,sha256,encrypted,plaintext_sha256,encrypted_data_key,finished_at) VALUES($1,$2,'succeeded','native',$3,$4,$5,true,$6,$7,now())`, []any{backupID, databaseID, encryptedPath, cipherSize, cipherHash, plainHash, wrappedKey}},
	} {
		if _, err = db.Pool.Exec(ctx, statement.query, statement.args...); err != nil {
			t.Fatal(err)
		}
	}
	t.Cleanup(func() {
		_, _ = db.Pool.Exec(context.Background(), `DELETE FROM jobs WHERE payload->>'restoreId'=$1`, restoreID.String())
		_, _ = db.Pool.Exec(context.Background(), `DELETE FROM organizations WHERE id=$1`, orgID)
	})
	logPath := filepath.Join(directory, "docker.log")
	dockerBin := filepath.Join(directory, "docker")
	script := `#!/bin/sh
printf '%s ' "$@" >> ` + strconv.Quote(logPath) + `; printf '\n' >> ` + strconv.Quote(logPath) + `
if [ "$1" = info ]; then echo active; exit 0; fi
if [ "$1" = network ] && [ "$2" = inspect ]; then echo 'overlay|swarm|true|{"encrypted":""}'; exit 0; fi
if [ "$1" = network ]; then exit 0; fi
if [ "$1" = stack ]; then exit 0; fi
if [ "$1" = service ] && [ "$2" = ls ]; then echo 'drill_verify 1/1'; exit 0; fi
if [ "$1" = service ] && [ "$2" = inspect ]; then echo 'null'; exit 0; fi
mount=''; entry=''; filename=''
while [ "$#" -gt 0 ]; do case "$1" in --volume) shift; mount="${1%%:*}" ;; --entrypoint) shift; entry="$1" ;; /backup/*) filename="${1#/backup/}" ;; esac; shift; done
[ "$entry" = pg_isready ] && exit 0
[ "$entry" = pg_restore ] && [ "$(cat "$mount/$filename")" = 'drill backup' ]
`
	if err = os.WriteFile(dockerBin, []byte(script), 0700); err != nil {
		t.Fatal(err)
	}
	worker := Worker{Store: db, Box: box, Swarm: Swarm{DockerBin: dockerBin, Network: "dockyard-public", Timeout: 5 * time.Second}, Databases: database.NewRegistry(), BackupDirectory: directory, Logger: slog.New(slog.NewTextHandler(io.Discard, nil))}
	if err = worker.queueRestoreDrill(ctx, backupID); err != nil {
		t.Fatal(err)
	}
	if err = worker.queueRestoreDrill(ctx, backupID); err != nil {
		t.Fatal(err)
	}
	if err = db.Pool.QueryRow(ctx, `SELECT id FROM database_restores WHERE database_backup_id=$1 AND kind='drill'`, backupID).Scan(&restoreID); err != nil {
		t.Fatal(err)
	}
	var drillJobs int
	if err = db.Pool.QueryRow(ctx, `SELECT count(*) FROM jobs WHERE kind='restore.database' AND payload->>'restoreId'=$1`, restoreID.String()).Scan(&drillJobs); err != nil || drillJobs != 1 {
		t.Fatalf("restore drill jobs = %d, err = %v", drillJobs, err)
	}
	leasedJob := leaseResourceJob(t, ctx, db, "restore.database", "restoreId", restoreID)
	if err = worker.restoreDatabase(ctx, leasedJob); err != nil {
		t.Fatal(err)
	}
	if err = worker.finish(ctx, leasedJob, nil); err != nil {
		t.Fatal(err)
	}
	restore, err := db.GetDatabaseRestore(ctx, orgID, restoreID)
	if err != nil || restore.Status != "succeeded" || restore.Kind != "drill" {
		t.Fatalf("restore drill = %#v, err = %v", restore, err)
	}
	logData, _ := os.ReadFile(logPath)
	if !strings.Contains(string(logData), "stack deploy") || !strings.Contains(string(logData), "stack rm drill-") || strings.Contains(string(logData), "stack rm production-") {
		t.Fatalf("drill did not use an isolated stack:\n%s", logData)
	}
}
