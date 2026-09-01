package deploy

import (
	"context"
	"errors"
	"os"
	"testing"

	"github.com/GhaziBenDahmane/Orka/internal/cryptox"
	"github.com/GhaziBenDahmane/Orka/internal/store"
	"github.com/google/uuid"
)

func TestWorkerRejectsPlaintextRemoteDestinationBeforeCredentialDecryption(t *testing.T) {
	databaseURL := os.Getenv("DOCKYARD_TEST_DATABASE_URL")
	if databaseURL == "" {
		t.Skip("DOCKYARD_TEST_DATABASE_URL is not set")
	}
	db, err := store.Open(context.Background(), databaseURL)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(db.Pool.Close)
	db.RequireRemoteBackups = true

	organizationID, destinationID := uuid.New(), uuid.New()
	if _, err = db.Pool.Exec(context.Background(), `INSERT INTO organizations(id,name,slug) VALUES($1,'Worker TLS Test',$2)`, organizationID, "worker-tls-"+organizationID.String()); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = db.Pool.Exec(context.Background(), `DELETE FROM organizations WHERE id=$1`, organizationID)
	})
	if _, err = db.Pool.Exec(context.Background(), `INSERT INTO backup_destinations(id,organization_id,name,endpoint,bucket,use_tls,encrypted_credentials) VALUES($1,$2,'legacy','http://objects.example.test','backups',false,'deliberately-invalid-ciphertext')`, destinationID, organizationID); err != nil {
		t.Fatal(err)
	}
	box, err := cryptox.New(make([]byte, 32))
	if err != nil {
		t.Fatal(err)
	}
	worker := Worker{Store: db, Box: box}
	if _, err = worker.s3(context.Background(), destinationID); !errors.Is(err, store.ErrRemoteBackupTLSRequired) {
		t.Fatalf("worker destination error=%v, want TLS required", err)
	}
}
