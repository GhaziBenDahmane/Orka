package store

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/google/uuid"
)

func TestOIDCStateCarriesNonceAndIsConsumedOnce(t *testing.T) {
	databaseURL := os.Getenv("DOCKYARD_TEST_DATABASE_URL")
	if databaseURL == "" {
		t.Skip("DOCKYARD_TEST_DATABASE_URL is not set")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	db, err := Open(ctx, databaseURL)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(db.Pool.Close)

	organizationID, providerID := uuid.New(), uuid.New()
	if _, err = db.Pool.Exec(ctx, `INSERT INTO organizations(id,name,slug) VALUES($1,'OIDC state',$2)`, organizationID, "oidc-state-"+organizationID.String()); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = db.Pool.Exec(context.Background(), `DELETE FROM organizations WHERE id=$1`, organizationID)
	})
	if _, err = db.Pool.Exec(ctx, `INSERT INTO oidc_providers(id,organization_id,name,issuer,client_id,encrypted_client_secret,domains) VALUES($1,$2,'test','https://idp.example.test','client','secret','{example.test}')`, providerID, organizationID); err != nil {
		t.Fatal(err)
	}

	hash := []byte("state digest")
	if err = db.CreateOIDCState(ctx, hash, providerID, "pkce-verifier", "login-nonce"); err != nil {
		t.Fatal(err)
	}
	gotProviderID, verifier, nonce, err := db.ConsumeOIDCState(ctx, hash)
	if err != nil || gotProviderID != providerID || verifier != "pkce-verifier" || nonce != "login-nonce" {
		t.Fatalf("consumed state provider=%s verifier=%q nonce=%q err=%v", gotProviderID, verifier, nonce, err)
	}
	if _, _, _, err = db.ConsumeOIDCState(ctx, hash); err != ErrNotFound {
		t.Fatalf("second consumption error=%v, want ErrNotFound", err)
	}
}
