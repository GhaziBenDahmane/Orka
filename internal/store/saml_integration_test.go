package store

import (
	"context"
	"errors"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
)

func TestSAMLProviderStateReplayAndJITIsolation(t *testing.T) {
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

	orgID, otherOrgID := uuid.New(), uuid.New()
	_, err = db.Pool.Exec(ctx, `INSERT INTO organizations(id,name,slug) VALUES($1,'SAML Test',$2),($3,'Other SAML Test',$4)`, orgID, "saml-"+orgID.String(), otherOrgID, "other-saml-"+otherOrgID.String())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = db.Pool.Exec(context.Background(), `DELETE FROM organizations WHERE id=ANY($1)`, []uuid.UUID{orgID, otherOrgID})
		_, _ = db.Pool.Exec(context.Background(), `DELETE FROM users WHERE email=ANY($1)`, []string{"saml-user-" + orgID.String() + "@example.test", "saml-race-" + orgID.String() + "@example.test"})
	})

	provider, err := db.CreateSAMLProvider(ctx, SAMLProvider{OrganizationID: orgID, Name: "workforce", IDPMetadata: "<metadata/>", CertificatePEM: "certificate", EncryptedPrivateKey: "ciphertext", Domains: []string{"example.test"}, EmailAttribute: "mail", NameAttribute: "displayName", DefaultRole: "developer", AllowIDPInitiated: true})
	if err != nil {
		t.Fatal(err)
	}
	otherProvider, err := db.CreateSAMLProvider(ctx, SAMLProvider{OrganizationID: otherOrgID, Name: "other", IDPMetadata: "<metadata/>", CertificatePEM: "certificate", EncryptedPrivateKey: "ciphertext", Domains: []string{"other.test"}, EmailAttribute: "mail", NameAttribute: "displayName", DefaultRole: "viewer"})
	if err != nil {
		t.Fatal(err)
	}

	items, err := db.ListSAMLProviders(ctx, orgID)
	if err != nil || len(items) != 1 || items[0].ID != provider.ID || !items[0].AllowIDPInitiated {
		t.Fatalf("organization providers = %#v, err = %v", items, err)
	}
	discovered, err := db.DiscoverSAML(ctx, "EXAMPLE.TEST")
	found := false
	for _, item := range discovered {
		found = found || item.ID == provider.ID
	}
	if err != nil || !found {
		t.Fatalf("discovered providers = %#v, err = %v", discovered, err)
	}
	if err = db.DisableSAMLProvider(ctx, orgID, otherProvider.ID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("cross-tenant disable error = %v, want not found", err)
	}
	rotationExpiry := time.Now().Add(365 * 24 * time.Hour)
	if err = db.BeginSAMLCertificateRotation(ctx, orgID, provider.ID, "replacement-certificate", "replacement-key", rotationExpiry); err != nil {
		t.Fatalf("begin certificate rotation: %v", err)
	}
	if err = db.BeginSAMLCertificateRotation(ctx, orgID, provider.ID, "overwritten-certificate", "overwritten-key", rotationExpiry); !errors.Is(err, ErrSAMLCertificateRotationPending) {
		t.Fatalf("replace pending certificate error=%v, want pending", err)
	}
	rotating, err := db.GetOrganizationSAMLProvider(ctx, orgID, provider.ID)
	if err != nil || rotating.PendingCertificatePEM != "replacement-certificate" || rotating.PendingCertificateNotAfter == nil {
		t.Fatalf("pending certificate rotation=%#v err=%v", rotating, err)
	}
	if err = db.CancelSAMLCertificateRotation(ctx, otherOrgID, provider.ID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("cross-tenant rotation cancellation error=%v, want not found", err)
	}
	if err = db.CreateSAMLState(ctx, []byte("rotation-state"), provider.ID, "rotation-request"); err != nil {
		t.Fatal(err)
	}
	if err = db.PromoteSAMLCertificateRotation(ctx, orgID, provider.ID); err != nil {
		t.Fatalf("promote certificate rotation: %v", err)
	}
	var activeCertificate, activeKey string
	var pendingCertificate *string
	var pendingStates int
	if err = db.Pool.QueryRow(ctx, `SELECT certificate_pem,encrypted_private_key,pending_certificate_pem,(SELECT count(*) FROM saml_states WHERE provider_id=$1) FROM saml_providers WHERE id=$1`, provider.ID).Scan(&activeCertificate, &activeKey, &pendingCertificate, &pendingStates); err != nil || activeCertificate != "replacement-certificate" || activeKey != "replacement-key" || pendingCertificate != nil || pendingStates != 0 {
		t.Fatalf("promoted certificate=%q key=%q pending=%v states=%d err=%v", activeCertificate, activeKey, pendingCertificate, pendingStates, err)
	}
	if err = db.BeginSAMLCertificateRotation(ctx, orgID, provider.ID, "cancelled-certificate", "cancelled-key", rotationExpiry); err != nil {
		t.Fatal(err)
	}
	if err = db.CancelSAMLCertificateRotation(ctx, orgID, provider.ID); err != nil {
		t.Fatalf("cancel certificate rotation: %v", err)
	}

	state := []byte("opaque-state-hash")
	if err = db.CreateSAMLState(ctx, state, provider.ID, "request-1"); err != nil {
		t.Fatal(err)
	}
	if _, err = db.ConsumeSAMLState(ctx, state, otherProvider.ID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("cross-provider state consume error = %v, want not found", err)
	}
	requestID, err := db.ConsumeSAMLState(ctx, state, provider.ID)
	if err != nil || requestID != "request-1" {
		t.Fatalf("consumed request = %q, err = %v", requestID, err)
	}
	if _, err = db.ConsumeSAMLState(ctx, state, provider.ID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("replayed state error = %v, want not found", err)
	}

	if err = db.RecordSAMLAssertion(ctx, provider.ID, "assertion-1", time.Now().Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	if err = db.RecordSAMLAssertion(ctx, provider.ID, "assertion-1", time.Now().Add(time.Hour)); err == nil {
		t.Fatal("replayed assertion was accepted")
	}

	email := "saml-user-" + orgID.String() + "@example.test"
	userID, err := db.JITSAMLUser(ctx, provider, "subject-1", email, "SAML User")
	if err != nil {
		t.Fatal(err)
	}
	repeatedID, err := db.JITSAMLUser(ctx, provider, "subject-1", email, "Changed Name")
	if err != nil || repeatedID != userID {
		t.Fatalf("repeated JIT user = %s, err = %v", repeatedID, err)
	}
	var role string
	if err = db.Pool.QueryRow(ctx, `SELECT role FROM memberships WHERE organization_id=$1 AND user_id=$2`, orgID, userID).Scan(&role); err != nil || role != "developer" {
		t.Fatalf("JIT membership role = %q, err = %v", role, err)
	}

	raceEmail := "saml-race-" + orgID.String() + "@example.test"
	start := make(chan struct{})
	results := make(chan struct {
		id  uuid.UUID
		err error
	}, 2)
	var group sync.WaitGroup
	for _, subject := range []string{"race-subject-1", "race-subject-2"} {
		subject := subject
		group.Add(1)
		go func() {
			defer group.Done()
			<-start
			id, jitErr := db.JITSAMLUser(ctx, provider, subject, raceEmail, "Concurrent SAML User")
			results <- struct {
				id  uuid.UUID
				err error
			}{id: id, err: jitErr}
		}()
	}
	close(start)
	group.Wait()
	close(results)
	var racedUserID uuid.UUID
	for result := range results {
		if result.err != nil {
			t.Fatalf("concurrent SAML JIT failed: %v", result.err)
		}
		if racedUserID != uuid.Nil && racedUserID != result.id {
			t.Fatalf("concurrent SAML JIT created distinct users %s and %s", racedUserID, result.id)
		}
		racedUserID = result.id
	}
	var users, identities int
	if err = db.Pool.QueryRow(ctx, `SELECT count(*) FROM users WHERE email=$1`, raceEmail).Scan(&users); err != nil {
		t.Fatal(err)
	}
	if err = db.Pool.QueryRow(ctx, `SELECT count(*) FROM saml_external_identities WHERE provider_id=$1 AND user_id=$2`, provider.ID, racedUserID).Scan(&identities); err != nil {
		t.Fatal(err)
	}
	if users != 1 || identities != 2 {
		t.Fatalf("concurrent SAML JIT users=%d identities=%d", users, identities)
	}
}
