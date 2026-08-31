package store

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
)

func TestCustomTLSCertificateLifecycleCommitsWithAudit(t *testing.T) {
	pool, ctx := migrationTestPool(t)
	if err := Migrate(ctx, pool); err != nil {
		t.Fatal(err)
	}
	db := &Store{Pool: pool}
	organizationID, userID, certificateID := uuid.New(), uuid.New(), uuid.New()
	if _, err := pool.Exec(ctx, `INSERT INTO organizations(id,name,slug) VALUES($1,'TLS audit',$2)`, organizationID, "tls-audit-"+organizationID.String()); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO users(id,email,password_hash) VALUES($1,$2,'!test')`, userID, userID.String()+"@example.test"); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `DELETE FROM organizations WHERE id=$1`, organizationID)
		_, _ = pool.Exec(context.Background(), `DELETE FROM users WHERE id=$1`, userID)
	})
	invalidPrincipal := Principal{OrganizationID: organizationID, UserID: uuid.New()}
	principal := Principal{OrganizationID: organizationID, UserID: userID}
	now := time.Now().UTC()
	input := CustomTLSCertificate{ID: certificateID, Name: "Wildcard", EncryptedCertificate: "original-certificate", EncryptedPrivateKey: "original-key", Fingerprint: "sha256:" + strings.Repeat("a", 64), CommonName: "*.example.test", DNSNames: []string{"*.example.test"}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(365 * 24 * time.Hour)}

	if _, err := db.CreateCustomTLSCertificateWithAudit(ctx, invalidPrincipal, input, "127.0.0.1:1234"); err == nil {
		t.Fatal("custom TLS certificate creation succeeded without valid audit evidence")
	}
	if _, err := db.GetCustomTLSCertificate(ctx, organizationID, certificateID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("failed evidence retained custom TLS certificate: %v", err)
	}
	certificate, err := db.CreateCustomTLSCertificateWithAudit(ctx, principal, input, "127.0.0.1:1234")
	if err != nil {
		t.Fatal(err)
	}
	rotated := certificate
	rotated.Name = "Wildcard rotated"
	rotated.EncryptedCertificate = "rotated-certificate"
	rotated.EncryptedPrivateKey = "rotated-key"
	rotated.Fingerprint = "sha256:" + strings.Repeat("b", 64)
	rotated.NotAfter = now.Add(730 * 24 * time.Hour)
	if _, err = db.UpdateCustomTLSCertificateWithAudit(ctx, invalidPrincipal, rotated, "127.0.0.1:1234"); err == nil {
		t.Fatal("custom TLS certificate rotation succeeded without valid audit evidence")
	}
	stored, err := db.GetCustomTLSCertificate(ctx, organizationID, certificate.ID)
	if err != nil || stored.Revision != 1 || stored.EncryptedCertificate != "original-certificate" || stored.EncryptedPrivateKey != "original-key" {
		t.Fatalf("failed evidence changed custom TLS certificate: certificate=%#v err=%v", stored, err)
	}
	certificate, err = db.UpdateCustomTLSCertificateWithAudit(ctx, principal, rotated, "127.0.0.1:1234")
	if err != nil || certificate.Revision != 2 || certificate.EncryptedCertificate != "rotated-certificate" {
		t.Fatalf("audited custom TLS rotation=%#v err=%v", certificate, err)
	}

	if err = db.DeleteCustomTLSCertificateWithAudit(ctx, invalidPrincipal, certificate.ID, "127.0.0.1:1234"); err == nil {
		t.Fatal("custom TLS certificate deletion succeeded without valid audit evidence")
	}
	if _, err = db.GetCustomTLSCertificate(ctx, organizationID, certificate.ID); err != nil {
		t.Fatalf("failed evidence deleted custom TLS certificate: %v", err)
	}
	if err = db.DeleteCustomTLSCertificateWithAudit(ctx, principal, certificate.ID, "127.0.0.1:1234"); err != nil {
		t.Fatal(err)
	}
	if _, err = db.GetCustomTLSCertificate(ctx, organizationID, certificate.ID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("deleted custom TLS certificate lookup error=%v, want not found", err)
	}

	var auditCount int
	if err = pool.QueryRow(ctx, `SELECT count(*) FROM audit_events WHERE organization_id=$1 AND actor_user_id=$2 AND resource_id=$3 AND action IN ('custom_tls_certificate.create','custom_tls_certificate.rotate','custom_tls_certificate.delete')`, organizationID, userID, certificate.ID.String()).Scan(&auditCount); err != nil || auditCount != 3 {
		t.Fatalf("custom TLS certificate audit count=%d err=%v", auditCount, err)
	}
}
