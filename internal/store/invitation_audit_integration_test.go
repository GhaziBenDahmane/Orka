package store

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"
)

func TestInvitationLifecycleCommitsWithAudit(t *testing.T) {
	pool, ctx := migrationTestPool(t)
	if err := Migrate(ctx, pool); err != nil {
		t.Fatal(err)
	}
	db := &Store{Pool: pool}
	organizationID, ownerID := uuid.New(), uuid.New()
	if _, err := pool.Exec(ctx, `INSERT INTO organizations(id,name,slug) VALUES($1,'Invitation audit',$2)`, organizationID, "invitation-audit-"+organizationID.String()); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO users(id,email,password_hash) VALUES($1,$2,'!test')`, ownerID, ownerID.String()+"@example.test"); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `DELETE FROM organizations WHERE id=$1`, organizationID)
		_, _ = pool.Exec(context.Background(), `DELETE FROM users WHERE email LIKE '%@invitation-audit.test' OR id=$1`, ownerID)
	})
	principal := Principal{OrganizationID: organizationID, UserID: ownerID, Role: "owner"}
	missingServiceAccountID := uuid.New()
	invalidAuditPrincipal := principal
	invalidAuditPrincipal.ServiceAccountID = &missingServiceAccountID
	expiresAt := time.Now().Add(7 * 24 * time.Hour)

	first, err := db.CreateOrganizationInvitationWithAudit(ctx, principal, "replace@invitation-audit.test", "developer", []byte("first-invitation-hash"), expiresAt, "127.0.0.1:1234")
	if err != nil {
		t.Fatal(err)
	}
	if _, err = db.CreateOrganizationInvitationWithAudit(ctx, invalidAuditPrincipal, first.Email, "viewer", []byte("replacement-invitation-hash"), expiresAt, "127.0.0.1:1234"); err == nil {
		t.Fatal("replacement invitation succeeded without valid audit evidence")
	}
	stored, err := db.GetOrganizationInvitation(ctx, organizationID, first.ID)
	if err != nil || stored.RevokedAt != nil {
		t.Fatalf("failed evidence revoked existing invitation: invitation=%#v err=%v", stored, err)
	}
	var pendingCount int
	if err = pool.QueryRow(ctx, `SELECT count(*) FROM organization_invitations WHERE organization_id=$1 AND email=$2 AND revoked_at IS NULL AND accepted_at IS NULL`, organizationID, first.Email).Scan(&pendingCount); err != nil || pendingCount != 1 {
		t.Fatalf("failed evidence retained replacement invitation: count=%d err=%v", pendingCount, err)
	}

	if err = db.RevokeOrganizationInvitationWithAudit(ctx, invalidAuditPrincipal, first.ID, "127.0.0.1:1234"); err == nil {
		t.Fatal("invitation revocation succeeded without valid audit evidence")
	}
	stored, err = db.GetOrganizationInvitation(ctx, organizationID, first.ID)
	if err != nil || stored.RevokedAt != nil {
		t.Fatalf("failed evidence revoked invitation: invitation=%#v err=%v", stored, err)
	}
	if err = db.RevokeOrganizationInvitationWithAudit(ctx, principal, first.ID, "127.0.0.1:1234"); err != nil {
		t.Fatal(err)
	}

	acceptedTokenHash := []byte("accepted-invitation-hash")
	acceptedInvitation, err := db.CreateOrganizationInvitationWithAudit(ctx, principal, "accepted@invitation-audit.test", "viewer", acceptedTokenHash, expiresAt, "127.0.0.1:1234")
	if err != nil {
		t.Fatal(err)
	}
	acceptance, err := db.AcceptOrganizationInvitationWithAudit(ctx, acceptedTokenHash, "Accepted User", "pre-hashed-password", "127.0.0.1:1234")
	if err != nil {
		t.Fatal(err)
	}
	if acceptance.InvitationID != acceptedInvitation.ID || acceptance.OrganizationID != organizationID || acceptance.Role != "viewer" {
		t.Fatalf("invitation acceptance=%#v", acceptance)
	}
	var membershipCount int
	if err = pool.QueryRow(ctx, `SELECT count(*) FROM memberships WHERE organization_id=$1 AND user_id=$2 AND role='viewer'`, organizationID, acceptance.UserID).Scan(&membershipCount); err != nil || membershipCount != 1 {
		t.Fatalf("accepted membership count=%d err=%v", membershipCount, err)
	}

	var auditCount int
	if err = pool.QueryRow(ctx, `SELECT count(*) FROM audit_events WHERE organization_id=$1 AND action IN ('invitation.create','invitation.revoke','invitation.accept')`, organizationID).Scan(&auditCount); err != nil || auditCount != 4 {
		t.Fatalf("invitation lifecycle audit count=%d err=%v", auditCount, err)
	}
	var acceptanceActor uuid.UUID
	if err = pool.QueryRow(ctx, `SELECT actor_user_id FROM audit_events WHERE organization_id=$1 AND action='invitation.accept' AND resource_id=$2`, organizationID, acceptedInvitation.ID.String()).Scan(&acceptanceActor); err != nil || acceptanceActor != acceptance.UserID {
		t.Fatalf("invitation acceptance actor=%s err=%v", acceptanceActor, err)
	}
}
