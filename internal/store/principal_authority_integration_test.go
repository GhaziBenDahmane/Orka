package store

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"
)

func TestAdministrativeMutationsRevalidateActorAuthorityAfterOrganizationLock(t *testing.T) {
	t.Run("member update after admin demotion", func(t *testing.T) {
		db, ctx, organizationID, _, actorID := authorityFenceFixture(t)
		targetID := uuid.New()
		if _, err := db.Pool.Exec(ctx, `INSERT INTO users(id,email,password_hash) VALUES($1,$2,'!test')`, targetID, targetID.String()+"@example.test"); err != nil {
			t.Fatal(err)
		}
		if _, err := db.Pool.Exec(ctx, `INSERT INTO memberships(organization_id,user_id,role) VALUES($1,$2,'viewer')`, organizationID, targetID); err != nil {
			t.Fatal(err)
		}

		demotion, err := db.Pool.Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		defer demotion.Rollback(ctx)
		if _, err = updateOrganizationMemberRoleTx(ctx, demotion, organizationID, actorID, "developer", "owner"); err != nil {
			t.Fatal(err)
		}

		result := make(chan error, 1)
		started := make(chan struct{})
		go func() {
			close(started)
			_, updateErr := db.UpdateOrganizationMemberRoleWithAudit(ctx, Principal{OrganizationID: organizationID, UserID: actorID, Role: "admin"}, targetID, "developer", "127.0.0.1:1234")
			result <- updateErr
		}()
		<-started
		assertAuthorityMutationBlocked(t, result)
		if err = demotion.Commit(ctx); err != nil {
			t.Fatal(err)
		}
		assertInsufficientRoleResult(t, result)
		assertMembershipRole(t, db.Pool, ctx, organizationID, targetID, "viewer")
		assertNoAuthorityMutationAudit(t, db, ctx, organizationID, actorID, "membership.role.update")

		t.Cleanup(func() {
			_, _ = db.Pool.Exec(context.Background(), `DELETE FROM users WHERE id=$1`, targetID)
		})
	})

	t.Run("invitation after admin removal", func(t *testing.T) {
		db, ctx, organizationID, _, actorID := authorityFenceFixture(t)
		removal, err := db.Pool.Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		defer removal.Rollback(ctx)
		if err = deleteOrganizationMemberTx(ctx, removal, organizationID, actorID, "owner"); err != nil {
			t.Fatal(err)
		}

		email := "stale-admin-" + uuid.NewString() + "@example.test"
		result := make(chan error, 1)
		started := make(chan struct{})
		go func() {
			close(started)
			_, createErr := db.CreateOrganizationInvitationWithAudit(ctx, Principal{OrganizationID: organizationID, UserID: actorID, Role: "admin"}, email, "viewer", []byte(uuid.NewString()), time.Now().Add(time.Hour), "127.0.0.1:1234")
			result <- createErr
		}()
		<-started
		assertAuthorityMutationBlocked(t, result)
		if err = removal.Commit(ctx); err != nil {
			t.Fatal(err)
		}
		assertInsufficientRoleResult(t, result)

		var invitations int
		if err = db.Pool.QueryRow(ctx, `SELECT count(*) FROM organization_invitations WHERE organization_id=$1 AND email=$2`, organizationID, email).Scan(&invitations); err != nil || invitations != 0 {
			t.Fatalf("stale actor created invitations=%d err=%v", invitations, err)
		}
		assertNoAuthorityMutationAudit(t, db, ctx, organizationID, actorID, "invitation.create")
	})

	t.Run("mandatory SSO after owner demotion", func(t *testing.T) {
		db, ctx, organizationID, ownerID, _ := authorityFenceFixture(t)
		secondOwnerID := uuid.New()
		if _, err := db.Pool.Exec(ctx, `INSERT INTO users(id,email,password_hash) VALUES($1,$2,'!test')`, secondOwnerID, secondOwnerID.String()+"@example.test"); err != nil {
			t.Fatal(err)
		}
		if _, err := db.Pool.Exec(ctx, `INSERT INTO memberships(organization_id,user_id,role) VALUES($1,$2,'owner')`, organizationID, secondOwnerID); err != nil {
			t.Fatal(err)
		}
		if _, err := db.CreateOIDCProvider(ctx, OIDCProvider{OrganizationID: organizationID, Name: "Authority fence", Issuer: "https://identity.example.test", ClientID: "client", EncryptedClientSecret: "ciphertext", Domains: []string{"example.test"}}); err != nil {
			t.Fatal(err)
		}

		demotion, err := db.Pool.Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		defer demotion.Rollback(ctx)
		if _, err = updateOrganizationMemberRoleTx(ctx, demotion, organizationID, ownerID, "admin", "owner"); err != nil {
			t.Fatal(err)
		}

		result := make(chan error, 1)
		started := make(chan struct{})
		go func() {
			close(started)
			_, policyErr := db.SetOrganizationAuthSettingsWithAudit(ctx, Principal{OrganizationID: organizationID, UserID: ownerID, Role: "owner"}, true, "127.0.0.1:1234")
			result <- policyErr
		}()
		<-started
		assertAuthorityMutationBlocked(t, result)
		if err = demotion.Commit(ctx); err != nil {
			t.Fatal(err)
		}
		assertInsufficientRoleResult(t, result)

		settings, err := db.GetOrganizationAuthSettings(ctx, organizationID)
		if err != nil || settings.RequireSSO {
			t.Fatalf("stale owner changed mandatory SSO settings=%#v err=%v", settings, err)
		}
		assertNoAuthorityMutationAudit(t, db, ctx, organizationID, ownerID, "sso.policy.update")
		t.Cleanup(func() {
			_, _ = db.Pool.Exec(context.Background(), `DELETE FROM users WHERE id=$1`, secondOwnerID)
		})
	})

	t.Run("invitation after service account disable", func(t *testing.T) {
		db, ctx, organizationID, _, _ := authorityFenceFixture(t)
		accountID := uuid.New()
		if _, err := db.Pool.Exec(ctx, `INSERT INTO service_accounts(id,organization_id,name,role) VALUES($1,$2,'stale-admin','admin')`, accountID, organizationID); err != nil {
			t.Fatal(err)
		}
		principal := Principal{OrganizationID: organizationID, ServiceAccountID: &accountID, Role: "admin"}
		activeInvitation, err := db.CreateOrganizationInvitationWithAudit(ctx, principal, "active-service-account-"+uuid.NewString()+"@example.test", "viewer", []byte(uuid.NewString()), time.Now().Add(time.Hour), "127.0.0.1:1234")
		if err != nil {
			t.Fatal(err)
		}
		var creatorIsNull bool
		if err = db.Pool.QueryRow(ctx, `SELECT created_by IS NULL FROM organization_invitations WHERE id=$1`, activeInvitation.ID).Scan(&creatorIsNull); err != nil || !creatorIsNull {
			t.Fatalf("service-account invitation human creator null=%t err=%v", creatorIsNull, err)
		}

		disable, err := db.Pool.Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		defer disable.Rollback(ctx)
		if _, err = disable.Exec(ctx, `UPDATE service_accounts SET enabled=false WHERE id=$1`, accountID); err != nil {
			t.Fatal(err)
		}

		email := "stale-service-account-" + uuid.NewString() + "@example.test"
		result := make(chan error, 1)
		started := make(chan struct{})
		go func() {
			close(started)
			_, createErr := db.CreateOrganizationInvitationWithAudit(ctx, principal, email, "viewer", []byte(uuid.NewString()), time.Now().Add(time.Hour), "127.0.0.1:1234")
			result <- createErr
		}()
		<-started
		assertAuthorityMutationBlocked(t, result)
		if err = disable.Commit(ctx); err != nil {
			t.Fatal(err)
		}
		assertInsufficientRoleResult(t, result)

		var invitations, audits int
		if err = db.Pool.QueryRow(ctx, `SELECT count(*) FROM organization_invitations WHERE organization_id=$1 AND email=$2`, organizationID, email).Scan(&invitations); err != nil || invitations != 0 {
			t.Fatalf("disabled service account created invitations=%d err=%v", invitations, err)
		}
		if err = db.Pool.QueryRow(ctx, `SELECT count(*) FROM audit_events WHERE organization_id=$1 AND actor_service_account_id=$2 AND action='invitation.create'`, organizationID, accountID).Scan(&audits); err != nil || audits != 1 {
			t.Fatalf("service account invitation audit events=%d err=%v, want only the authorized mutation", audits, err)
		}
	})
}

func authorityFenceFixture(t *testing.T) (*Store, context.Context, uuid.UUID, uuid.UUID, uuid.UUID) {
	t.Helper()
	pool, ctx := migrationTestPool(t)
	if err := Migrate(ctx, pool); err != nil {
		t.Fatal(err)
	}
	db := &Store{Pool: pool}
	organizationID, ownerID, actorID := uuid.New(), uuid.New(), uuid.New()
	if _, err := pool.Exec(ctx, `INSERT INTO organizations(id,name,slug) VALUES($1,'Authority fence',$2)`, organizationID, "authority-fence-"+organizationID.String()); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO users(id,email,password_hash) VALUES($1,$2,'!test'),($3,$4,'!test')`, ownerID, ownerID.String()+"@example.test", actorID, actorID.String()+"@example.test"); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO memberships(organization_id,user_id,role) VALUES($1,$2,'owner'),($1,$3,'admin')`, organizationID, ownerID, actorID); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `DELETE FROM organizations WHERE id=$1`, organizationID)
		_, _ = pool.Exec(context.Background(), `DELETE FROM users WHERE id=ANY($1)`, []uuid.UUID{ownerID, actorID})
	})
	return db, ctx, organizationID, ownerID, actorID
}

func assertAuthorityMutationBlocked(t *testing.T, result <-chan error) {
	t.Helper()
	select {
	case err := <-result:
		t.Fatalf("administrative mutation bypassed organization lock: %v", err)
	case <-time.After(100 * time.Millisecond):
	}
}

func assertInsufficientRoleResult(t *testing.T, result <-chan error) {
	t.Helper()
	select {
	case err := <-result:
		if !errors.Is(err, ErrInsufficientRole) {
			t.Fatalf("administrative mutation error=%v, want ErrInsufficientRole", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("administrative mutation did not resume after actor authority changed")
	}
}

func assertNoAuthorityMutationAudit(t *testing.T, db *Store, ctx context.Context, organizationID, actorID uuid.UUID, action string) {
	t.Helper()
	var audits int
	if err := db.Pool.QueryRow(ctx, `SELECT count(*) FROM audit_events WHERE organization_id=$1 AND actor_user_id=$2 AND action=$3`, organizationID, actorID, action).Scan(&audits); err != nil || audits != 0 {
		t.Fatalf("rejected mutation retained audit events=%d err=%v", audits, err)
	}
}
