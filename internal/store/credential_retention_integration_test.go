package store

import (
	"testing"
	"time"

	"github.com/google/uuid"
)

func TestPruneExpiredCredentialsPreservesActiveAndRecentRecords(t *testing.T) {
	pool, ctx := migrationTestPool(t)
	if err := Migrate(ctx, pool); err != nil {
		t.Fatal(err)
	}

	organizationID, userID := uuid.New(), uuid.New()
	projectID, environmentID, serviceID := uuid.New(), uuid.New(), uuid.New()
	serviceAccountID, clusterID := uuid.New(), uuid.New()
	oidcProviderID, samlProviderID := uuid.New(), uuid.New()
	statements := []struct {
		query string
		args  []any
	}{
		{`INSERT INTO organizations(id,name,slug) VALUES($1,'Credential retention',$2)`, []any{organizationID, "credential-retention-" + organizationID.String()}},
		{`INSERT INTO users(id,email,password_hash) VALUES($1,$2,'unused')`, []any{userID, userID.String() + "@example.test"}},
		{`INSERT INTO projects(id,organization_id,name,slug) VALUES($1,$2,'Project','project')`, []any{projectID, organizationID}},
		{`INSERT INTO environments(id,project_id,name,slug) VALUES($1,$2,'Production','production')`, []any{environmentID, projectID}},
		{`INSERT INTO compose_services(id,environment_id,name,slug,stack_name,compose_yaml) VALUES($1,$2,'API','api',$3,'services: {}')`, []any{serviceID, environmentID, "retention-" + serviceID.String()}},
		{`INSERT INTO service_accounts(id,organization_id,name,role) VALUES($1,$2,'automation','developer')`, []any{serviceAccountID, organizationID}},
		{`INSERT INTO clusters(id,organization_id,name,slug) VALUES($1,$2,'Primary','primary')`, []any{clusterID, organizationID}},
		{`INSERT INTO oidc_providers(id,organization_id,name,issuer,client_id,encrypted_client_secret) VALUES($1,$2,'OIDC','https://id.example.test','client','encrypted')`, []any{oidcProviderID, organizationID}},
		{`INSERT INTO saml_providers(id,organization_id,name,idp_metadata,certificate_pem,encrypted_private_key) VALUES($1,$2,'SAML','metadata','certificate','encrypted')`, []any{samlProviderID, organizationID}},
		{`INSERT INTO sessions(id,user_id,token_hash,expires_at) VALUES($1,$2,$3,now()-interval '31 days'),($4,$2,$5,now()+interval '1 day')`, []any{uuid.New(), userID, []byte("old-session"), uuid.New(), []byte("active-session")}},
		{`INSERT INTO service_account_tokens(id,service_account_id,token_hash,expires_at,revoked_at) VALUES($1,$2,$3,now()+interval '1 day',now()-interval '31 days'),($4,$2,$5,now()+interval '1 day',now()-interval '1 day'),($6,$2,$7,now()+interval '1 day',NULL)`, []any{uuid.New(), serviceAccountID, []byte("old-service-account"), uuid.New(), []byte("recent-service-account"), uuid.New(), []byte("active-service-account")}},
		{`INSERT INTO scim_tokens(id,organization_id,name,token_hash,expires_at,revoked_at) VALUES($1,$2,'old',$3,now()-interval '31 days',NULL),($4,$2,'active',$5,now()+interval '1 day',NULL)`, []any{uuid.New(), organizationID, []byte("old-scim"), uuid.New(), []byte("active-scim")}},
		{`INSERT INTO deploy_tokens(id,compose_service_id,token_hash,name,expires_at,revoked_at) VALUES($1,$2,$3,'old',now()+interval '1 day',now()-interval '31 days'),($4,$2,$5,'active',now()+interval '1 day',NULL)`, []any{uuid.New(), serviceID, []byte("old-deploy"), uuid.New(), []byte("active-deploy")}},
		{`INSERT INTO organization_invitations(id,organization_id,email,role,token_hash,expires_at,accepted_at,accepted_user_id) VALUES($1,$2,'old@example.test','viewer',$3,now()-interval '31 days',now()-interval '31 days',$4),($5,$2,'active@example.test','viewer',$6,now()+interval '1 day',NULL,NULL)`, []any{uuid.New(), organizationID, []byte("old-invitation"), userID, uuid.New(), []byte("active-invitation")}},
		{`INSERT INTO cluster_enrollment_tokens(id,cluster_id,token_hash,expires_at,used_at) VALUES($1,$2,$3,now()+interval '1 day',now()-interval '31 days'),($4,$2,$5,now()+interval '1 day',NULL)`, []any{uuid.New(), clusterID, []byte("old-enrollment"), uuid.New(), []byte("active-enrollment")}},
		{`INSERT INTO oidc_states(token_hash,provider_id,provider_revision,code_verifier,nonce,expires_at) VALUES($1,$2,1,'old','old-nonce',now()-interval '1 second'),($3,$2,1,'active','active-nonce',now()+interval '1 day')`, []any{[]byte("old-oidc"), oidcProviderID, []byte("active-oidc")}},
		{`INSERT INTO saml_states(token_hash,provider_id,provider_revision,request_id,expires_at) VALUES($1,$2,1,'old',now()-interval '1 second'),($3,$2,1,'active',now()+interval '1 day')`, []any{[]byte("old-saml-state"), samlProviderID, []byte("active-saml-state")}},
		{`INSERT INTO saml_assertions(provider_id,assertion_id,expires_at) VALUES($1,'old',now()-interval '1 second'),($1,'active',now()+interval '1 day')`, []any{samlProviderID}},
	}
	for _, statement := range statements {
		if _, err := pool.Exec(ctx, statement.query, statement.args...); err != nil {
			t.Fatal(err)
		}
	}

	db := &Store{Pool: pool}
	result, err := db.PruneExpiredCredentials(ctx, 30*24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	want := CredentialPruneResult{Sessions: 1, ServiceAccountTokens: 1, SCIMTokens: 1, DeployTokens: 1, Invitations: 1, ClusterEnrollmentTokens: 1, OIDCStates: 1, SAMLStates: 1, SAMLAssertions: 1}
	if result != want || result.Total() != 9 {
		t.Fatalf("prune result=%+v total=%d, want %+v total=9", result, result.Total(), want)
	}

	for _, table := range []string{"sessions", "scim_tokens", "deploy_tokens", "organization_invitations", "cluster_enrollment_tokens", "oidc_states", "saml_states", "saml_assertions"} {
		var count int
		if err = pool.QueryRow(ctx, `SELECT count(*) FROM `+table).Scan(&count); err != nil || count != 1 {
			t.Fatalf("%s remaining=%d err=%v, want 1", table, count, err)
		}
	}
	var serviceAccountTokens int
	if err = pool.QueryRow(ctx, `SELECT count(*) FROM service_account_tokens`).Scan(&serviceAccountTokens); err != nil || serviceAccountTokens != 2 {
		t.Fatalf("service_account_tokens remaining=%d err=%v, want 2", serviceAccountTokens, err)
	}
}

func TestDisableServiceAccountRevokesTokensAtomically(t *testing.T) {
	pool, ctx := migrationTestPool(t)
	if err := Migrate(ctx, pool); err != nil {
		t.Fatal(err)
	}
	organizationID, accountID := uuid.New(), uuid.New()
	if _, err := pool.Exec(ctx, `INSERT INTO organizations(id,name,slug) VALUES($1,'Disable account',$2)`, organizationID, "disable-account-"+organizationID.String()); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO service_accounts(id,organization_id,name,role) VALUES($1,$2,'automation','developer')`, accountID, organizationID); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO service_account_tokens(id,service_account_id,token_hash,expires_at) VALUES($1,$2,$3,now()+interval '1 day')`, uuid.New(), accountID, []byte("disable-token")); err != nil {
		t.Fatal(err)
	}
	if err := (&Store{Pool: pool}).DisableServiceAccount(ctx, organizationID, accountID); err != nil {
		t.Fatal(err)
	}
	var enabled bool
	var activeTokens int
	if err := pool.QueryRow(ctx, `SELECT enabled FROM service_accounts WHERE id=$1`, accountID).Scan(&enabled); err != nil {
		t.Fatal(err)
	}
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM service_account_tokens WHERE service_account_id=$1 AND revoked_at IS NULL`, accountID).Scan(&activeTokens); err != nil {
		t.Fatal(err)
	}
	if enabled || activeTokens != 0 {
		t.Fatalf("disabled account enabled=%t active_tokens=%d", enabled, activeTokens)
	}
}

func TestPruneExpiredCredentialsBoundsEachTable(t *testing.T) {
	pool, ctx := migrationTestPool(t)
	if err := Migrate(ctx, pool); err != nil {
		t.Fatal(err)
	}
	userID := uuid.New()
	if _, err := pool.Exec(ctx, `INSERT INTO users(id,email,password_hash) VALUES($1,$2,'unused')`, userID, userID.String()+"@example.test"); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO sessions(id,user_id,token_hash,expires_at)
		SELECT md5(item::text)::uuid,$1,decode(md5('expired-session-'||item::text),'hex'),now()-interval '31 days'
		FROM generate_series(1,$2::int) item`, userID, maxCredentialPruneRowsPerTable+1); err != nil {
		t.Fatal(err)
	}

	db := &Store{Pool: pool}
	first, err := db.PruneExpiredCredentials(ctx, DefaultCredentialRetention)
	if err != nil {
		t.Fatal(err)
	}
	if first.Sessions != maxCredentialPruneRowsPerTable || first.Total() != maxCredentialPruneRowsPerTable {
		t.Fatalf("first batch=%+v, want %d sessions", first, maxCredentialPruneRowsPerTable)
	}
	second, err := db.PruneExpiredCredentials(ctx, DefaultCredentialRetention)
	if err != nil {
		t.Fatal(err)
	}
	if second.Sessions != 1 || second.Total() != 1 {
		t.Fatalf("second batch=%+v, want one session", second)
	}
}
