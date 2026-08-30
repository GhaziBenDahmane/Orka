package store

import (
	"context"
	"errors"
	"time"
)

const (
	// DefaultCredentialRetention keeps terminal authentication records long
	// enough for incident investigation without retaining them indefinitely.
	DefaultCredentialRetention           = 30 * 24 * time.Hour
	minCredentialRetention               = 24 * time.Hour
	maxCredentialRetention               = 365 * 24 * time.Hour
	maxCredentialPruneRowsPerTable int64 = 10_000
)

// CredentialPruneResult reports how many terminal credential records were removed.
type CredentialPruneResult struct {
	Sessions                int64
	ServiceAccountTokens    int64
	SCIMTokens              int64
	DeployTokens            int64
	Invitations             int64
	ClusterEnrollmentTokens int64
	OIDCStates              int64
	SAMLStates              int64
	SAMLAssertions          int64
}

func (r CredentialPruneResult) Total() int64 {
	return r.Sessions + r.ServiceAccountTokens + r.SCIMTokens + r.DeployTokens +
		r.Invitations + r.ClusterEnrollmentTokens + r.OIDCStates + r.SAMLStates + r.SAMLAssertions
}

// PruneExpiredCredentials removes terminal credentials after the requested
// retention period. Short-lived login and replay state is removed immediately
// after expiry.
func (s *Store) PruneExpiredCredentials(ctx context.Context, retention time.Duration) (CredentialPruneResult, error) {
	var result CredentialPruneResult
	if retention < minCredentialRetention || retention > maxCredentialRetention {
		return result, errors.New("credential retention must be between 24 hours and 365 days")
	}

	tx, err := s.Pool.Begin(ctx)
	if err != nil {
		return result, err
	}
	defer tx.Rollback(ctx)

	retentionSeconds := int64(retention / time.Second)
	deletes := []struct {
		query string
		count *int64
		args  []any
	}{
		{`DELETE FROM sessions WHERE ctid IN (SELECT ctid FROM sessions WHERE expires_at < now()-make_interval(secs => $1) ORDER BY expires_at LIMIT $2)`, &result.Sessions, []any{retentionSeconds, maxCredentialPruneRowsPerTable}},
		{`DELETE FROM service_account_tokens WHERE ctid IN (SELECT ctid FROM service_account_tokens WHERE COALESCE(revoked_at,expires_at) < now()-make_interval(secs => $1) ORDER BY COALESCE(revoked_at,expires_at) LIMIT $2)`, &result.ServiceAccountTokens, []any{retentionSeconds, maxCredentialPruneRowsPerTable}},
		{`DELETE FROM scim_tokens WHERE ctid IN (SELECT ctid FROM scim_tokens WHERE COALESCE(revoked_at,expires_at) < now()-make_interval(secs => $1) ORDER BY COALESCE(revoked_at,expires_at) LIMIT $2)`, &result.SCIMTokens, []any{retentionSeconds, maxCredentialPruneRowsPerTable}},
		{`DELETE FROM deploy_tokens WHERE ctid IN (SELECT ctid FROM deploy_tokens WHERE COALESCE(revoked_at,expires_at) < now()-make_interval(secs => $1) ORDER BY COALESCE(revoked_at,expires_at) LIMIT $2)`, &result.DeployTokens, []any{retentionSeconds, maxCredentialPruneRowsPerTable}},
		{`DELETE FROM organization_invitations WHERE ctid IN (SELECT ctid FROM organization_invitations WHERE COALESCE(accepted_at,revoked_at,expires_at) < now()-make_interval(secs => $1) ORDER BY COALESCE(accepted_at,revoked_at,expires_at) LIMIT $2)`, &result.Invitations, []any{retentionSeconds, maxCredentialPruneRowsPerTable}},
		{`DELETE FROM cluster_enrollment_tokens WHERE ctid IN (SELECT ctid FROM cluster_enrollment_tokens WHERE COALESCE(used_at,expires_at) < now()-make_interval(secs => $1) ORDER BY COALESCE(used_at,expires_at) LIMIT $2)`, &result.ClusterEnrollmentTokens, []any{retentionSeconds, maxCredentialPruneRowsPerTable}},
		{`DELETE FROM oidc_states WHERE ctid IN (SELECT ctid FROM oidc_states WHERE expires_at < now() ORDER BY expires_at LIMIT $1)`, &result.OIDCStates, []any{maxCredentialPruneRowsPerTable}},
		{`DELETE FROM saml_states WHERE ctid IN (SELECT ctid FROM saml_states WHERE expires_at < now() ORDER BY expires_at LIMIT $1)`, &result.SAMLStates, []any{maxCredentialPruneRowsPerTable}},
		{`DELETE FROM saml_assertions WHERE ctid IN (SELECT ctid FROM saml_assertions WHERE expires_at < now() ORDER BY expires_at LIMIT $1)`, &result.SAMLAssertions, []any{maxCredentialPruneRowsPerTable}},
	}
	for _, deletion := range deletes {
		tag, execErr := tx.Exec(ctx, deletion.query, deletion.args...)
		if execErr != nil {
			return CredentialPruneResult{}, execErr
		}
		*deletion.count = tag.RowsAffected()
	}
	if err = tx.Commit(ctx); err != nil {
		return CredentialPruneResult{}, err
	}
	return result, nil
}
