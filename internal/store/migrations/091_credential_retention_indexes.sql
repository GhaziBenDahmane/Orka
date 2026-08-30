CREATE INDEX service_account_tokens_terminal_idx
    ON service_account_tokens ((COALESCE(revoked_at,expires_at)));

CREATE INDEX scim_tokens_terminal_idx
    ON scim_tokens ((COALESCE(revoked_at,expires_at)));

CREATE INDEX deploy_tokens_terminal_idx
    ON deploy_tokens ((COALESCE(revoked_at,expires_at)));

CREATE INDEX organization_invitations_terminal_idx
    ON organization_invitations ((COALESCE(accepted_at,revoked_at,expires_at)));

CREATE INDEX cluster_enrollment_tokens_terminal_idx
    ON cluster_enrollment_tokens ((COALESCE(used_at,expires_at)));

CREATE INDEX oidc_states_expires_idx ON oidc_states(expires_at);
