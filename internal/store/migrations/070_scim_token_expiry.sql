ALTER TABLE scim_tokens
    ADD COLUMN expires_at timestamptz NOT NULL DEFAULT (now() + interval '90 days');

CREATE INDEX scim_tokens_active_expiry_idx
    ON scim_tokens(organization_id,expires_at)
    WHERE revoked_at IS NULL;
