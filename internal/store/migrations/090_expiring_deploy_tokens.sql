ALTER TABLE deploy_tokens
    ADD COLUMN expires_at timestamptz,
    ADD COLUMN last_used_at timestamptz;

UPDATE deploy_tokens SET expires_at=now()+interval '90 days' WHERE expires_at IS NULL;

ALTER TABLE deploy_tokens ALTER COLUMN expires_at SET NOT NULL;

CREATE INDEX deploy_tokens_service_created_idx
    ON deploy_tokens(compose_service_id,created_at DESC);

CREATE INDEX deploy_tokens_active_expiry_idx
    ON deploy_tokens(expires_at)
    WHERE revoked_at IS NULL;
