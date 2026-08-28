CREATE TABLE service_accounts (
    id uuid PRIMARY KEY,
    organization_id uuid NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    name text NOT NULL,
    role text NOT NULL CHECK (role IN ('admin','developer','viewer')),
    enabled boolean NOT NULL DEFAULT true,
    created_by uuid REFERENCES users(id) ON DELETE SET NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    UNIQUE (organization_id,name)
);

CREATE TABLE service_account_tokens (
    id uuid PRIMARY KEY,
    service_account_id uuid NOT NULL REFERENCES service_accounts(id) ON DELETE CASCADE,
    token_hash bytea NOT NULL UNIQUE,
    expires_at timestamptz NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    last_used_at timestamptz,
    revoked_at timestamptz
);
CREATE INDEX service_account_tokens_active_idx ON service_account_tokens(service_account_id,expires_at)
    WHERE revoked_at IS NULL;

ALTER TABLE audit_events
    ADD COLUMN actor_service_account_id uuid REFERENCES service_accounts(id) ON DELETE SET NULL;
