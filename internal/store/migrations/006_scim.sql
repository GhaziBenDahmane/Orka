CREATE TABLE scim_tokens (
    id uuid PRIMARY KEY,
    organization_id uuid NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    name text NOT NULL,
    token_hash bytea NOT NULL UNIQUE,
    default_role text NOT NULL DEFAULT 'developer' CHECK (default_role IN ('admin','developer','viewer')),
    created_at timestamptz NOT NULL DEFAULT now(),
    revoked_at timestamptz
);
