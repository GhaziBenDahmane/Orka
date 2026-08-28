CREATE TABLE oidc_providers (
    id uuid PRIMARY KEY,
    organization_id uuid NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    name text NOT NULL,
    issuer text NOT NULL,
    client_id text NOT NULL,
    encrypted_client_secret text NOT NULL,
    domains text[] NOT NULL DEFAULT '{}',
    scopes text[] NOT NULL DEFAULT '{openid,profile,email}',
    default_role text NOT NULL DEFAULT 'developer' CHECK (default_role IN ('admin','developer','viewer')),
    enabled boolean NOT NULL DEFAULT true,
    created_at timestamptz NOT NULL DEFAULT now(),
    UNIQUE (organization_id, name)
);

CREATE TABLE oidc_states (
    token_hash bytea PRIMARY KEY,
    provider_id uuid NOT NULL REFERENCES oidc_providers(id) ON DELETE CASCADE,
    code_verifier text NOT NULL,
    expires_at timestamptz NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE external_identities (
    provider_id uuid NOT NULL REFERENCES oidc_providers(id) ON DELETE CASCADE,
    subject text NOT NULL,
    user_id uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    created_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (provider_id, subject)
);
