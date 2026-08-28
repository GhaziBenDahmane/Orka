CREATE TABLE saml_providers (
    id uuid PRIMARY KEY,
    organization_id uuid NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    name text NOT NULL,
    idp_metadata text NOT NULL,
    certificate_pem text NOT NULL,
    encrypted_private_key text NOT NULL,
    domains text[] NOT NULL DEFAULT '{}',
    email_attribute text NOT NULL DEFAULT 'email',
    name_attribute text NOT NULL DEFAULT 'name',
    default_role text NOT NULL DEFAULT 'developer' CHECK (default_role IN ('admin','developer','viewer')),
    allow_idp_initiated boolean NOT NULL DEFAULT false,
    enabled boolean NOT NULL DEFAULT true,
    created_at timestamptz NOT NULL DEFAULT now(),
    UNIQUE (organization_id,name)
);

CREATE TABLE saml_states (
    token_hash bytea PRIMARY KEY,
    provider_id uuid NOT NULL REFERENCES saml_providers(id) ON DELETE CASCADE,
    request_id text NOT NULL,
    expires_at timestamptz NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX saml_states_expires_idx ON saml_states(expires_at);

CREATE TABLE saml_assertions (
    provider_id uuid NOT NULL REFERENCES saml_providers(id) ON DELETE CASCADE,
    assertion_id text NOT NULL,
    expires_at timestamptz NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (provider_id,assertion_id)
);
CREATE INDEX saml_assertions_expires_idx ON saml_assertions(expires_at);

CREATE TABLE saml_external_identities (
    provider_id uuid NOT NULL REFERENCES saml_providers(id) ON DELETE CASCADE,
    subject text NOT NULL,
    user_id uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    created_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (provider_id,subject)
);
