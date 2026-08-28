ALTER TABLE sessions
    ADD COLUMN auth_method text NOT NULL DEFAULT 'local'
        CHECK (auth_method IN ('local','oidc','saml')),
    ADD COLUMN user_agent text NOT NULL DEFAULT '',
    ADD COLUMN ip_address text NOT NULL DEFAULT '';

CREATE TABLE organization_auth_settings (
    organization_id uuid PRIMARY KEY REFERENCES organizations(id) ON DELETE CASCADE,
    require_sso boolean NOT NULL DEFAULT false,
    updated_at timestamptz NOT NULL DEFAULT now()
);
