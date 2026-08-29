ALTER TABLE sessions
    ADD COLUMN organization_id uuid REFERENCES organizations(id) ON DELETE CASCADE;

-- Sessions created before organization scoping cannot prove which tenant's
-- identity provider authenticated them. Revoke them instead of guessing.
DELETE FROM sessions WHERE auth_method IN ('oidc', 'saml');

ALTER TABLE sessions
    ADD CONSTRAINT sessions_auth_scope_check CHECK (
        (auth_method = 'local' AND organization_id IS NULL)
        OR (auth_method IN ('oidc', 'saml') AND organization_id IS NOT NULL)
    );

CREATE INDEX sessions_organization_idx ON sessions(organization_id) WHERE organization_id IS NOT NULL;
