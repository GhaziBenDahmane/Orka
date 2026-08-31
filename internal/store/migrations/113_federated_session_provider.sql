ALTER TABLE sessions
    ADD COLUMN oidc_provider_id uuid REFERENCES oidc_providers(id) ON DELETE CASCADE,
    ADD COLUMN saml_provider_id uuid REFERENCES saml_providers(id) ON DELETE CASCADE;

-- Existing federated sessions predate provider provenance and cannot be
-- revoked safely when a provider's trust configuration changes.
DELETE FROM sessions WHERE auth_method IN ('oidc', 'saml');

ALTER TABLE sessions DROP CONSTRAINT sessions_auth_scope_check;
ALTER TABLE sessions ADD CONSTRAINT sessions_auth_scope_check CHECK (
    (auth_method = 'local' AND organization_id IS NULL AND oidc_provider_id IS NULL AND saml_provider_id IS NULL)
    OR (auth_method = 'oidc' AND organization_id IS NOT NULL AND oidc_provider_id IS NOT NULL AND saml_provider_id IS NULL)
    OR (auth_method = 'saml' AND organization_id IS NOT NULL AND oidc_provider_id IS NULL AND saml_provider_id IS NOT NULL)
);

CREATE INDEX sessions_oidc_provider_idx ON sessions(oidc_provider_id) WHERE oidc_provider_id IS NOT NULL;
CREATE INDEX sessions_saml_provider_idx ON sessions(saml_provider_id) WHERE saml_provider_id IS NOT NULL;
