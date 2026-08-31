ALTER TABLE oidc_providers ADD COLUMN revision bigint NOT NULL DEFAULT 1 CHECK (revision > 0);
ALTER TABLE saml_providers ADD COLUMN revision bigint NOT NULL DEFAULT 1 CHECK (revision > 0);

-- Pending flows created before revision binding cannot prove which provider
-- configuration initiated them.
DELETE FROM oidc_states;
DELETE FROM saml_states;

ALTER TABLE oidc_states ADD COLUMN provider_revision bigint NOT NULL;
ALTER TABLE saml_states ADD COLUMN provider_revision bigint NOT NULL;
