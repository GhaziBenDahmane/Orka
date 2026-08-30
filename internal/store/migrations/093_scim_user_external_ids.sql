ALTER TABLE scim_user_defaults
    ADD COLUMN external_id text;

CREATE UNIQUE INDEX scim_user_defaults_external_id_idx
    ON scim_user_defaults(organization_id,external_id)
    WHERE external_id IS NOT NULL;
