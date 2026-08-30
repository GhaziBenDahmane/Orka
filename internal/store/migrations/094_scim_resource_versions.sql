ALTER TABLE scim_user_defaults
    ADD COLUMN created_at timestamptz NOT NULL DEFAULT now(),
    ADD COLUMN updated_at timestamptz NOT NULL DEFAULT now(),
    ADD COLUMN revision bigint NOT NULL DEFAULT 1 CHECK (revision > 0);

ALTER TABLE scim_groups
    ADD COLUMN revision bigint NOT NULL DEFAULT 1 CHECK (revision > 0);
