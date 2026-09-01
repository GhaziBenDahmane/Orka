ALTER TABLE edge_certificate_targets
    ADD COLUMN affected_organization_ids uuid[] NOT NULL DEFAULT '{}'::uuid[];
