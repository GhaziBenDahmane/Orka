ALTER TABLE database_instances
    ADD COLUMN management_kind text NOT NULL DEFAULT 'managed',
    ADD COLUMN connection_service_name text NOT NULL DEFAULT '';

ALTER TABLE database_instances
    ADD CONSTRAINT database_instances_management_kind_check
    CHECK (management_kind IN ('managed','compose'));

ALTER TABLE database_instances
    ADD CONSTRAINT database_instances_connection_service_check
    CHECK (
        (management_kind = 'managed' AND connection_service_name = '') OR
        (management_kind = 'compose' AND connection_service_name ~ '^[a-z0-9][a-z0-9_-]{0,62}$')
    );

CREATE INDEX database_instances_compose_targets_idx
    ON database_instances(compose_service_id, connection_service_name)
    WHERE management_kind = 'compose';
