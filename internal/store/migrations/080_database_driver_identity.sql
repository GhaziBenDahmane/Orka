ALTER TABLE database_instances
    ADD COLUMN driver_source text NOT NULL DEFAULT 'unbound'
        CHECK (driver_source IN ('built-in', 'external', 'unbound')),
    ADD COLUMN driver_artifact_digest text NOT NULL DEFAULT ''
        CHECK (driver_artifact_digest = '' OR driver_artifact_digest ~ '^sha256:[a-f0-9]{64}$');

UPDATE database_instances
SET driver_source = 'built-in'
WHERE engine IN ('postgres', 'mysql', 'mariadb', 'mongo', 'redis', 'valkey', 'libsql', 'clickhouse', 'qdrant', 'meilisearch');

ALTER TABLE database_instances
    ADD CONSTRAINT database_driver_identity_consistent CHECK (
        (driver_source = 'built-in' AND driver_artifact_digest = '') OR
        (driver_source = 'external' AND driver_artifact_digest ~ '^sha256:[a-f0-9]{64}$') OR
        (driver_source = 'unbound' AND driver_artifact_digest = '')
    );
