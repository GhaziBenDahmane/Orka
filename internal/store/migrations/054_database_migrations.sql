CREATE TABLE database_migrations (
    id uuid PRIMARY KEY,
    database_instance_id uuid NOT NULL REFERENCES database_instances(id) ON DELETE CASCADE,
    source_kind text NOT NULL DEFAULT 'dokploy',
    source_id text NOT NULL,
    source_engine text NOT NULL,
    source_version text NOT NULL,
    source_host text NOT NULL,
    encrypted_source_config text NOT NULL,
    status text NOT NULL DEFAULT 'queued' CHECK (status IN ('queued', 'running', 'succeeded', 'failed', 'cancelled')),
    size_bytes bigint,
    sha256 text NOT NULL DEFAULT '',
    output text NOT NULL DEFAULT '',
    error text NOT NULL DEFAULT '',
    created_at timestamptz NOT NULL DEFAULT now(),
    started_at timestamptz,
    finished_at timestamptz
);

CREATE UNIQUE INDEX database_migrations_active_idx
    ON database_migrations(database_instance_id)
    WHERE status IN ('queued', 'running');

CREATE INDEX database_migrations_database_created_idx
    ON database_migrations(database_instance_id, created_at DESC);
