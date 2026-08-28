CREATE TABLE database_backups (
    id uuid PRIMARY KEY,
    database_instance_id uuid NOT NULL REFERENCES database_instances(id) ON DELETE CASCADE,
    status text NOT NULL CHECK (status IN ('queued','running','succeeded','failed')),
    format text NOT NULL,
    path text NOT NULL DEFAULT '',
    size_bytes bigint,
    sha256 text NOT NULL DEFAULT '',
    error text NOT NULL DEFAULT '',
    actor_user_id uuid REFERENCES users(id) ON DELETE SET NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    started_at timestamptz,
    finished_at timestamptz
);
CREATE INDEX database_backups_instance_created_idx ON database_backups(database_instance_id, created_at DESC);
