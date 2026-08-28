CREATE TABLE database_restores (
    id uuid PRIMARY KEY,
    database_backup_id uuid NOT NULL REFERENCES database_backups(id) ON DELETE RESTRICT,
    status text NOT NULL CHECK (status IN ('queued','running','succeeded','failed')),
    error text NOT NULL DEFAULT '',
    actor_user_id uuid REFERENCES users(id) ON DELETE SET NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    started_at timestamptz,
    finished_at timestamptz
);
