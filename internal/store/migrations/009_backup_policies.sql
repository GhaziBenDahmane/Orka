CREATE TABLE backup_policies (
    id uuid PRIMARY KEY,
    database_instance_id uuid NOT NULL UNIQUE REFERENCES database_instances(id) ON DELETE CASCADE,
    interval_seconds integer NOT NULL CHECK (interval_seconds BETWEEN 900 AND 2678400),
    retention_count integer NOT NULL CHECK (retention_count BETWEEN 1 AND 100),
    enabled boolean NOT NULL DEFAULT true,
    next_run_at timestamptz NOT NULL,
    last_run_at timestamptz,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX backup_policies_due_idx ON backup_policies(next_run_at)
    WHERE enabled;
