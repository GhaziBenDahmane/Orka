ALTER TABLE database_instances
    ADD COLUMN deletion_requested_at timestamptz;

CREATE INDEX database_instances_deleting_idx
    ON database_instances(deletion_requested_at)
    WHERE deletion_requested_at IS NOT NULL;
