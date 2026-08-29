ALTER TABLE template_repositories
    ADD COLUMN sync_interval_seconds integer NOT NULL DEFAULT 0,
    ADD COLUMN next_sync_at timestamptz,
    ADD CONSTRAINT template_repositories_sync_interval_check
        CHECK (sync_interval_seconds = 0 OR sync_interval_seconds BETWEEN 300 AND 604800);

CREATE INDEX template_repositories_due_sync_idx
    ON template_repositories(next_sync_at)
    WHERE enabled AND sync_interval_seconds > 0;
