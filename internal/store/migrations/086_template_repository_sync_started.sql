ALTER TABLE template_repositories
    ADD COLUMN sync_started_at timestamptz,
    ADD COLUMN sync_attempt_id uuid;

UPDATE template_repositories
SET sync_started_at=updated_at
WHERE last_sync_status='running';

CREATE INDEX template_repositories_sync_started_idx
    ON template_repositories(sync_started_at)
    WHERE last_sync_status='running';
