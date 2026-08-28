ALTER TABLE jobs DROP CONSTRAINT jobs_status_check;
ALTER TABLE jobs ADD CONSTRAINT jobs_status_check
    CHECK (status IN ('pending','running','succeeded','failed','cancelled'));

ALTER TABLE jobs ADD COLUMN cancel_requested_at timestamptz;

ALTER TABLE database_backups DROP CONSTRAINT database_backups_status_check;
ALTER TABLE database_backups ADD CONSTRAINT database_backups_status_check
    CHECK (status IN ('queued','running','succeeded','failed','cancelled'));

ALTER TABLE database_restores DROP CONSTRAINT database_restores_status_check;
ALTER TABLE database_restores ADD CONSTRAINT database_restores_status_check
    CHECK (status IN ('queued','running','succeeded','failed','cancelled'));

CREATE INDEX jobs_running_heartbeat_idx ON jobs(locked_at)
    WHERE status = 'running';
