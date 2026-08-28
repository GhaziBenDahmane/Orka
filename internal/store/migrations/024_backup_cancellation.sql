ALTER TABLE database_restores DROP CONSTRAINT database_restores_status_check;
ALTER TABLE database_restores ADD CONSTRAINT database_restores_status_check
    CHECK (status IN ('queued','running','succeeded','failed','cancelled'));

ALTER TABLE database_backups DROP CONSTRAINT database_backups_status_check;
ALTER TABLE database_backups ADD CONSTRAINT database_backups_status_check
    CHECK (status IN ('queued','running','succeeded','failed','cancelled'));
