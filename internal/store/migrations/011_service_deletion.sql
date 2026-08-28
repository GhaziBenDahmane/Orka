ALTER TABLE compose_services ADD COLUMN deletion_requested_at timestamptz;

ALTER TABLE database_restores
    DROP CONSTRAINT database_restores_database_backup_id_fkey;
ALTER TABLE database_restores
    ADD CONSTRAINT database_restores_database_backup_id_fkey
    FOREIGN KEY (database_backup_id) REFERENCES database_backups(id) ON DELETE CASCADE;
