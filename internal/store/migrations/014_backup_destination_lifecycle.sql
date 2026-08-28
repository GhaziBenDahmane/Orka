ALTER TABLE database_backups
    DROP CONSTRAINT database_backups_destination_id_fkey,
    ADD CONSTRAINT database_backups_destination_id_fkey
        FOREIGN KEY (destination_id)
        REFERENCES backup_destinations(id)
        DEFERRABLE INITIALLY DEFERRED;
