ALTER TABLE database_backups
    ADD COLUMN encrypted_data_key text NOT NULL DEFAULT '';
