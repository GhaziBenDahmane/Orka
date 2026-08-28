ALTER TABLE database_backups
    ADD COLUMN encrypted boolean NOT NULL DEFAULT false,
    ADD COLUMN plaintext_sha256 text NOT NULL DEFAULT '';
