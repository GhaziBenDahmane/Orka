ALTER TABLE commit_status_deliveries
    ADD COLUMN provider text NOT NULL DEFAULT '',
    ADD COLUMN repository_url text NOT NULL DEFAULT '',
    ADD COLUMN status_context text NOT NULL DEFAULT '',
    ADD COLUMN credential_server text NOT NULL DEFAULT '',
    ADD COLUMN credential_username text NOT NULL DEFAULT '',
    ADD COLUMN encrypted_credential text NOT NULL DEFAULT '';
