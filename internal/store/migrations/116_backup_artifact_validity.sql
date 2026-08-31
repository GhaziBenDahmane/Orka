ALTER TABLE database_backups
    ADD COLUMN artifact_valid boolean GENERATED ALWAYS AS (
        COALESCE(
            status = 'succeeded'
            AND size_bytes > 0
            AND sha256 ~ '^[a-f0-9]{64}$'
            AND finished_at IS NOT NULL
            AND (
                NOT encrypted
                OR (
                    plaintext_sha256 ~ '^[a-f0-9]{64}$'
                    AND encrypted_data_key <> ''
                )
            )
            AND (
                (destination_id IS NULL AND path <> '')
                OR (
                    destination_id IS NOT NULL
                    AND object_key <> ''
                    AND encrypted
                )
            ),
            false
        )
    ) STORED;

CREATE INDEX database_backups_valid_instance_finished_idx
    ON database_backups(database_instance_id, finished_at DESC)
    WHERE artifact_valid;

ALTER TABLE volume_backups
    ADD COLUMN artifact_valid boolean GENERATED ALWAYS AS (
        COALESCE(
            status = 'succeeded'
            AND size_bytes > 0
            AND sha256 ~ '^[a-f0-9]{64}$'
            AND plaintext_sha256 ~ '^[a-f0-9]{64}$'
            AND encrypted_data_key <> ''
            AND object_key <> ''
            AND finished_at IS NOT NULL,
            false
        )
    ) STORED;

CREATE INDEX volume_backups_valid_service_finished_idx
    ON volume_backups(compose_service_id, volume_name, finished_at DESC)
    WHERE artifact_valid;
