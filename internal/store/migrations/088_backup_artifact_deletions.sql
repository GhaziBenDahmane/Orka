CREATE TABLE backup_artifact_deletions (
    id uuid PRIMARY KEY,
    destination_id uuid NOT NULL REFERENCES backup_destinations(id) ON DELETE RESTRICT,
    object_key text NOT NULL CHECK (object_key <> '' AND length(object_key) <= 2048),
    source_kind text NOT NULL CHECK (source_kind IN ('database','volume')),
    source_id uuid NOT NULL,
    attempts integer NOT NULL DEFAULT 0 CHECK (attempts >= 0),
    next_attempt_at timestamptz NOT NULL DEFAULT now(),
    last_error text NOT NULL DEFAULT '',
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    UNIQUE (destination_id,object_key)
);

CREATE INDEX backup_artifact_deletions_due_idx
    ON backup_artifact_deletions(next_attempt_at,id);

ALTER TABLE volume_restores
    DROP CONSTRAINT volume_restores_volume_backup_id_fkey,
    ADD CONSTRAINT volume_restores_volume_backup_id_fkey
        FOREIGN KEY (volume_backup_id) REFERENCES volume_backups(id) ON DELETE CASCADE;
