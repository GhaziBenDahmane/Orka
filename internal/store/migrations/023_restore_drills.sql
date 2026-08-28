ALTER TABLE backup_policies
    ADD COLUMN verify_restore boolean NOT NULL DEFAULT false;

ALTER TABLE database_restores
    ADD COLUMN kind text NOT NULL DEFAULT 'manual'
        CHECK (kind IN ('manual','drill'));

CREATE UNIQUE INDEX database_restores_one_drill_per_backup
    ON database_restores(database_backup_id)
    WHERE kind='drill';
