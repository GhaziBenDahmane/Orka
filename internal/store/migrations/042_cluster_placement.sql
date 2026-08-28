ALTER TABLE environments
    ADD COLUMN placement_selector jsonb NOT NULL DEFAULT '{}'::jsonb,
    ADD COLUMN minimum_nodes integer NOT NULL DEFAULT 0 CHECK (minimum_nodes BETWEEN 0 AND 10000);

CREATE INDEX clusters_active_labels_idx ON clusters USING gin(labels) WHERE state='active';

ALTER TABLE clusters
    ADD COLUMN maintenance_starts_at timestamptz,
    ADD COLUMN maintenance_ends_at timestamptz,
    ADD CONSTRAINT clusters_maintenance_window_check CHECK (
        (maintenance_starts_at IS NULL AND maintenance_ends_at IS NULL) OR
        (maintenance_starts_at IS NOT NULL AND maintenance_ends_at > maintenance_starts_at)
    );
