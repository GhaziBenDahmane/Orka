ALTER TABLE volume_restores
    ADD COLUMN target_storage_node_id text NOT NULL DEFAULT '',
    ADD COLUMN offline boolean NOT NULL DEFAULT false;

ALTER TABLE volume_restores
    ADD CONSTRAINT volume_restores_target_storage_node_check
    CHECK (target_storage_node_id = '' OR target_storage_node_id ~ '^[a-z0-9]{1,64}$');
