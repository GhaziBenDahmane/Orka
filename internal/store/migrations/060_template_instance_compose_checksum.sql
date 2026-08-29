ALTER TABLE template_instances
    ADD COLUMN applied_compose_checksum text NOT NULL DEFAULT '';
