ALTER TABLE template_instances
    ADD COLUMN encrypted_overrides text NOT NULL DEFAULT '';
