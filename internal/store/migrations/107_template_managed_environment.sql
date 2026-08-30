ALTER TABLE template_instances
    ADD COLUMN managed_environment_keys text[] NOT NULL DEFAULT '{}';
