ALTER TABLE template_instances
    ADD COLUMN environment_ownership_recorded boolean NOT NULL DEFAULT false;
