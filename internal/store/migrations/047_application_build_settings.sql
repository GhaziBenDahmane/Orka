ALTER TABLE application_sources
    ADD COLUMN build_target text NOT NULL DEFAULT '',
    ADD COLUMN enable_submodules boolean NOT NULL DEFAULT false,
    ADD COLUMN encrypted_build_config text NOT NULL DEFAULT '';
