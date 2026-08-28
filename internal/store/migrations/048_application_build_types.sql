ALTER TABLE application_sources
    ADD COLUMN build_type text NOT NULL DEFAULT 'dockerfile',
    ADD COLUMN output_directory text NOT NULL DEFAULT '';

ALTER TABLE application_sources
    ADD CONSTRAINT application_sources_build_type_check
    CHECK (build_type IN ('dockerfile', 'static'));
