ALTER TABLE application_sources DROP CONSTRAINT application_sources_build_type_check;
ALTER TABLE application_sources
    ADD CONSTRAINT application_sources_build_type_check
    CHECK (build_type IN ('dockerfile', 'static', 'nixpacks', 'railpack'));
