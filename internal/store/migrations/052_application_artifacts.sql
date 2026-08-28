ALTER TABLE application_sources
    ADD COLUMN source_type text NOT NULL DEFAULT 'git';

ALTER TABLE application_sources
    ADD CONSTRAINT application_sources_source_type_check
    CHECK (source_type IN ('git', 'drop'));

CREATE TABLE application_artifacts (
    compose_service_id uuid PRIMARY KEY REFERENCES compose_services(id) ON DELETE CASCADE,
    encrypted_archive text NOT NULL,
    filename text NOT NULL,
    sha256 text NOT NULL CHECK (sha256 ~ '^[a-f0-9]{64}$'),
    compressed_size bigint NOT NULL CHECK (compressed_size > 0 AND compressed_size <= 26214400),
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now()
);
