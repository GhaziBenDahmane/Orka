CREATE TABLE application_sources (
    compose_service_id uuid PRIMARY KEY REFERENCES compose_services(id) ON DELETE CASCADE,
    repository_url text NOT NULL,
    git_ref text NOT NULL DEFAULT 'main',
    context_directory text NOT NULL DEFAULT '.',
    dockerfile text NOT NULL DEFAULT 'Dockerfile',
    target_service text NOT NULL,
    registry_image text NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now()
);
