CREATE TABLE template_instances (
    compose_service_id uuid PRIMARY KEY REFERENCES compose_services(id) ON DELETE CASCADE,
    template_id uuid REFERENCES templates(id) ON DELETE SET NULL,
    template_key text NOT NULL,
    template_version text NOT NULL,
    template_checksum text NOT NULL,
    base_domain text NOT NULL DEFAULT '',
    encrypted_variables text NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX template_instances_key_version_idx ON template_instances(template_key,template_version);
