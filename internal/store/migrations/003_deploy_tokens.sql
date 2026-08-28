CREATE TABLE deploy_tokens (
    id uuid PRIMARY KEY,
    compose_service_id uuid NOT NULL REFERENCES compose_services(id) ON DELETE CASCADE,
    token_hash bytea NOT NULL UNIQUE,
    name text NOT NULL,
    created_by uuid REFERENCES users(id) ON DELETE SET NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    revoked_at timestamptz
);
