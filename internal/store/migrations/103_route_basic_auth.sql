CREATE TABLE route_basic_auth_users (
    id uuid PRIMARY KEY,
    compose_service_id uuid NOT NULL REFERENCES compose_services(id) ON DELETE CASCADE,
    username text NOT NULL,
    password_hash text NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    UNIQUE (compose_service_id, username)
);

CREATE INDEX route_basic_auth_users_service_idx ON route_basic_auth_users(compose_service_id, username);
