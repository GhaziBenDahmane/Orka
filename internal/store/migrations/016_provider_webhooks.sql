CREATE TABLE webhook_integrations (
    id uuid PRIMARY KEY,
    compose_service_id uuid NOT NULL REFERENCES compose_services(id) ON DELETE CASCADE,
    name text NOT NULL,
    provider text NOT NULL CHECK (provider IN ('github','gitlab','gitea','bitbucket')),
    branch text NOT NULL,
    encrypted_secret text NOT NULL,
    enabled boolean NOT NULL DEFAULT true,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    UNIQUE (compose_service_id,name)
);

CREATE TABLE webhook_deliveries (
    integration_id uuid NOT NULL REFERENCES webhook_integrations(id) ON DELETE CASCADE,
    delivery_id text NOT NULL,
    received_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (integration_id,delivery_id)
);
CREATE INDEX webhook_deliveries_received_idx ON webhook_deliveries(received_at);
