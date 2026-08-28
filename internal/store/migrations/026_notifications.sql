CREATE TABLE notification_endpoints (
    id uuid PRIMARY KEY,
    organization_id uuid NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    name text NOT NULL,
    kind text NOT NULL CHECK (kind IN ('webhook','slack')),
    encrypted_url text NOT NULL,
    encrypted_secret text NOT NULL,
    events text[] NOT NULL,
    enabled boolean NOT NULL DEFAULT true,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    UNIQUE (organization_id, name)
);

CREATE TABLE notification_deliveries (
    id uuid PRIMARY KEY,
    endpoint_id uuid NOT NULL REFERENCES notification_endpoints(id) ON DELETE CASCADE,
    event_type text NOT NULL,
    resource_type text NOT NULL,
    resource_id text NOT NULL,
    payload jsonb NOT NULL,
    status text NOT NULL DEFAULT 'pending' CHECK (status IN ('pending','running','succeeded','failed')),
    response_code integer,
    last_error text NOT NULL DEFAULT '',
    created_at timestamptz NOT NULL DEFAULT now(),
    started_at timestamptz,
    finished_at timestamptz,
    UNIQUE (endpoint_id, event_type, resource_type, resource_id)
);

CREATE INDEX notification_deliveries_endpoint_created_idx ON notification_deliveries(endpoint_id, created_at DESC);
