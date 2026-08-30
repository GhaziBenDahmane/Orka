CREATE TABLE managed_networks (
    id uuid PRIMARY KEY,
    organization_id uuid NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    cluster_id uuid REFERENCES clusters(id) ON DELETE RESTRICT,
    name text NOT NULL CHECK (char_length(name) BETWEEN 1 AND 63 AND btrim(name) = name),
    driver text NOT NULL DEFAULT 'overlay' CHECK (driver IN ('overlay','bridge')),
    internal boolean NOT NULL DEFAULT false,
    attachable boolean NOT NULL DEFAULT true,
    enable_ipv4 boolean NOT NULL DEFAULT true,
    enable_ipv6 boolean NOT NULL DEFAULT false,
    mtu integer CHECK (mtu IS NULL OR mtu BETWEEN 576 AND 65535),
    ipam jsonb NOT NULL DEFAULT '[]'::jsonb CHECK (jsonb_typeof(ipam) = 'array'),
    docker_id text NOT NULL DEFAULT '',
    status text NOT NULL DEFAULT 'provisioning' CHECK (status IN ('provisioning','ready','deleting','error')),
    last_error text NOT NULL DEFAULT '',
    deletion_requested_at timestamptz,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    CHECK (enable_ipv4 OR enable_ipv6),
    UNIQUE NULLS NOT DISTINCT (organization_id, cluster_id, name)
);

CREATE INDEX managed_networks_cluster_idx ON managed_networks(cluster_id);

CREATE TABLE compose_service_networks (
    compose_service_id uuid NOT NULL REFERENCES compose_services(id) ON DELETE CASCADE,
    network_id uuid NOT NULL REFERENCES managed_networks(id) ON DELETE RESTRICT,
    service_names text[] NOT NULL DEFAULT '{}' CHECK (cardinality(service_names) <= 100),
    created_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (compose_service_id, network_id)
);

CREATE INDEX compose_service_networks_network_idx ON compose_service_networks(network_id);
