CREATE TABLE custom_tls_certificates (
    id uuid PRIMARY KEY,
    organization_id uuid NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    name text NOT NULL CHECK (char_length(name) BETWEEN 1 AND 100 AND btrim(name) = name),
    encrypted_certificate text NOT NULL,
    encrypted_private_key text NOT NULL,
    fingerprint text NOT NULL CHECK (fingerprint ~ '^sha256:[0-9a-f]{64}$'),
    common_name text NOT NULL DEFAULT '',
    dns_names text[] NOT NULL CHECK (cardinality(dns_names) BETWEEN 1 AND 100),
    not_before timestamptz NOT NULL,
    not_after timestamptz NOT NULL CHECK (not_after > not_before),
    revision bigint NOT NULL DEFAULT 1 CHECK (revision > 0),
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    UNIQUE (organization_id, name),
    UNIQUE (organization_id, fingerprint)
);

ALTER TABLE routes ADD COLUMN custom_certificate_id uuid REFERENCES custom_tls_certificates(id) ON DELETE RESTRICT;
ALTER TABLE routes ADD CONSTRAINT routes_custom_certificate_tls_check
    CHECK (custom_certificate_id IS NULL OR (tls AND certificate_resolver = ''));
CREATE INDEX routes_custom_certificate_idx ON routes(custom_certificate_id) WHERE custom_certificate_id IS NOT NULL;

CREATE TABLE edge_certificate_targets (
    target_key text PRIMARY KEY CHECK (target_key = 'local' OR target_key ~ '^[0-9a-f-]{36}$'),
    cluster_id uuid UNIQUE REFERENCES clusters(id) ON DELETE CASCADE,
    generation bigint NOT NULL DEFAULT 1 CHECK (generation > 0),
    applied_generation bigint NOT NULL DEFAULT 0 CHECK (applied_generation >= 0),
    status text NOT NULL DEFAULT 'pending' CHECK (status IN ('pending','ready','error')),
    last_error text NOT NULL DEFAULT '',
    updated_at timestamptz NOT NULL DEFAULT now(),
    CHECK ((target_key = 'local') = (cluster_id IS NULL))
);

ALTER TABLE cluster_commands DROP CONSTRAINT cluster_commands_kind_check;
ALTER TABLE cluster_commands ADD CONSTRAINT cluster_commands_kind_check
    CHECK (kind IN ('swarm.deploy','swarm.remove','swarm.logs','swarm.nodes','swarm.status','swarm.storage-node','swarm.volume-node','swarm.volume-artifact','swarm.prune-volumes','swarm.exec','swarm.edge-certificates','container.run','database.utility','agent.upgrade','database.transfer'));
