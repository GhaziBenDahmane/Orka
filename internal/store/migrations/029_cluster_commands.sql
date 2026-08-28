CREATE TABLE cluster_commands (
    id uuid PRIMARY KEY,
    cluster_id uuid NOT NULL REFERENCES clusters(id) ON DELETE CASCADE,
    kind text NOT NULL CHECK (kind IN ('swarm.deploy','swarm.remove','swarm.logs','swarm.nodes')),
    encrypted_payload text NOT NULL,
    status text NOT NULL DEFAULT 'pending' CHECK (status IN ('pending','leased','succeeded','failed','cancelled')),
    attempts integer NOT NULL DEFAULT 0,
    max_attempts integer NOT NULL DEFAULT 5,
    run_after timestamptz NOT NULL DEFAULT now(),
    lease_id uuid,
    lease_expires_at timestamptz,
    output text NOT NULL DEFAULT '',
    last_error text NOT NULL DEFAULT '',
    created_at timestamptz NOT NULL DEFAULT now(),
    started_at timestamptz,
    finished_at timestamptz
);

CREATE INDEX cluster_commands_claim_idx ON cluster_commands(cluster_id,status,run_after,created_at);
