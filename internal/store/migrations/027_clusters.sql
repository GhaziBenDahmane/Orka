CREATE TABLE clusters (
    id uuid PRIMARY KEY,
    organization_id uuid NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    name text NOT NULL,
    slug text NOT NULL,
    state text NOT NULL DEFAULT 'pending' CHECK (state IN ('pending','active','draining','disabled')),
    labels jsonb NOT NULL DEFAULT '{}'::jsonb,
    agent_version text NOT NULL DEFAULT '',
    docker_version text NOT NULL DEFAULT '',
    certificate_serial text NOT NULL DEFAULT '',
    certificate_not_after timestamptz,
    last_seen_at timestamptz,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    UNIQUE (organization_id, slug)
);

CREATE TABLE cluster_enrollment_tokens (
    id uuid PRIMARY KEY,
    cluster_id uuid NOT NULL REFERENCES clusters(id) ON DELETE CASCADE,
    token_hash bytea NOT NULL UNIQUE,
    expires_at timestamptz NOT NULL,
    created_by uuid REFERENCES users(id) ON DELETE SET NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    used_at timestamptz
);

CREATE INDEX cluster_enrollment_tokens_active_idx ON cluster_enrollment_tokens(cluster_id, expires_at) WHERE used_at IS NULL;
