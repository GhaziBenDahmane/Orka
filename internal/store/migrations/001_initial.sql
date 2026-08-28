CREATE TABLE users (
    id uuid PRIMARY KEY,
    email text NOT NULL UNIQUE,
    password_hash text NOT NULL,
    display_name text NOT NULL DEFAULT '',
    created_at timestamptz NOT NULL DEFAULT now(),
    disabled_at timestamptz
);

CREATE TABLE organizations (
    id uuid PRIMARY KEY,
    name text NOT NULL,
    slug text NOT NULL UNIQUE,
    created_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE memberships (
    organization_id uuid NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    user_id uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    role text NOT NULL CHECK (role IN ('owner', 'admin', 'developer', 'viewer')),
    created_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (organization_id, user_id)
);

CREATE TABLE sessions (
    id uuid PRIMARY KEY,
    user_id uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    token_hash bytea NOT NULL UNIQUE,
    expires_at timestamptz NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    last_seen_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX sessions_expires_idx ON sessions(expires_at);

CREATE TABLE projects (
    id uuid PRIMARY KEY,
    organization_id uuid NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    name text NOT NULL,
    slug text NOT NULL,
    description text NOT NULL DEFAULT '',
    created_at timestamptz NOT NULL DEFAULT now(),
    UNIQUE (organization_id, slug)
);

CREATE TABLE environments (
    id uuid PRIMARY KEY,
    project_id uuid NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    name text NOT NULL,
    slug text NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    UNIQUE (project_id, slug)
);

CREATE TABLE compose_services (
    id uuid PRIMARY KEY,
    environment_id uuid NOT NULL REFERENCES environments(id) ON DELETE CASCADE,
    name text NOT NULL,
    slug text NOT NULL,
    stack_name text NOT NULL UNIQUE,
    compose_yaml text NOT NULL,
    encrypted_env text NOT NULL DEFAULT '',
    revision bigint NOT NULL DEFAULT 1,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    UNIQUE (environment_id, slug)
);

CREATE TABLE routes (
    id uuid PRIMARY KEY,
    compose_service_id uuid NOT NULL REFERENCES compose_services(id) ON DELETE CASCADE,
    service_name text NOT NULL,
    host text NOT NULL,
    path_prefix text NOT NULL DEFAULT '/',
    target_port integer NOT NULL CHECK (target_port BETWEEN 1 AND 65535),
    tls boolean NOT NULL DEFAULT true,
    certificate_resolver text NOT NULL DEFAULT 'letsencrypt',
    created_at timestamptz NOT NULL DEFAULT now(),
    UNIQUE (host, path_prefix)
);

CREATE TABLE deployments (
    id uuid PRIMARY KEY,
    compose_service_id uuid NOT NULL REFERENCES compose_services(id) ON DELETE CASCADE,
    revision bigint NOT NULL,
    compose_snapshot text NOT NULL,
    env_snapshot text NOT NULL DEFAULT '',
    status text NOT NULL CHECK (status IN ('queued','running','succeeded','failed','cancelled')),
    trigger text NOT NULL,
    actor_user_id uuid REFERENCES users(id) ON DELETE SET NULL,
    error text NOT NULL DEFAULT '',
    output text NOT NULL DEFAULT '',
    created_at timestamptz NOT NULL DEFAULT now(),
    started_at timestamptz,
    finished_at timestamptz
);
CREATE INDEX deployments_service_created_idx ON deployments(compose_service_id, created_at DESC);

CREATE TABLE jobs (
    id uuid PRIMARY KEY,
    kind text NOT NULL,
    payload jsonb NOT NULL,
    status text NOT NULL DEFAULT 'pending' CHECK (status IN ('pending','running','succeeded','failed')),
    attempts integer NOT NULL DEFAULT 0,
    max_attempts integer NOT NULL DEFAULT 3,
    run_after timestamptz NOT NULL DEFAULT now(),
    locked_at timestamptz,
    locked_by text,
    last_error text NOT NULL DEFAULT '',
    created_at timestamptz NOT NULL DEFAULT now(),
    finished_at timestamptz
);
CREATE INDEX jobs_claim_idx ON jobs(status, run_after, created_at);

CREATE TABLE templates (
    id uuid PRIMARY KEY,
    organization_id uuid REFERENCES organizations(id) ON DELETE CASCADE,
    template_key text NOT NULL,
    version text NOT NULL,
    name text NOT NULL,
    description text NOT NULL DEFAULT '',
    compose_yaml text NOT NULL,
    config jsonb NOT NULL DEFAULT '{}'::jsonb,
    source text NOT NULL DEFAULT 'native',
    checksum text NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    UNIQUE NULLS NOT DISTINCT (organization_id, template_key, version)
);

CREATE TABLE database_instances (
    id uuid PRIMARY KEY,
    environment_id uuid NOT NULL REFERENCES environments(id) ON DELETE CASCADE,
    name text NOT NULL,
    slug text NOT NULL,
    engine text NOT NULL,
    version text NOT NULL,
    compose_service_id uuid REFERENCES compose_services(id) ON DELETE SET NULL,
    encrypted_credentials text NOT NULL,
    config jsonb NOT NULL DEFAULT '{}'::jsonb,
    status text NOT NULL DEFAULT 'pending',
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    UNIQUE (environment_id, slug)
);

CREATE TABLE audit_events (
    id bigserial PRIMARY KEY,
    organization_id uuid REFERENCES organizations(id) ON DELETE SET NULL,
    actor_user_id uuid REFERENCES users(id) ON DELETE SET NULL,
    action text NOT NULL,
    resource_type text NOT NULL,
    resource_id text NOT NULL DEFAULT '',
    remote_addr text NOT NULL DEFAULT '',
    metadata jsonb NOT NULL DEFAULT '{}'::jsonb,
    created_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX audit_events_org_created_idx ON audit_events(organization_id, created_at DESC);
