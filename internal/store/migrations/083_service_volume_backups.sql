ALTER TABLE compose_services
    ADD COLUMN storage_node_id text NOT NULL DEFAULT ''
        CHECK (storage_node_id = '' OR storage_node_id ~ '^[a-z0-9]{1,64}$');

UPDATE compose_services service
SET storage_node_id=database.storage_node_id
FROM database_instances database
WHERE database.compose_service_id=service.id AND database.storage_node_id<>'';

CREATE TABLE volume_backup_policies (
    id uuid PRIMARY KEY,
    compose_service_id uuid NOT NULL REFERENCES compose_services(id) ON DELETE CASCADE,
    volume_name text NOT NULL CHECK (volume_name ~ '^[A-Za-z0-9][A-Za-z0-9_.-]{0,254}$'),
    destination_id uuid NOT NULL REFERENCES backup_destinations(id) ON DELETE RESTRICT,
    interval_seconds integer NOT NULL CHECK (interval_seconds BETWEEN 900 AND 2678400),
    retention_count integer NOT NULL CHECK (retention_count BETWEEN 1 AND 100),
    quiesce boolean NOT NULL DEFAULT true,
    enabled boolean NOT NULL DEFAULT true,
    next_run_at timestamptz NOT NULL,
    last_run_at timestamptz,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    UNIQUE (compose_service_id,volume_name)
);
CREATE INDEX volume_backup_policies_due_idx ON volume_backup_policies(next_run_at) WHERE enabled;

CREATE TABLE volume_backups (
    id uuid PRIMARY KEY,
    volume_backup_policy_id uuid REFERENCES volume_backup_policies(id) ON DELETE SET NULL,
    compose_service_id uuid NOT NULL REFERENCES compose_services(id) ON DELETE CASCADE,
    volume_name text NOT NULL CHECK (volume_name ~ '^[A-Za-z0-9][A-Za-z0-9_.-]{0,254}$'),
    storage_node_id text NOT NULL CHECK (storage_node_id ~ '^[a-z0-9]{1,64}$'),
    destination_id uuid NOT NULL REFERENCES backup_destinations(id) DEFERRABLE INITIALLY DEFERRED,
    quiesce boolean NOT NULL,
    status text NOT NULL CHECK (status IN ('queued','running','succeeded','failed','cancelled')),
    object_key text NOT NULL DEFAULT '',
    size_bytes bigint,
    sha256 text NOT NULL DEFAULT '',
    plaintext_sha256 text NOT NULL DEFAULT '',
    encrypted_data_key text NOT NULL DEFAULT '',
    error text NOT NULL DEFAULT '',
    actor_user_id uuid REFERENCES users(id) ON DELETE SET NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    started_at timestamptz,
    finished_at timestamptz
);
CREATE INDEX volume_backups_service_created_idx ON volume_backups(compose_service_id,created_at DESC);

CREATE TABLE volume_restores (
    id uuid PRIMARY KEY,
    volume_backup_id uuid NOT NULL REFERENCES volume_backups(id) ON DELETE RESTRICT,
    status text NOT NULL CHECK (status IN ('queued','running','succeeded','failed','cancelled')),
    error text NOT NULL DEFAULT '',
    actor_user_id uuid REFERENCES users(id) ON DELETE SET NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    started_at timestamptz,
    finished_at timestamptz
);

ALTER TABLE cluster_commands DROP CONSTRAINT cluster_commands_kind_check;
ALTER TABLE cluster_commands ADD CONSTRAINT cluster_commands_kind_check
    CHECK (kind IN ('swarm.deploy','swarm.remove','swarm.logs','swarm.nodes','swarm.storage-node','swarm.volume-node','swarm.volume-artifact','swarm.prune-volumes','container.run','database.utility','agent.upgrade','database.transfer'));
