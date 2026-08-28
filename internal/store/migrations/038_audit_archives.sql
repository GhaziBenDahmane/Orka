CREATE TABLE audit_archive_destinations (
    id uuid PRIMARY KEY,
    organization_id uuid NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    backup_destination_id uuid NOT NULL REFERENCES backup_destinations(id) ON DELETE RESTRICT,
    name text NOT NULL,
    object_prefix text NOT NULL DEFAULT 'audit',
    retention_days integer NOT NULL CHECK (retention_days BETWEEN 30 AND 3650),
    enabled boolean NOT NULL DEFAULT true,
    last_archived_id bigint NOT NULL DEFAULT 0,
    last_chain_hash text NOT NULL DEFAULT '',
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    UNIQUE (organization_id,name),
    UNIQUE (organization_id,backup_destination_id)
);

CREATE TABLE audit_archive_batches (
    id uuid PRIMARY KEY,
    destination_id uuid NOT NULL REFERENCES audit_archive_destinations(id) ON DELETE CASCADE,
    first_event_id bigint NOT NULL,
    last_event_id bigint NOT NULL,
    previous_sha256 text NOT NULL DEFAULT '',
    sha256 text NOT NULL DEFAULT '',
    object_key text NOT NULL,
    size_bytes bigint,
    status text NOT NULL DEFAULT 'pending' CHECK (status IN ('pending','running','succeeded','failed')),
    last_error text NOT NULL DEFAULT '',
    created_at timestamptz NOT NULL DEFAULT now(),
    started_at timestamptz,
    finished_at timestamptz,
    UNIQUE(destination_id,first_event_id,last_event_id),
    CHECK (first_event_id > 0 AND last_event_id >= first_event_id)
);

CREATE INDEX audit_archive_batches_destination_created_idx ON audit_archive_batches(destination_id,created_at DESC);
