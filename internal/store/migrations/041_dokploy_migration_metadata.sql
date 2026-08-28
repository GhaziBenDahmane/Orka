CREATE TABLE dokploy_migration_resources (
    target_organization_id uuid NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    source_organization_id text NOT NULL,
    source_kind text NOT NULL,
    source_id text NOT NULL,
    target_id uuid,
    status text NOT NULL CHECK (status IN ('imported','skipped')),
    reason text NOT NULL DEFAULT '',
    metadata jsonb NOT NULL DEFAULT '{}'::jsonb,
    updated_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY(target_organization_id,source_organization_id,source_kind,source_id)
);

CREATE INDEX dokploy_migration_resources_target_status_idx ON dokploy_migration_resources(target_organization_id,status,source_kind);
