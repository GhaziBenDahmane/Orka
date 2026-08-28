CREATE TABLE resource_policies (
    organization_id uuid NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    scope_type text NOT NULL CHECK (scope_type IN ('organization','project','environment')),
    scope_id uuid NOT NULL,
    maintenance_enabled boolean NOT NULL DEFAULT false,
    maintenance_reason text NOT NULL DEFAULT '',
    max_projects integer CHECK (max_projects IS NULL OR max_projects > 0),
    max_environments integer CHECK (max_environments IS NULL OR max_environments > 0),
    max_services integer CHECK (max_services IS NULL OR max_services > 0),
    max_databases integer CHECK (max_databases IS NULL OR max_databases > 0),
    updated_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (scope_type, scope_id),
    CHECK (scope_type = 'organization' OR max_projects IS NULL),
    CHECK (scope_type <> 'environment' OR max_environments IS NULL),
    CHECK (scope_type <> 'organization' OR scope_id = organization_id)
);

CREATE INDEX resource_policies_organization_idx ON resource_policies(organization_id);
