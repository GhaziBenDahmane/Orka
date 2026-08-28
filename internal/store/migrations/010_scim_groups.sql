CREATE TABLE scim_user_defaults (
    organization_id uuid NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    user_id uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    default_role text NOT NULL CHECK (default_role IN ('admin','developer','viewer')),
    PRIMARY KEY (organization_id,user_id)
);

CREATE TABLE scim_groups (
    id uuid PRIMARY KEY,
    organization_id uuid NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    external_id text,
    display_name text NOT NULL,
    role text NOT NULL DEFAULT 'viewer' CHECK (role IN ('admin','developer','viewer')),
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    UNIQUE (organization_id,display_name)
);

CREATE UNIQUE INDEX scim_groups_external_id_idx
    ON scim_groups(organization_id,external_id) WHERE external_id IS NOT NULL;

CREATE TABLE scim_group_members (
    group_id uuid NOT NULL REFERENCES scim_groups(id) ON DELETE CASCADE,
    user_id uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    PRIMARY KEY (group_id,user_id)
);
