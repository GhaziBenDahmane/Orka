CREATE TABLE tags (
    id uuid PRIMARY KEY,
    organization_id uuid NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    name text NOT NULL CHECK (char_length(name) BETWEEN 1 AND 64 AND btrim(name) = name),
    color text NOT NULL DEFAULT '#64748B' CHECK (color ~ '^#[0-9A-Fa-f]{6}$'),
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now()
);

CREATE UNIQUE INDEX tags_organization_name_unique
    ON tags (organization_id, lower(name));

CREATE TABLE compose_service_tags (
    compose_service_id uuid NOT NULL REFERENCES compose_services(id) ON DELETE CASCADE,
    tag_id uuid NOT NULL REFERENCES tags(id) ON DELETE CASCADE,
    created_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (compose_service_id, tag_id)
);

CREATE INDEX compose_service_tags_tag_idx ON compose_service_tags(tag_id);
