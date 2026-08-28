CREATE TABLE source_credentials (
    id uuid PRIMARY KEY,
    organization_id uuid NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    kind text NOT NULL CHECK (kind IN ('git','registry')),
    name text NOT NULL,
    server text NOT NULL,
    username text NOT NULL,
    encrypted_secret text NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    UNIQUE (organization_id,kind,name)
);

ALTER TABLE application_sources
    ADD COLUMN git_credential_id uuid REFERENCES source_credentials(id) ON DELETE SET NULL,
    ADD COLUMN registry_credential_id uuid REFERENCES source_credentials(id) ON DELETE SET NULL;
