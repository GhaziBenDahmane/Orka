CREATE TABLE backup_destinations (
    id uuid PRIMARY KEY,
    organization_id uuid NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    name text NOT NULL,
    endpoint text NOT NULL,
    region text NOT NULL DEFAULT '',
    bucket text NOT NULL,
    prefix text NOT NULL DEFAULT '',
    use_tls boolean NOT NULL DEFAULT true,
    encrypted_credentials text NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    UNIQUE (organization_id,name)
);

ALTER TABLE backup_policies
    ADD COLUMN destination_id uuid REFERENCES backup_destinations(id) ON DELETE SET NULL;

ALTER TABLE database_backups
    ADD COLUMN destination_id uuid REFERENCES backup_destinations(id) ON DELETE RESTRICT,
    ADD COLUMN object_key text NOT NULL DEFAULT '';
