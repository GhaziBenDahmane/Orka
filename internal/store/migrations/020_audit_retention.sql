CREATE TABLE audit_retention_policies (
    organization_id uuid PRIMARY KEY REFERENCES organizations(id) ON DELETE CASCADE,
    retention_days integer NOT NULL DEFAULT 365 CHECK (retention_days BETWEEN 30 AND 3650),
    updated_at timestamptz NOT NULL DEFAULT now()
);
