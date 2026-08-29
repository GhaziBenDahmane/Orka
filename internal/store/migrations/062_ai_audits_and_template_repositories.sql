ALTER TABLE service_accounts DROP CONSTRAINT service_accounts_role_check;
ALTER TABLE service_accounts ADD CONSTRAINT service_accounts_role_check
    CHECK (role IN ('admin','developer','viewer','auditor'));

CREATE TABLE template_repositories (
    id uuid PRIMARY KEY,
    organization_id uuid NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    name text NOT NULL,
    slug text NOT NULL,
    repository_url text NOT NULL,
    git_ref text NOT NULL DEFAULT 'main',
    catalog_path text NOT NULL DEFAULT '',
    enabled boolean NOT NULL DEFAULT true,
    last_sync_status text NOT NULL DEFAULT 'never' CHECK (last_sync_status IN ('never','running','succeeded','failed')),
    last_sync_error text NOT NULL DEFAULT '',
    last_synced_at timestamptz,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    UNIQUE (organization_id,slug),
    UNIQUE (organization_id,repository_url,git_ref,catalog_path)
);

ALTER TABLE templates
    ADD COLUMN repository_id uuid REFERENCES template_repositories(id) ON DELETE SET NULL,
    ADD COLUMN source_path text NOT NULL DEFAULT '';
CREATE INDEX templates_repository_idx ON templates(repository_id);

CREATE TABLE ai_audit_runs (
    id uuid PRIMARY KEY,
    organization_id uuid NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    service_account_id uuid NOT NULL REFERENCES service_accounts(id) ON DELETE CASCADE,
    agent_name text NOT NULL,
    agent_version text NOT NULL DEFAULT '',
    model text NOT NULL DEFAULT '',
    status text NOT NULL DEFAULT 'running' CHECK (status IN ('running','completed','failed')),
    scope jsonb NOT NULL DEFAULT '{}'::jsonb,
    summary text NOT NULL DEFAULT '',
    started_at timestamptz NOT NULL DEFAULT now(),
    completed_at timestamptz
);
CREATE INDEX ai_audit_runs_org_started_idx ON ai_audit_runs(organization_id,started_at DESC);

CREATE TABLE ai_audit_findings (
    id uuid PRIMARY KEY,
    run_id uuid NOT NULL REFERENCES ai_audit_runs(id) ON DELETE CASCADE,
    severity text NOT NULL CHECK (severity IN ('info','low','medium','high','critical')),
    category text NOT NULL,
    title text NOT NULL,
    description text NOT NULL,
    resource_type text NOT NULL DEFAULT '',
    resource_id text NOT NULL DEFAULT '',
    evidence jsonb NOT NULL DEFAULT '{}'::jsonb,
    remediation text NOT NULL DEFAULT '',
    fingerprint text NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    UNIQUE (run_id,fingerprint)
);
CREATE INDEX ai_audit_findings_run_severity_idx ON ai_audit_findings(run_id,severity);
