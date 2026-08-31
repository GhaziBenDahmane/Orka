CREATE INDEX ai_audit_runs_org_account_started_idx
    ON ai_audit_runs(organization_id, service_account_id, started_at DESC);
