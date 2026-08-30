CREATE INDEX ai_audit_runs_status_org_completed_idx
    ON ai_audit_runs(status, organization_id, completed_at DESC);

CREATE INDEX ai_audit_runs_running_org_started_idx
    ON ai_audit_runs(organization_id, started_at)
    WHERE status='running';
