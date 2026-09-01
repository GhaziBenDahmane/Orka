ALTER TABLE ai_audit_runs
    ADD COLUMN lease_expires_at timestamptz;

UPDATE ai_audit_runs
SET lease_expires_at=CASE
    WHEN status='running' THEN started_at+interval '15 minutes'
    ELSE COALESCE(completed_at,started_at)
END;

ALTER TABLE ai_audit_runs
    ALTER COLUMN lease_expires_at SET NOT NULL,
    ALTER COLUMN lease_expires_at SET DEFAULT (now()+interval '15 minutes');

CREATE INDEX ai_audit_runs_running_lease_idx
    ON ai_audit_runs(lease_expires_at)
    WHERE status='running';
