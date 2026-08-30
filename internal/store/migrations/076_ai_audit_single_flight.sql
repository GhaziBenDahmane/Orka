WITH ranked AS (
    SELECT id,row_number() OVER (PARTITION BY service_account_id,agent_name ORDER BY started_at DESC,id DESC) AS position
    FROM ai_audit_runs
    WHERE status='running'
)
UPDATE ai_audit_runs run
SET status='failed',
    summary='superseded while enabling single-flight audit execution',
    completed_at=now()
FROM ranked
WHERE run.id=ranked.id AND ranked.position>1;

CREATE UNIQUE INDEX ai_audit_runs_active_agent_idx
    ON ai_audit_runs(service_account_id,agent_name)
    WHERE status='running';
