ALTER TABLE ai_audit_findings
    ADD COLUMN disposition text NOT NULL DEFAULT 'open'
        CHECK (disposition IN ('open','acknowledged','resolved')),
    ADD COLUMN triage_note text NOT NULL DEFAULT '',
    ADD COLUMN triaged_by_user_id uuid REFERENCES users(id) ON DELETE SET NULL,
    ADD COLUMN triaged_by_service_account_id uuid REFERENCES service_accounts(id) ON DELETE SET NULL,
    ADD COLUMN triaged_at timestamptz;

ALTER TABLE ai_audit_findings
    ADD CONSTRAINT ai_audit_findings_single_triage_actor
        CHECK (num_nonnulls(triaged_by_user_id,triaged_by_service_account_id) <= 1);

CREATE INDEX ai_audit_findings_disposition_idx
    ON ai_audit_findings(disposition,created_at DESC);
