ALTER TABLE ai_audit_findings
    ADD COLUMN previous_finding_id uuid REFERENCES ai_audit_findings(id) ON DELETE SET NULL,
    ADD COLUMN occurrence_number integer NOT NULL DEFAULT 1 CHECK (occurrence_number > 0);

CREATE INDEX ai_audit_findings_previous_idx
    ON ai_audit_findings(previous_finding_id)
    WHERE previous_finding_id IS NOT NULL;

CREATE INDEX ai_audit_findings_fingerprint_created_idx
    ON ai_audit_findings(fingerprint,created_at DESC);
