ALTER TABLE compose_services
    ADD COLUMN desired_state text NOT NULL DEFAULT 'running',
    ADD CONSTRAINT compose_services_desired_state_check CHECK (desired_state IN ('running', 'stopped'));

CREATE INDEX compose_services_reconciliation_candidates_idx
    ON compose_services(updated_at, id)
    WHERE deletion_requested_at IS NULL AND desired_state = 'running';
