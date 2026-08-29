ALTER TABLE deployments
    ADD COLUMN effective_compose text NOT NULL DEFAULT '';

CREATE TABLE service_reconciliations (
    compose_service_id uuid PRIMARY KEY REFERENCES compose_services(id) ON DELETE CASCADE,
    state text NOT NULL CHECK (state IN ('healthy','missing','degraded','unknown','repairing')),
    consecutive_failures integer NOT NULL DEFAULT 0 CHECK (consecutive_failures >= 0),
    detail text NOT NULL DEFAULT '',
    last_checked_at timestamptz NOT NULL DEFAULT now(),
    last_repair_at timestamptz,
    updated_at timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX service_reconciliations_state_idx
    ON service_reconciliations(state, last_checked_at);

CREATE UNIQUE INDEX deployments_one_active_reconciliation_idx
    ON deployments(compose_service_id)
    WHERE trigger='reconcile' AND status IN ('queued','running');
