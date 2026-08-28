ALTER TABLE application_sources
    ADD COLUMN status_provider text NOT NULL DEFAULT '' CHECK (status_provider IN ('','github','gitlab','gitea','bitbucket')),
    ADD COLUMN status_credential_id uuid REFERENCES source_credentials(id) ON DELETE SET NULL,
    ADD COLUMN status_context text NOT NULL DEFAULT 'dockyard/deploy';

ALTER TABLE deployments ADD COLUMN commit_sha text NOT NULL DEFAULT '';

CREATE TABLE commit_status_deliveries (
    id uuid PRIMARY KEY,
    deployment_id uuid NOT NULL REFERENCES deployments(id) ON DELETE CASCADE,
    state text NOT NULL CHECK (state IN ('pending','success','failure','error')),
    status text NOT NULL DEFAULT 'pending' CHECK (status IN ('pending','running','succeeded','failed')),
    response_code integer,
    last_error text NOT NULL DEFAULT '',
    created_at timestamptz NOT NULL DEFAULT now(),
    started_at timestamptz,
    finished_at timestamptz,
    UNIQUE (deployment_id,state)
);

CREATE INDEX commit_status_deliveries_deployment_created_idx ON commit_status_deliveries(deployment_id,created_at DESC);
