ALTER TABLE template_repositories
    ADD COLUMN encrypted_webhook_secret text NOT NULL DEFAULT '',
    ADD COLUMN sync_requested_at timestamptz;

CREATE TABLE template_repository_webhook_deliveries (
    repository_id uuid NOT NULL REFERENCES template_repositories(id) ON DELETE CASCADE,
    delivery_id text NOT NULL,
    received_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (repository_id, delivery_id)
);

CREATE INDEX template_repository_webhook_deliveries_received_idx
    ON template_repository_webhook_deliveries(received_at);
