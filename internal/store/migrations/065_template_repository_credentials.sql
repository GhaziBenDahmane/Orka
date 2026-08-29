ALTER TABLE template_repositories
    ADD COLUMN credential_id uuid REFERENCES source_credentials(id) ON DELETE SET NULL;

CREATE INDEX template_repositories_credential_idx
    ON template_repositories(credential_id)
    WHERE credential_id IS NOT NULL;
