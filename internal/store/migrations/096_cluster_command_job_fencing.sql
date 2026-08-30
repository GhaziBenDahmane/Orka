ALTER TABLE cluster_commands
    ADD COLUMN owner_job_id uuid REFERENCES jobs(id) ON DELETE CASCADE,
    ADD COLUMN owner_job_lease_id uuid;

ALTER TABLE cluster_commands
    ADD CONSTRAINT cluster_commands_job_owner_check
    CHECK ((owner_job_id IS NULL) = (owner_job_lease_id IS NULL));

CREATE INDEX cluster_commands_active_job_owner_idx
    ON cluster_commands(owner_job_id,owner_job_lease_id)
    WHERE owner_job_id IS NOT NULL AND status IN ('pending','leased','verifying');
