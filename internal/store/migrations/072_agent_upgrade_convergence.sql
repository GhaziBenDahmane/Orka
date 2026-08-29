ALTER TABLE clusters
    ADD COLUMN agent_image text NOT NULL DEFAULT '',
    ADD COLUMN agent_update_state text NOT NULL DEFAULT '';

UPDATE cluster_commands
SET status='cancelled',
    last_error='upgrade predates durable convergence tracking; queue it again',
    lease_id=NULL,
    lease_expires_at=NULL,
    finished_at=now()
WHERE kind='agent.upgrade' AND status IN ('pending','leased');

ALTER TABLE cluster_commands ADD COLUMN target_image text NOT NULL DEFAULT '';
ALTER TABLE cluster_commands DROP CONSTRAINT cluster_commands_status_check;
ALTER TABLE cluster_commands ADD CONSTRAINT cluster_commands_status_check
    CHECK (status IN ('pending','leased','verifying','succeeded','failed','cancelled'));
ALTER TABLE cluster_commands ADD CONSTRAINT cluster_commands_upgrade_target_check
    CHECK (
        kind <> 'agent.upgrade'
        OR target_image ~ '^[A-Za-z0-9][A-Za-z0-9._:/-]*@sha256:[a-f0-9]{64}$'
        OR (target_image='' AND status IN ('succeeded','failed','cancelled'))
    );

CREATE UNIQUE INDEX cluster_commands_active_agent_upgrade_idx
    ON cluster_commands(cluster_id)
    WHERE kind='agent.upgrade' AND status IN ('pending','leased','verifying');
