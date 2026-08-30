ALTER TABLE database_instances
    ADD COLUMN storage_node_id text NOT NULL DEFAULT ''
        CHECK (storage_node_id = '' OR storage_node_id ~ '^[a-z0-9]{1,64}$');

ALTER TABLE cluster_commands DROP CONSTRAINT cluster_commands_kind_check;
ALTER TABLE cluster_commands ADD CONSTRAINT cluster_commands_kind_check
    CHECK (kind IN ('swarm.deploy','swarm.remove','swarm.logs','swarm.nodes','swarm.storage-node','swarm.prune-volumes','container.run','database.utility','agent.upgrade','database.transfer'));
