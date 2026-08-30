ALTER TABLE cluster_commands DROP CONSTRAINT cluster_commands_kind_check;
ALTER TABLE cluster_commands ADD CONSTRAINT cluster_commands_kind_check
    CHECK (kind IN ('swarm.deploy','swarm.remove','swarm.logs','swarm.nodes','swarm.storage-node','swarm.volume-artifact','swarm.prune-volumes','container.run','database.utility','agent.upgrade','database.transfer'));
