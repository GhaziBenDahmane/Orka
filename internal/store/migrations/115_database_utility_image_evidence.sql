ALTER TABLE cluster_commands DROP CONSTRAINT cluster_commands_kind_check;
ALTER TABLE cluster_commands ADD CONSTRAINT cluster_commands_kind_check
    CHECK (kind IN ('swarm.deploy','swarm.remove','swarm.logs','swarm.nodes','swarm.status','swarm.storage-node','swarm.volume-node','swarm.volume-artifact','swarm.prune-volumes','swarm.exec','swarm.edge-certificates','container.run','image.resolve','database.utility','agent.upgrade','database.transfer'));

ALTER TABLE database_backups ADD COLUMN utility_image text NOT NULL DEFAULT '';
ALTER TABLE database_restores ADD COLUMN utility_image text NOT NULL DEFAULT '';
ALTER TABLE database_restores ADD COLUMN readiness_image text NOT NULL DEFAULT '';
ALTER TABLE database_migrations ADD COLUMN source_utility_image text NOT NULL DEFAULT '';
ALTER TABLE database_migrations ADD COLUMN target_utility_image text NOT NULL DEFAULT '';
ALTER TABLE database_migrations ADD COLUMN readiness_image text NOT NULL DEFAULT '';
