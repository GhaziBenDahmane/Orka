CREATE TABLE service_schedules (
    id uuid PRIMARY KEY,
    compose_service_id uuid NOT NULL REFERENCES compose_services(id) ON DELETE CASCADE,
    name text NOT NULL CHECK (char_length(name) BETWEEN 1 AND 120),
    description text NOT NULL DEFAULT '' CHECK (char_length(description) <= 1000),
    cron_expression text NOT NULL CHECK (char_length(cron_expression) BETWEEN 1 AND 256),
    timezone text NOT NULL DEFAULT 'UTC' CHECK (char_length(timezone) BETWEEN 1 AND 128),
    target_service text NOT NULL CHECK (target_service ~ '^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$'),
    shell text NOT NULL DEFAULT 'sh' CHECK (shell IN ('sh','bash')),
    command text NOT NULL CHECK (char_length(command) BETWEEN 1 AND 16384),
    timeout_seconds integer NOT NULL DEFAULT 900 CHECK (timeout_seconds BETWEEN 1 AND 86400),
    enabled boolean NOT NULL DEFAULT true,
    next_run_at timestamptz NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    UNIQUE (compose_service_id,name)
);
CREATE INDEX service_schedules_due_idx ON service_schedules(next_run_at,id) WHERE enabled;

CREATE TABLE service_schedule_executions (
    id uuid PRIMARY KEY,
    schedule_id uuid REFERENCES service_schedules(id) ON DELETE SET NULL,
    compose_service_id uuid NOT NULL REFERENCES compose_services(id) ON DELETE CASCADE,
    schedule_name text NOT NULL,
    target_service text NOT NULL,
    shell text NOT NULL CHECK (shell IN ('sh','bash')),
    command text NOT NULL,
    timeout_seconds integer NOT NULL CHECK (timeout_seconds BETWEEN 1 AND 86400),
    trigger text NOT NULL CHECK (trigger IN ('scheduled','manual')),
    actor_user_id uuid REFERENCES users(id) ON DELETE SET NULL,
    status text NOT NULL DEFAULT 'queued' CHECK (status IN ('queued','running','succeeded','failed','cancelled')),
    output text NOT NULL DEFAULT '',
    error text NOT NULL DEFAULT '',
    created_at timestamptz NOT NULL DEFAULT now(),
    started_at timestamptz,
    finished_at timestamptz
);
CREATE INDEX service_schedule_executions_schedule_idx ON service_schedule_executions(schedule_id,created_at DESC,id DESC);
CREATE INDEX service_schedule_executions_service_idx ON service_schedule_executions(compose_service_id,created_at DESC,id DESC);
CREATE UNIQUE INDEX service_schedule_executions_active_idx ON service_schedule_executions(schedule_id)
    WHERE schedule_id IS NOT NULL AND status IN ('queued','running');

ALTER TABLE cluster_commands DROP CONSTRAINT cluster_commands_kind_check;
ALTER TABLE cluster_commands ADD CONSTRAINT cluster_commands_kind_check
    CHECK (kind IN ('swarm.deploy','swarm.remove','swarm.logs','swarm.nodes','swarm.status','swarm.storage-node','swarm.volume-node','swarm.volume-artifact','swarm.prune-volumes','swarm.exec','container.run','database.utility','agent.upgrade','database.transfer'));
