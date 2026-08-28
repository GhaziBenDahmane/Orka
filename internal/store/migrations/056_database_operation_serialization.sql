ALTER TABLE jobs ADD COLUMN resource_key text;

UPDATE jobs j
SET resource_key='database:' || b.database_instance_id::text
FROM database_backups b
WHERE j.kind='backup.database' AND j.payload->>'backupId'=b.id::text;

UPDATE jobs j
SET resource_key='database:' || b.database_instance_id::text
FROM database_restores r
JOIN database_backups b ON b.id=r.database_backup_id
WHERE j.kind='restore.database' AND j.payload->>'restoreId'=r.id::text;

UPDATE jobs j
SET resource_key='database:' || m.database_instance_id::text
FROM database_migrations m
WHERE j.kind='migrate.database' AND j.payload->>'migrationId'=m.id::text;

WITH duplicate_running AS (
    SELECT id,row_number() OVER (PARTITION BY resource_key ORDER BY locked_at,id) AS position
    FROM jobs
    WHERE status='running' AND resource_key IS NOT NULL
)
UPDATE jobs j
SET status='pending',run_after=now(),locked_at=NULL,locked_by=NULL,lease_id=NULL
FROM duplicate_running d
WHERE j.id=d.id AND d.position>1;

CREATE UNIQUE INDEX jobs_one_running_resource_idx
    ON jobs(resource_key)
    WHERE status='running' AND resource_key IS NOT NULL;

CREATE INDEX jobs_resource_order_idx
    ON jobs(resource_key,status,created_at,id)
    WHERE resource_key IS NOT NULL;
