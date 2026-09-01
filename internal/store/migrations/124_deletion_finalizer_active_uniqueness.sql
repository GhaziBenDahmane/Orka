CREATE UNIQUE INDEX jobs_deletion_finalizer_active_unique
ON jobs(kind, (
    CASE kind
        WHEN 'delete.project' THEN payload->>'projectId'
        WHEN 'delete.environment' THEN payload->>'environmentId'
        WHEN 'delete.compose' THEN payload->>'serviceId'
        WHEN 'delete.database-link' THEN payload->>'databaseId'
        WHEN 'delete.cluster' THEN payload->>'clusterId'
        WHEN 'network.delete' THEN payload->>'networkId'
    END
))
WHERE status IN ('pending','running')
  AND kind IN ('delete.project','delete.environment','delete.compose','delete.database-link','delete.cluster','network.delete');
