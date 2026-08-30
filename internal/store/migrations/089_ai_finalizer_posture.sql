CREATE INDEX jobs_finalizer_posture_idx
    ON jobs(kind,status)
    INCLUDE(payload)
    WHERE kind IN ('delete.project','delete.environment','delete.compose','delete.cluster');
