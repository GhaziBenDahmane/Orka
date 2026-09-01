CREATE UNIQUE INDEX jobs_commit_status_delivery_active_unique
    ON jobs ((payload->>'deliveryId'))
    WHERE kind='commit.status' AND status IN ('pending','running');
