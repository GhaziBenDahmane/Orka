UPDATE jobs
SET status='cancelled',finished_at=COALESCE(finished_at,now()),locked_at=NULL,locked_by=NULL,lease_id=NULL
WHERE resource_key LIKE 'database:%' AND status='pending' AND cancel_requested_at IS NOT NULL;
