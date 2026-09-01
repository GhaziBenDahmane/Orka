CREATE UNIQUE INDEX jobs_notification_delivery_active_unique
    ON jobs ((payload->>'deliveryId'))
    WHERE kind='notify.webhook' AND status IN ('pending','running');
