ALTER TABLE notification_endpoints DROP CONSTRAINT notification_endpoints_kind_check;
ALTER TABLE notification_endpoints ADD CONSTRAINT notification_endpoints_kind_check CHECK (kind IN ('webhook','slack','smtp','pagerduty','opsgenie'));
