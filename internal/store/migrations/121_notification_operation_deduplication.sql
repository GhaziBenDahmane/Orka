ALTER TABLE notification_deliveries
    ADD COLUMN operation_id text NOT NULL DEFAULT '';

ALTER TABLE notification_deliveries
    DROP CONSTRAINT notification_deliveries_endpoint_id_event_type_resource_typ_key;

ALTER TABLE notification_deliveries
    ADD CONSTRAINT notification_deliveries_operation_unique
    UNIQUE (endpoint_id, event_type, resource_type, resource_id, operation_id);
