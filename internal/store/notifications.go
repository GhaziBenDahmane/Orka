package store

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

type NotificationEndpoint struct {
	ID              uuid.UUID `json:"id"`
	OrganizationID  uuid.UUID `json:"organizationId"`
	Name            string    `json:"name"`
	Kind            string    `json:"kind"`
	EncryptedURL    string    `json:"-"`
	EncryptedSecret string    `json:"-"`
	Events          []string  `json:"events"`
	Enabled         bool      `json:"enabled"`
	CreatedAt       time.Time `json:"createdAt"`
	UpdatedAt       time.Time `json:"updatedAt"`
}

type NotificationDelivery struct {
	ID           uuid.UUID       `json:"id"`
	EndpointID   uuid.UUID       `json:"endpointId"`
	EventType    string          `json:"eventType"`
	ResourceType string          `json:"resourceType"`
	ResourceID   string          `json:"resourceId"`
	Payload      json.RawMessage `json:"payload"`
	Status       string          `json:"status"`
	ResponseCode *int            `json:"responseCode,omitempty"`
	LastError    string          `json:"lastError,omitempty"`
	CreatedAt    time.Time       `json:"createdAt"`
	StartedAt    *time.Time      `json:"startedAt,omitempty"`
	FinishedAt   *time.Time      `json:"finishedAt,omitempty"`
}

func (s *Store) CreateNotificationEndpoint(ctx context.Context, item NotificationEndpoint) (NotificationEndpoint, error) {
	tx, err := s.Pool.Begin(ctx)
	if err != nil {
		return NotificationEndpoint{}, err
	}
	defer tx.Rollback(ctx)
	item, err = createNotificationEndpointTx(ctx, tx, item)
	if err != nil {
		return NotificationEndpoint{}, err
	}
	return item, tx.Commit(ctx)
}

func (s *Store) CreateNotificationEndpointWithAudit(ctx context.Context, principal Principal, item NotificationEndpoint, remoteAddr string) (NotificationEndpoint, error) {
	item.OrganizationID = principal.OrganizationID
	tx, err := s.Pool.Begin(ctx)
	if err != nil {
		return NotificationEndpoint{}, err
	}
	defer tx.Rollback(ctx)
	item, err = createNotificationEndpointTx(ctx, tx, item)
	if err != nil {
		return NotificationEndpoint{}, err
	}
	if err = appendPrincipalAudit(ctx, tx, principal, "notification_endpoint.create", "notification_endpoint", item.ID.String(), remoteAddr, map[string]any{"kind": item.Kind, "events": item.Events}); err != nil {
		return NotificationEndpoint{}, err
	}
	return item, tx.Commit(ctx)
}

func createNotificationEndpointTx(ctx context.Context, tx pgx.Tx, item NotificationEndpoint) (NotificationEndpoint, error) {
	if item.ID == uuid.Nil {
		item.ID = uuid.New()
	}
	err := tx.QueryRow(ctx, `INSERT INTO notification_endpoints(id,organization_id,name,kind,encrypted_url,encrypted_secret,events,enabled) VALUES($1,$2,$3,$4,$5,$6,$7,$8) RETURNING created_at,updated_at`, item.ID, item.OrganizationID, item.Name, item.Kind, item.EncryptedURL, item.EncryptedSecret, item.Events, item.Enabled).Scan(&item.CreatedAt, &item.UpdatedAt)
	return item, err
}

func (s *Store) ListNotificationEndpoints(ctx context.Context, organizationID uuid.UUID) ([]NotificationEndpoint, error) {
	rows, err := s.Pool.Query(ctx, `SELECT id,organization_id,name,kind,events,enabled,created_at,updated_at FROM notification_endpoints WHERE organization_id=$1 ORDER BY name`, organizationID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	items := []NotificationEndpoint{}
	for rows.Next() {
		var item NotificationEndpoint
		if err := rows.Scan(&item.ID, &item.OrganizationID, &item.Name, &item.Kind, &item.Events, &item.Enabled, &item.CreatedAt, &item.UpdatedAt); err != nil {
			return nil, err
		}
		items = append(items, item)
	}
	return items, rows.Err()
}

func (s *Store) DeleteNotificationEndpoint(ctx context.Context, organizationID, id uuid.UUID) error {
	tx, err := s.Pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	if err = deleteNotificationEndpointTx(ctx, tx, organizationID, id); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

func (s *Store) DeleteNotificationEndpointWithAudit(ctx context.Context, principal Principal, id uuid.UUID, remoteAddr string) error {
	tx, err := s.Pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	if err = deleteNotificationEndpointTx(ctx, tx, principal.OrganizationID, id); err != nil {
		return err
	}
	if err = appendPrincipalAudit(ctx, tx, principal, "notification_endpoint.delete", "notification_endpoint", id.String(), remoteAddr, nil); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

func deleteNotificationEndpointTx(ctx context.Context, tx pgx.Tx, organizationID, id uuid.UUID) error {
	tag, err := tx.Exec(ctx, `UPDATE notification_endpoints SET enabled=false,updated_at=now() WHERE id=$1 AND organization_id=$2`, id, organizationID)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	_, err = tx.Exec(ctx, `UPDATE notification_deliveries SET status='failed',last_error='endpoint disabled',finished_at=now() WHERE endpoint_id=$1 AND status='pending'`, id)
	if err != nil {
		return err
	}
	_, err = tx.Exec(ctx, `UPDATE jobs SET status='cancelled',cancel_requested_at=now(),finished_at=now() WHERE kind='notify.webhook' AND status='pending' AND payload->>'deliveryId' IN (SELECT id::text FROM notification_deliveries WHERE endpoint_id=$1)`, id)
	if err != nil {
		return err
	}
	return nil
}

func (s *Store) GetNotificationDeliveryForJob(ctx context.Context, jobID, leaseID, id uuid.UUID) (NotificationDelivery, NotificationEndpoint, error) {
	var d NotificationDelivery
	var endpoint NotificationEndpoint
	err := s.WithJobLease(ctx, jobID, leaseID, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `UPDATE notification_deliveries d SET status='running',started_at=COALESCE(started_at,now()) FROM notification_endpoints e WHERE d.id=$1 AND e.id=d.endpoint_id AND e.enabled RETURNING d.id,d.endpoint_id,d.event_type,d.resource_type,d.resource_id,d.payload,d.status,d.created_at,e.kind,e.encrypted_url,e.encrypted_secret`, id).Scan(&d.ID, &d.EndpointID, &d.EventType, &d.ResourceType, &d.ResourceID, &d.Payload, &d.Status, &d.CreatedAt, &endpoint.Kind, &endpoint.EncryptedURL, &endpoint.EncryptedSecret)
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return NotificationDelivery{}, NotificationEndpoint{}, ErrNotFound
	}
	endpoint.ID = d.EndpointID
	return d, endpoint, err
}

func (s *Store) FinishNotificationDelivery(ctx context.Context, id uuid.UUID, code int, deliveryErr error) {
	if deliveryErr == nil {
		_, _ = s.Pool.Exec(ctx, `UPDATE notification_deliveries SET status='succeeded',response_code=$2,last_error='',finished_at=now() WHERE id=$1`, id, code)
		return
	}
	_, _ = s.Pool.Exec(ctx, `UPDATE notification_deliveries SET status='failed',response_code=NULLIF($2,0),last_error=$3,finished_at=now() WHERE id=$1`, id, code, truncateStore(deliveryErr.Error(), 8192))
}

func (s *Store) FinishNotificationDeliveryForJob(ctx context.Context, jobID, leaseID, id uuid.UUID, code int, deliveryErr error) error {
	return s.WithJobLease(ctx, jobID, leaseID, func(tx pgx.Tx) error {
		if deliveryErr == nil {
			_, err := tx.Exec(ctx, `UPDATE notification_deliveries SET status='succeeded',response_code=$2,last_error='',finished_at=now() WHERE id=$1`, id, code)
			return err
		}
		_, err := tx.Exec(ctx, `UPDATE notification_deliveries SET status='failed',response_code=NULLIF($2,0),last_error=$3,finished_at=now() WHERE id=$1`, id, code, truncateStore(deliveryErr.Error(), 8192))
		return err
	})
}

func (s *Store) QueueFailureNotifications(ctx context.Context, jobKind string, rawPayload []byte, cause error) error {
	eventType, resourceType, resourceID, organizationID, err := s.failureResource(ctx, jobKind, rawPayload)
	if errors.Is(err, ErrNotFound) {
		return nil
	}
	if err != nil {
		return err
	}
	notification := map[string]any{"event": eventType, "operation": jobKind, "resourceType": resourceType, "resourceId": resourceID, "error": truncateStore(cause.Error(), 8192), "occurredAt": time.Now().UTC(), "text": "Dockyard " + eventType + " for " + resourceType + " " + resourceID}
	if jobKind == "restore.volume" {
		var offline bool
		var serviceID uuid.UUID
		var volumeName, targetStorageNodeID string
		if err = s.Pool.QueryRow(ctx, `SELECT restore.offline,service.id,backup.volume_name,restore.target_storage_node_id FROM volume_restores restore JOIN volume_backups backup ON backup.id=restore.volume_backup_id JOIN compose_services service ON service.id=backup.compose_service_id WHERE restore.id=$1`, resourceID).Scan(&offline, &serviceID, &volumeName, &targetStorageNodeID); err != nil {
			return err
		}
		mode := "online"
		if offline {
			mode = "offline"
		}
		notification["mode"] = mode
		notification["serviceId"] = serviceID.String()
		notification["volumeName"] = volumeName
		notification["targetStorageNodeId"] = targetStorageNodeID
		if offline {
			notification["text"] = "Dockyard restore.failed for offline volume " + volumeName + " on service " + serviceID.String() + " targeting node " + targetStorageNodeID
		}
	}
	payload, _ := json.Marshal(notification)
	tx, err := s.Pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	if err = queueNotificationDeliveries(ctx, tx, organizationID, eventType, resourceType, resourceID, payload); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

func queueNotificationDeliveries(ctx context.Context, tx pgx.Tx, organizationID uuid.UUID, eventType, resourceType, resourceID string, payload json.RawMessage) error {
	rows, err := tx.Query(ctx, `SELECT id FROM notification_endpoints WHERE organization_id=$1 AND enabled AND $2=ANY(events)`, organizationID, eventType)
	if err != nil {
		return err
	}
	var endpointIDs []uuid.UUID
	for rows.Next() {
		var id uuid.UUID
		if err := rows.Scan(&id); err != nil {
			rows.Close()
			return err
		}
		endpointIDs = append(endpointIDs, id)
	}
	if err = rows.Err(); err != nil {
		rows.Close()
		return err
	}
	rows.Close()
	for _, endpointID := range endpointIDs {
		deliveryID := uuid.New()
		tag, err := tx.Exec(ctx, `INSERT INTO notification_deliveries(id,endpoint_id,event_type,resource_type,resource_id,payload) VALUES($1,$2,$3,$4,$5,$6) ON CONFLICT DO NOTHING`, deliveryID, endpointID, eventType, resourceType, resourceID, payload)
		if err == nil && tag.RowsAffected() == 1 {
			jobPayload, _ := json.Marshal(map[string]string{"deliveryId": deliveryID.String()})
			_, err = tx.Exec(ctx, `INSERT INTO jobs(id,kind,payload,max_attempts) VALUES($1,'notify.webhook',$2,8)`, uuid.New(), jobPayload)
		}
		if err != nil {
			return err
		}
	}
	return nil
}

func (s *Store) failureResource(ctx context.Context, jobKind string, rawPayload []byte) (string, string, string, uuid.UUID, error) {
	var payload map[string]string
	if err := json.Unmarshal(rawPayload, &payload); err != nil {
		return "", "", "", uuid.Nil, err
	}
	var resourceID, resourceType, eventType, query string
	switch jobKind {
	case "deploy.compose":
		resourceID, resourceType, eventType = payload["deploymentId"], "deployment", "deployment.failed"
		query = `SELECT p.organization_id FROM deployments d JOIN compose_services s ON s.id=d.compose_service_id JOIN environments e ON e.id=s.environment_id JOIN projects p ON p.id=e.project_id WHERE d.id=$1`
	case "stop.compose":
		resourceID, resourceType, eventType = payload["serviceId"], "compose_service", "service.stop.failed"
		query = `SELECT p.organization_id FROM compose_services s JOIN environments e ON e.id=s.environment_id JOIN projects p ON p.id=e.project_id WHERE s.id=$1`
	case "run.service-schedule":
		resourceID, resourceType, eventType = payload["executionId"], "service_schedule_execution", "service.schedule.failed"
		query = `SELECT project.organization_id FROM service_schedule_executions execution JOIN compose_services service ON service.id=execution.compose_service_id JOIN environments environment ON environment.id=service.environment_id JOIN projects project ON project.id=environment.project_id WHERE execution.id=$1`
	case "backup.database":
		resourceID, resourceType, eventType = payload["backupId"], "database_backup", "backup.failed"
		query = `SELECT p.organization_id FROM database_backups b JOIN database_instances d ON d.id=b.database_instance_id JOIN environments e ON e.id=d.environment_id JOIN projects p ON p.id=e.project_id WHERE b.id=$1`
	case "backup.volume":
		resourceID, resourceType, eventType = payload["backupId"], "volume_backup", "backup.failed"
		query = `SELECT p.organization_id FROM volume_backups b JOIN compose_services s ON s.id=b.compose_service_id JOIN environments e ON e.id=s.environment_id JOIN projects p ON p.id=e.project_id WHERE b.id=$1`
	case "restore.database":
		resourceID, resourceType = payload["restoreId"], "database_restore"
		id, err := uuid.Parse(resourceID)
		if err != nil {
			return "", "", "", uuid.Nil, err
		}
		var organizationID uuid.UUID
		var restoreKind string
		err = s.Pool.QueryRow(ctx, `SELECT p.organization_id,r.kind FROM database_restores r JOIN database_backups b ON b.id=r.database_backup_id JOIN database_instances d ON d.id=b.database_instance_id JOIN environments e ON e.id=d.environment_id JOIN projects p ON p.id=e.project_id WHERE r.id=$1`, id).Scan(&organizationID, &restoreKind)
		if errors.Is(err, pgx.ErrNoRows) {
			return "", "", "", uuid.Nil, ErrNotFound
		}
		if err != nil {
			return "", "", "", uuid.Nil, err
		}
		if restoreKind == "drill" {
			eventType = "restore.drill.failed"
		} else {
			eventType = "restore.failed"
		}
		return eventType, resourceType, resourceID, organizationID, nil
	case "migrate.database":
		resourceID, resourceType, eventType = payload["migrationId"], "database_migration", "database.migration.failed"
		query = `SELECT p.organization_id FROM database_migrations m JOIN database_instances d ON d.id=m.database_instance_id JOIN environments e ON e.id=d.environment_id JOIN projects p ON p.id=e.project_id WHERE m.id=$1`
	case "restore.volume":
		resourceID, resourceType, eventType = payload["restoreId"], "volume_restore", "restore.failed"
		query = `SELECT p.organization_id FROM volume_restores r JOIN volume_backups b ON b.id=r.volume_backup_id JOIN compose_services s ON s.id=b.compose_service_id JOIN environments e ON e.id=s.environment_id JOIN projects p ON p.id=e.project_id WHERE r.id=$1`
	case "audit.archive":
		resourceID, resourceType, eventType = payload["batchId"], "audit_archive_batch", "audit.archive.failed"
		query = `SELECT a.organization_id FROM audit_archive_batches b JOIN audit_archive_destinations a ON a.id=b.destination_id WHERE b.id=$1`
	case "network.create":
		resourceID, resourceType, eventType = payload["networkId"], "managed_network", "network.provision.failed"
		query = `SELECT organization_id FROM managed_networks WHERE id=$1`
	case "network.delete":
		resourceID, resourceType, eventType = payload["networkId"], "managed_network", "network.delete.failed"
		query = `SELECT organization_id FROM managed_networks WHERE id=$1`
	default:
		return "", "", "", uuid.Nil, ErrNotFound
	}
	id, err := uuid.Parse(resourceID)
	if err != nil {
		return "", "", "", uuid.Nil, err
	}
	var organizationID uuid.UUID
	if err := s.Pool.QueryRow(ctx, query, id).Scan(&organizationID); errors.Is(err, pgx.ErrNoRows) {
		return "", "", "", uuid.Nil, ErrNotFound
	} else if err != nil {
		return "", "", "", uuid.Nil, err
	}
	return eventType, resourceType, resourceID, organizationID, nil
}

func truncateStore(value string, limit int) string {
	if len(value) > limit {
		return value[:limit]
	}
	return value
}
