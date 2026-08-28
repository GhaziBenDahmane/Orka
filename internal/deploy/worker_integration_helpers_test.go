package deploy

import (
	"context"
	"testing"

	"github.com/bendahma/dokploy-go/internal/store"
	"github.com/google/uuid"
)

func leaseResourceJob(t *testing.T, ctx context.Context, db *store.Store, kind, resourceKey string, resourceID uuid.UUID) job {
	t.Helper()
	leaseID := uuid.New()
	var item job
	err := db.Pool.QueryRow(ctx, `UPDATE jobs SET status='running',attempts=attempts+1,locked_at=now(),locked_by='integration-test',lease_id=$4
		WHERE id=(SELECT id FROM jobs WHERE kind=$1 AND payload->>$2=$3 AND status='pending' ORDER BY created_at LIMIT 1 FOR UPDATE SKIP LOCKED)
		RETURNING id,lease_id,kind,payload,attempts-1,max_attempts`, kind, resourceKey, resourceID.String(), leaseID).Scan(&item.ID, &item.LeaseID, &item.Kind, &item.Payload, &item.Attempts, &item.MaxAttempts)
	if err != nil {
		t.Fatalf("lease %s job for %s: %v", kind, resourceID, err)
	}
	return item
}
