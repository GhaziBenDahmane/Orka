package store

import (
	"context"
	"errors"
	"os"
	"testing"
	"time"

	"github.com/google/uuid"
)

func TestDeploymentCancellationAndDeletionQueue(t *testing.T) {
	databaseURL := os.Getenv("DOCKYARD_TEST_DATABASE_URL")
	if databaseURL == "" {
		t.Skip("DOCKYARD_TEST_DATABASE_URL is not set")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	db, err := Open(ctx, databaseURL)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Pool.Close()

	orgID, otherOrgID, userID := uuid.New(), uuid.New(), uuid.New()
	projectID, environmentID, serviceID := uuid.New(), uuid.New(), uuid.New()
	tx, err := db.Pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(ctx)
	_, err = tx.Exec(ctx, `INSERT INTO organizations(id,name,slug) VALUES($1,'Lifecycle',$2),($3,'Other',$4)`, orgID, "lifecycle-"+orgID.String(), otherOrgID, "other-"+otherOrgID.String())
	if err == nil {
		_, err = tx.Exec(ctx, `INSERT INTO users(id,email,password_hash) VALUES($1,$2,'!test')`, userID, userID.String()+"@example.test")
	}
	if err == nil {
		_, err = tx.Exec(ctx, `INSERT INTO memberships(organization_id,user_id,role) VALUES($1,$2,'owner')`, orgID, userID)
	}
	if err == nil {
		_, err = tx.Exec(ctx, `INSERT INTO projects(id,organization_id,name,slug) VALUES($1,$2,'Project','project')`, projectID, orgID)
	}
	if err == nil {
		_, err = tx.Exec(ctx, `INSERT INTO environments(id,project_id,name,slug) VALUES($1,$2,'Production','production')`, environmentID, projectID)
	}
	if err == nil {
		_, err = tx.Exec(ctx, `INSERT INTO compose_services(id,environment_id,name,slug,stack_name,compose_yaml) VALUES($1,$2,'API','api',$3,'services: {}')`, serviceID, environmentID, "test-"+serviceID.String())
	}
	if err == nil {
		err = tx.Commit(ctx)
	}
	if err != nil {
		t.Fatal(err)
	}

	var deploymentID uuid.UUID
	t.Cleanup(func() {
		if deploymentID != uuid.Nil {
			_, _ = db.Pool.Exec(context.Background(), `DELETE FROM jobs WHERE payload->>'deploymentId'=$1 OR payload->>'serviceId'=$2`, deploymentID.String(), serviceID.String())
		}
		_, _ = db.Pool.Exec(context.Background(), `DELETE FROM organizations WHERE id=ANY($1)`, []uuid.UUID{orgID, otherOrgID})
		_, _ = db.Pool.Exec(context.Background(), `DELETE FROM users WHERE id=$1`, userID)
	})

	deployment, err := db.QueueDeployment(ctx, orgID, serviceID, userID, "test")
	if err != nil {
		t.Fatal(err)
	}
	deploymentID = deployment.ID
	if err = db.CancelDeployment(ctx, otherOrgID, deployment.ID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("cross-tenant cancellation error = %v, want not found", err)
	}
	if err = db.CancelDeployment(ctx, orgID, deployment.ID); err != nil {
		t.Fatal(err)
	}
	var jobStatus, deploymentStatus string
	err = db.Pool.QueryRow(ctx, `SELECT j.status,d.status FROM jobs j JOIN deployments d ON d.id=(j.payload->>'deploymentId')::uuid WHERE d.id=$1`, deployment.ID).Scan(&jobStatus, &deploymentStatus)
	if err != nil || jobStatus != "cancelled" || deploymentStatus != "cancelled" {
		t.Fatalf("states = %q/%q, err = %v", jobStatus, deploymentStatus, err)
	}
	if err = db.QueueServiceDeletion(ctx, orgID, serviceID); err != nil {
		t.Fatal(err)
	}
	var deletionQueued bool
	err = db.Pool.QueryRow(ctx, `SELECT deletion_requested_at IS NOT NULL AND EXISTS(SELECT 1 FROM jobs WHERE kind='delete.compose' AND payload->>'serviceId'=$2 AND status='pending') FROM compose_services WHERE id=$1`, serviceID, serviceID.String()).Scan(&deletionQueued)
	if err != nil || !deletionQueued {
		t.Fatalf("deletion queued = %v, err = %v", deletionQueued, err)
	}
}
