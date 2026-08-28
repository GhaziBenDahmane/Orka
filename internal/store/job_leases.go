package store

import (
	"context"
	"errors"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// WithJobLease serializes a resource-state transition with recovery of the
// corresponding job. The callback runs only while this exact execution
// attempt still owns the job row.
func (s *Store) WithJobLease(ctx context.Context, jobID, leaseID uuid.UUID, action func(pgx.Tx) error) error {
	if jobID == uuid.Nil || leaseID == uuid.Nil {
		return ErrLeaseLost
	}
	tx, err := s.Pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	var owned bool
	err = tx.QueryRow(ctx, `UPDATE jobs SET locked_at=now() WHERE id=$1 AND status='running' AND lease_id=$2 RETURNING true`, jobID, leaseID).Scan(&owned)
	if errors.Is(err, pgx.ErrNoRows) {
		return ErrLeaseLost
	}
	if err != nil {
		return err
	}
	if err = action(tx); err != nil {
		return err
	}
	return tx.Commit(ctx)
}
