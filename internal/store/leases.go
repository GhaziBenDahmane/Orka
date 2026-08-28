package store

import (
	"context"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
)

// AcquireControllerLease atomically acquires or renews a named singleton lease.
// A different controller may take it only after expiry.
func (s *Store) AcquireControllerLease(ctx context.Context, name, holder string, ttl time.Duration) (bool, error) {
	if name == "" || holder == "" || ttl < 5*time.Second || ttl > 24*time.Hour {
		return false, errors.New("invalid controller lease")
	}
	var acquired bool
	err := s.Pool.QueryRow(ctx, `INSERT INTO controller_leases(name,holder,expires_at) VALUES($1,$2,now()+($3::bigint * interval '1 millisecond'))
		ON CONFLICT(name) DO UPDATE SET holder=excluded.holder,expires_at=excluded.expires_at,updated_at=now()
		WHERE controller_leases.holder=excluded.holder OR controller_leases.expires_at<=now()
		RETURNING true`, name, holder, ttl.Milliseconds()).Scan(&acquired)
	if errors.Is(err, pgx.ErrNoRows) {
		return false, nil
	}
	return acquired, err
}
