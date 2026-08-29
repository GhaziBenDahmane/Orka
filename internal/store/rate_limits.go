package store

import (
	"context"
	"errors"
	"time"
)

// ConsumeRateLimit atomically consumes one attempt from a fixed window. Keys
// must already be irreversibly hashed so account identifiers are not retained.
func (s *Store) ConsumeRateLimit(ctx context.Context, bucket string, keyHash []byte, limit int, window time.Duration) (bool, int, error) {
	if bucket == "" || len(keyHash) == 0 || limit < 1 || window < time.Second {
		return false, 0, errors.New("invalid rate limit")
	}
	seconds := int(window / time.Second)
	var attempts, retryAfter int
	err := s.Pool.QueryRow(ctx, `
		INSERT INTO auth_rate_limits(bucket,key_hash,window_started_at,attempts)
		VALUES($1,$2,now(),1)
		ON CONFLICT(bucket,key_hash) DO UPDATE SET
			window_started_at=CASE WHEN auth_rate_limits.window_started_at <= now()-make_interval(secs => $3) THEN now() ELSE auth_rate_limits.window_started_at END,
			attempts=CASE WHEN auth_rate_limits.window_started_at <= now()-make_interval(secs => $3) THEN 1 ELSE auth_rate_limits.attempts+1 END
		RETURNING attempts, GREATEST(1,CEIL(EXTRACT(EPOCH FROM (window_started_at+make_interval(secs => $3)-now()))))::integer`,
		bucket, keyHash, seconds).Scan(&attempts, &retryAfter)
	return attempts <= limit, retryAfter, err
}

func (s *Store) PruneAuthenticationRateLimits(ctx context.Context, olderThan time.Duration) (int64, error) {
	if olderThan < time.Minute {
		return 0, errors.New("rate limit retention must be at least one minute")
	}
	tag, err := s.Pool.Exec(ctx, `DELETE FROM auth_rate_limits WHERE window_started_at < now()-make_interval(secs => $1)`, int(olderThan/time.Second))
	return tag.RowsAffected(), err
}
