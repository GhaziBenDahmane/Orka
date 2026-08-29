package store

import (
	"context"
	"os"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"
)

func TestConsumeRateLimitIsAtomicAndResets(t *testing.T) {
	databaseURL := os.Getenv("DOCKYARD_TEST_DATABASE_URL")
	if databaseURL == "" {
		t.Skip("DOCKYARD_TEST_DATABASE_URL is not set")
	}
	db, err := Open(context.Background(), databaseURL)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Pool.Close()

	key := []byte(uuid.NewString())
	var allowed atomic.Int32
	var group sync.WaitGroup
	for range 20 {
		group.Add(1)
		go func() {
			defer group.Done()
			ok, retryAfter, consumeErr := db.ConsumeRateLimit(context.Background(), "test", key, 5, time.Minute)
			if consumeErr != nil {
				t.Errorf("consume: %v", consumeErr)
				return
			}
			if retryAfter < 1 || retryAfter > 60 {
				t.Errorf("retryAfter=%d", retryAfter)
			}
			if ok {
				allowed.Add(1)
			}
		}()
	}
	group.Wait()
	if got := allowed.Load(); got != 5 {
		t.Fatalf("allowed=%d, want 5", got)
	}

	if _, err := db.Pool.Exec(context.Background(), `UPDATE auth_rate_limits SET window_started_at=now()-interval '2 minutes' WHERE bucket='test' AND key_hash=$1`, key); err != nil {
		t.Fatal(err)
	}
	ok, _, err := db.ConsumeRateLimit(context.Background(), "test", key, 5, time.Minute)
	if err != nil || !ok {
		t.Fatalf("reset attempt: allowed=%v err=%v", ok, err)
	}
	var attempts int
	if err := db.Pool.QueryRow(context.Background(), `SELECT attempts FROM auth_rate_limits WHERE bucket='test' AND key_hash=$1`, key).Scan(&attempts); err != nil || attempts != 1 {
		t.Fatalf("attempts=%d err=%v", attempts, err)
	}
}
