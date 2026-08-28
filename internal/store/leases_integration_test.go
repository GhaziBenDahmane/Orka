package store

import (
	"context"
	"os"
	"testing"
	"time"
)

func TestControllerLeaseFencesCompetingHolders(t *testing.T) {
	databaseURL := os.Getenv("DOCKYARD_TEST_DATABASE_URL")
	if databaseURL == "" {
		t.Skip("DOCKYARD_TEST_DATABASE_URL is not set")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	db, err := Open(ctx, databaseURL)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(db.Pool.Close)
	name := "test-lease-" + time.Now().Format("150405.000000000")
	if acquired, err := db.AcquireControllerLease(ctx, name, "controller-a", time.Minute); err != nil || !acquired {
		t.Fatalf("initial lease acquired=%v err=%v", acquired, err)
	}
	if acquired, err := db.AcquireControllerLease(ctx, name, "controller-b", time.Minute); err != nil || acquired {
		t.Fatalf("competing lease acquired=%v err=%v", acquired, err)
	}
	if acquired, err := db.AcquireControllerLease(ctx, name, "controller-a", time.Minute); err != nil || !acquired {
		t.Fatalf("renewal acquired=%v err=%v", acquired, err)
	}
	if _, err := db.Pool.Exec(ctx, `UPDATE controller_leases SET expires_at=now()-interval '1 second' WHERE name=$1`, name); err != nil {
		t.Fatal(err)
	}
	if acquired, err := db.AcquireControllerLease(ctx, name, "controller-b", time.Minute); err != nil || !acquired {
		t.Fatalf("takeover acquired=%v err=%v", acquired, err)
	}
}
