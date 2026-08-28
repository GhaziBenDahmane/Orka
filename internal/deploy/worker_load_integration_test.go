package deploy

import (
	"errors"
	"fmt"
	"io"
	"log/slog"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/bendahma/dokploy-go/internal/store"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

func TestConcurrentWorkersClaimEveryJobExactlyOnce(t *testing.T) {
	db, ctx := recoveryTestStore(t)
	const jobCount = 500
	rows := make([][]any, jobCount)
	for i := range rows {
		rows[i] = []any{uuid.New(), "test.load", []byte(fmt.Sprintf(`{"sequence":%d}`, i))}
	}
	inserted, err := db.Pool.CopyFrom(ctx, pgx.Identifier{"jobs"}, []string{"id", "kind", "payload"}, pgx.CopyFromRows(rows))
	if err != nil || inserted != jobCount {
		t.Fatalf("seed jobs inserted=%d err=%v", inserted, err)
	}

	const workerCount = 12
	var completed atomic.Int64
	var seen sync.Map
	var workerMu sync.Mutex
	workersUsed := map[string]int{}
	errorsFound := make(chan error, workerCount)
	var group sync.WaitGroup
	for i := 0; i < workerCount; i++ {
		workerID := fmt.Sprintf("load-worker-%02d", i)
		group.Add(1)
		go func() {
			defer group.Done()
			worker := Worker{Store: db, ID: workerID, Logger: slog.New(slog.NewTextHandler(io.Discard, nil))}
			for {
				claimed, claimErr := worker.claim(ctx)
				if errors.Is(claimErr, store.ErrNotFound) {
					return
				}
				if claimErr != nil {
					errorsFound <- fmt.Errorf("%s claim: %w", workerID, claimErr)
					return
				}
				if _, duplicate := seen.LoadOrStore(claimed.ID, workerID); duplicate {
					errorsFound <- fmt.Errorf("job %s was claimed more than once", claimed.ID)
					return
				}
				// Keep claims overlapping so SKIP LOCKED is exercised under contention.
				time.Sleep(time.Millisecond)
				if finishErr := worker.finish(ctx, claimed, nil); finishErr != nil {
					errorsFound <- fmt.Errorf("%s finish %s: %w", workerID, claimed.ID, finishErr)
					return
				}
				completed.Add(1)
				workerMu.Lock()
				workersUsed[workerID]++
				workerMu.Unlock()
			}
		}()
	}
	group.Wait()
	close(errorsFound)
	for workerErr := range errorsFound {
		t.Error(workerErr)
	}
	if t.Failed() {
		return
	}
	if got := completed.Load(); got != jobCount {
		t.Fatalf("completed jobs=%d, want %d", got, jobCount)
	}
	if len(workersUsed) < 2 {
		t.Fatalf("queue did not distribute work: %#v", workersUsed)
	}

	var total, succeeded, attempts, leased int
	if err = db.Pool.QueryRow(ctx, `SELECT count(*),count(*) FILTER (WHERE status='succeeded'),sum(attempts),count(*) FILTER (WHERE lease_id IS NOT NULL) FROM jobs`).Scan(&total, &succeeded, &attempts, &leased); err != nil {
		t.Fatal(err)
	}
	if total != jobCount || succeeded != jobCount || attempts != jobCount || leased != 0 {
		t.Fatalf("queue totals total=%d succeeded=%d attempts=%d leased=%d", total, succeeded, attempts, leased)
	}
}
