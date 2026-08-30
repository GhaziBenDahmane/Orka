package store

import (
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"testing"

	"github.com/google/uuid"
)

func TestAIAuditFindingLimitIsAtomic(t *testing.T) {
	pool, ctx := migrationTestPool(t)
	if err := Migrate(ctx, pool); err != nil {
		t.Fatal(err)
	}
	organizationID, accountID := uuid.New(), uuid.New()
	if _, err := pool.Exec(ctx, `INSERT INTO organizations(id,name,slug) VALUES($1,'AI limit',$2)`, organizationID, "ai-limit-"+organizationID.String()); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO service_accounts(id,organization_id,name,role) VALUES($1,$2,'auditor','auditor')`, accountID, organizationID); err != nil {
		t.Fatal(err)
	}
	db := &Store{Pool: pool}
	run, err := db.CreateAIAuditRun(ctx, organizationID, accountID, "concurrent", "v1", "test", json.RawMessage(`{}`))
	if err != nil {
		t.Fatal(err)
	}
	for index := 0; index < MaxAIAuditFindingsPerRun-1; index++ {
		_, err = db.AddAIAuditFinding(ctx, organizationID, accountID, AIAuditFinding{RunID: run.ID, Severity: "low", Category: "limit", Title: "Seed", Description: "Seed finding", Evidence: json.RawMessage(`{}`), Fingerprint: fmt.Sprintf("seed-%d", index)})
		if err != nil {
			t.Fatalf("seed finding %d: %v", index, err)
		}
	}

	const contenders = 12
	results := make(chan error, contenders)
	var wait sync.WaitGroup
	for index := 0; index < contenders; index++ {
		wait.Add(1)
		go func(index int) {
			defer wait.Done()
			_, addErr := db.AddAIAuditFinding(ctx, organizationID, accountID, AIAuditFinding{RunID: run.ID, Severity: "medium", Category: "limit", Title: "Concurrent", Description: "Concurrent finding", Evidence: json.RawMessage(`{}`), Fingerprint: fmt.Sprintf("concurrent-%d", index)})
			results <- addErr
		}(index)
	}
	wait.Wait()
	close(results)
	succeeded, limited := 0, 0
	for addErr := range results {
		switch {
		case addErr == nil:
			succeeded++
		case errors.Is(addErr, ErrAIAuditFindingLimit):
			limited++
		default:
			t.Fatalf("unexpected concurrent add error: %v", addErr)
		}
	}
	if succeeded != 1 || limited != contenders-1 {
		t.Fatalf("concurrent results succeeded=%d limited=%d", succeeded, limited)
	}
	var count int
	if err = pool.QueryRow(ctx, `SELECT count(*) FROM ai_audit_findings WHERE run_id=$1`, run.ID).Scan(&count); err != nil || count != MaxAIAuditFindingsPerRun {
		t.Fatalf("finding count=%d err=%v", count, err)
	}
	if _, err = db.AddAIAuditFinding(ctx, organizationID, accountID, AIAuditFinding{RunID: run.ID, Severity: "high", Category: "limit", Title: "Updated seed", Description: "Existing fingerprint", Evidence: json.RawMessage(`{}`), Fingerprint: "seed-0"}); err != nil {
		t.Fatalf("update existing fingerprint at limit: %v", err)
	}
	if err = pool.QueryRow(ctx, `SELECT count(*) FROM ai_audit_findings WHERE run_id=$1`, run.ID).Scan(&count); err != nil || count != MaxAIAuditFindingsPerRun {
		t.Fatalf("finding count after update=%d err=%v", count, err)
	}
}
