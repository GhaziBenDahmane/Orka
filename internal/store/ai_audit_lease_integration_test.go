package store

import (
	"encoding/json"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
)

func TestAIAuditRunLeasePreventsOverlapAndRecoversAfterExpiry(t *testing.T) {
	pool, ctx := migrationTestPool(t)
	if err := Migrate(ctx, pool); err != nil {
		t.Fatal(err)
	}
	organizationID, accountID := uuid.New(), uuid.New()
	if _, err := pool.Exec(ctx, `INSERT INTO organizations(id,name,slug) VALUES($1,'AI lease',$2)`, organizationID, "ai-lease-"+organizationID.String()); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO service_accounts(id,organization_id,name,role) VALUES($1,$2,'auditor','auditor')`, accountID, organizationID); err != nil {
		t.Fatal(err)
	}
	db := &Store{Pool: pool}
	first, err := db.CreateLeasedAIAuditRun(ctx, organizationID, accountID, "security", "v1", "test", json.RawMessage(`{}`), 2*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if lease := first.LeaseExpiresAt.Sub(first.StartedAt); lease < 119*time.Second || lease > 121*time.Second {
		t.Fatalf("lease duration=%s, want two minutes", lease)
	}
	if _, err = db.CreateAIAuditRun(ctx, organizationID, accountID, "security", "v2", "test", json.RawMessage(`{}`)); !errors.Is(err, ErrAIAuditRunActive) {
		t.Fatalf("overlapping audit error=%v, want ErrAIAuditRunActive", err)
	}
	assertAIAuditRunState(t, pool, ctx, first.ID, "running", "", false)

	if _, err = pool.Exec(ctx, `UPDATE ai_audit_runs SET lease_expires_at=now()-interval '1 second' WHERE id=$1`, first.ID); err != nil {
		t.Fatal(err)
	}
	second, err := db.CreateAIAuditRun(ctx, organizationID, accountID, "security", "v2", "test", json.RawMessage(`{}`))
	if err != nil {
		t.Fatal(err)
	}
	assertAIAuditRunState(t, pool, ctx, first.ID, "failed", "audit run lease expired before completion", true)
	if err = db.FinishAIAuditRun(ctx, organizationID, accountID, first.ID, "completed", "late completion"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("expired run accepted late completion: %v", err)
	}

	if _, err = pool.Exec(ctx, `UPDATE ai_audit_runs SET lease_expires_at=now()-interval '1 second' WHERE id=$1`, second.ID); err != nil {
		t.Fatal(err)
	}
	const contenders = 2
	results := make(chan error, contenders)
	var wait sync.WaitGroup
	for index := 0; index < contenders; index++ {
		wait.Add(1)
		go func() {
			defer wait.Done()
			_, createErr := db.CreateAIAuditRun(ctx, organizationID, accountID, "security", "v3", "test", json.RawMessage(`{}`))
			results <- createErr
		}()
	}
	wait.Wait()
	close(results)
	succeeded, active := 0, 0
	for createErr := range results {
		switch {
		case createErr == nil:
			succeeded++
		case errors.Is(createErr, ErrAIAuditRunActive):
			active++
		default:
			t.Fatalf("unexpected concurrent recovery error: %v", createErr)
		}
	}
	if succeeded != 1 || active != 1 {
		t.Fatalf("concurrent recovery succeeded=%d active=%d", succeeded, active)
	}
	var running int
	if err = pool.QueryRow(ctx, `SELECT count(*) FROM ai_audit_runs WHERE service_account_id=$1 AND agent_name='security' AND status='running'`, accountID).Scan(&running); err != nil || running != 1 {
		t.Fatalf("active audit count=%d err=%v", running, err)
	}
}
