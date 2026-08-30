package store

import (
	"sync"
	"testing"

	"github.com/google/uuid"
)

func TestReconciliationQueuesImmutableRepairAndSuppressesDuplicates(t *testing.T) {
	pool, ctx := migrationTestPool(t)
	if err := Migrate(ctx, pool); err != nil {
		t.Fatal(err)
	}
	db := &Store{Pool: pool}
	organizationID, otherOrganizationID := uuid.New(), uuid.New()
	projectID, environmentID, serviceID := uuid.New(), uuid.New(), uuid.New()
	statements := []struct {
		query string
		args  []any
	}{
		{`INSERT INTO organizations(id,name,slug) VALUES($1,'Reconcile',$2),($3,'Other',$4)`, []any{organizationID, "reconcile-" + organizationID.String(), otherOrganizationID, "other-" + otherOrganizationID.String()}},
		{`INSERT INTO projects(id,organization_id,name,slug) VALUES($1,$2,'Project','project')`, []any{projectID, organizationID}},
		{`INSERT INTO environments(id,project_id,name,slug) VALUES($1,$2,'Production','production')`, []any{environmentID, projectID}},
		{`INSERT INTO compose_services(id,environment_id,name,slug,stack_name,compose_yaml,encrypted_env,revision) VALUES($1,$2,'API','api',$3,'services: {api: {image: desired:new}}','new-secret',7)`, []any{serviceID, environmentID, "reconcile-" + serviceID.String()}},
		{`INSERT INTO deployments(id,compose_service_id,revision,compose_snapshot,effective_compose,env_snapshot,status,trigger,finished_at) VALUES($1,$2,4,'services: {api: {image: source:old}}','services: {api: {image: registry/app@sha256:old}}','old-secret','succeeded','manual',now())`, []any{uuid.New(), serviceID}},
	}
	for _, statement := range statements {
		if _, err := pool.Exec(ctx, statement.query, statement.args...); err != nil {
			t.Fatal(err)
		}
	}
	candidates, err := db.ListReconciliationCandidates(ctx, 10)
	if err != nil || len(candidates) != 1 || candidates[0].ServiceID != serviceID {
		t.Fatalf("candidates=%#v err=%v", candidates, err)
	}
	if repair, err := db.RecordReconciliation(ctx, candidates[0], "missing", "not found"); err != nil || repair != nil {
		t.Fatalf("first observation repair=%#v err=%v", repair, err)
	}
	var wg sync.WaitGroup
	repairs := make(chan *Deployment, 2)
	errorsSeen := make(chan error, 2)
	for range 2 {
		wg.Add(1)
		go func() {
			deployment, recordErr := db.RecordReconciliation(ctx, candidates[0], "missing", "not found")
			repairs <- deployment
			errorsSeen <- recordErr
			wg.Done()
		}()
	}
	wg.Wait()
	close(repairs)
	close(errorsSeen)
	for recordErr := range errorsSeen {
		if recordErr != nil {
			t.Fatal(recordErr)
		}
	}
	var repair *Deployment
	queued := 0
	for deployment := range repairs {
		if deployment != nil {
			repair = deployment
			queued++
		}
	}
	if queued != 1 || repair.Trigger != "reconcile" || repair.Revision != 4 {
		t.Fatalf("concurrent observations queued=%d repair=%#v", queued, repair)
	}
	var compose, encrypted string
	if err = pool.QueryRow(ctx, `SELECT compose_yaml,encrypted_env FROM compose_services WHERE id=$1`, serviceID).Scan(&compose, &encrypted); err != nil || compose != "services: {api: {image: desired:new}}" || encrypted != "new-secret" {
		t.Fatalf("desired state changed: compose=%q env=%q err=%v", compose, encrypted, err)
	}
	var snapshot, effective, env string
	if err = pool.QueryRow(ctx, `SELECT compose_snapshot,effective_compose,env_snapshot FROM deployments WHERE id=$1`, repair.ID).Scan(&snapshot, &effective, &env); err != nil || snapshot != "services: {api: {image: registry/app@sha256:old}}" || effective != snapshot || env != "old-secret" {
		t.Fatalf("repair snapshot=%q effective=%q env=%q err=%v", snapshot, effective, env, err)
	}
	var auditEvents int
	if err = pool.QueryRow(ctx, `SELECT count(*) FROM audit_events WHERE organization_id=$1 AND action='service.reconcile.queued' AND resource_id=$2`, organizationID, serviceID.String()).Scan(&auditEvents); err != nil || auditEvents != 1 {
		t.Fatalf("repair audit events=%d err=%v", auditEvents, err)
	}
	if duplicate, err := db.RecordReconciliation(ctx, candidates[0], "degraded", "still degraded"); err != nil || duplicate != nil {
		t.Fatalf("duplicate repair=%#v err=%v", duplicate, err)
	}
	items, err := db.ListServiceReconciliations(ctx, organizationID)
	if err != nil || len(items) != 1 || items[0].State != "repairing" || items[0].ConsecutiveFailures != 4 || items[0].LastRepairAt == nil {
		t.Fatalf("reconciliation=%#v err=%v", items, err)
	}
	item, err := db.GetServiceReconciliation(ctx, organizationID, serviceID)
	if err != nil || item == nil || item.ComposeServiceID != serviceID || item.State != "repairing" || item.ConsecutiveFailures != 4 || item.LastRepairAt == nil {
		t.Fatalf("service reconciliation=%#v err=%v", item, err)
	}
	other, err := db.ListServiceReconciliations(ctx, otherOrganizationID)
	if err != nil || len(other) != 0 {
		t.Fatalf("cross-tenant reconciliation=%#v err=%v", other, err)
	}
	otherItem, err := db.GetServiceReconciliation(ctx, otherOrganizationID, serviceID)
	if err != nil || otherItem != nil {
		t.Fatalf("cross-tenant service reconciliation=%#v err=%v", otherItem, err)
	}
	requested, err := db.QueueDeployment(ctx, organizationID, serviceID, uuid.Nil, "manual")
	if err != nil {
		t.Fatal(err)
	}
	var repairStatus, repairJobStatus, requestedResourceKey string
	if err = pool.QueryRow(ctx, `SELECT d.status,j.status FROM deployments d JOIN jobs j ON j.payload->>'deploymentId'=d.id::text WHERE d.id=$1`, repair.ID).Scan(&repairStatus, &repairJobStatus); err != nil {
		t.Fatal(err)
	}
	if err = pool.QueryRow(ctx, `SELECT resource_key FROM jobs WHERE payload->>'deploymentId'=$1`, requested.ID.String()).Scan(&requestedResourceKey); err != nil {
		t.Fatal(err)
	}
	if repairStatus != "cancelled" || repairJobStatus != "cancelled" || requestedResourceKey != "service:"+serviceID.String() {
		t.Fatalf("supersession repair=%s job=%s requested-key=%q", repairStatus, repairJobStatus, requestedResourceKey)
	}
}

func TestReconciliationHonorsMaintenanceAndNeedsEffectiveSourceSnapshot(t *testing.T) {
	pool, ctx := migrationTestPool(t)
	if err := Migrate(ctx, pool); err != nil {
		t.Fatal(err)
	}
	db := &Store{Pool: pool}
	organizationID, projectID, environmentID, serviceID := uuid.New(), uuid.New(), uuid.New(), uuid.New()
	statements := []struct {
		query string
		args  []any
	}{
		{`INSERT INTO organizations(id,name,slug) VALUES($1,'Reconcile policy',$2)`, []any{organizationID, "reconcile-policy-" + organizationID.String()}},
		{`INSERT INTO projects(id,organization_id,name,slug) VALUES($1,$2,'Project','project')`, []any{projectID, organizationID}},
		{`INSERT INTO environments(id,project_id,name,slug) VALUES($1,$2,'Production','production')`, []any{environmentID, projectID}},
		{`INSERT INTO compose_services(id,environment_id,name,slug,stack_name,compose_yaml) VALUES($1,$2,'API','api',$3,'services: {api: {image: source}}')`, []any{serviceID, environmentID, "reconcile-policy-" + serviceID.String()}},
		{`INSERT INTO application_sources(compose_service_id,repository_url,target_service,registry_image) VALUES($1,'https://example.test/repo','api','registry.example/app')`, []any{serviceID}},
		{`INSERT INTO deployments(id,compose_service_id,revision,compose_snapshot,status,trigger,finished_at) VALUES($1,$2,1,'services: {api: {image: source}}','succeeded','manual',now())`, []any{uuid.New(), serviceID}},
		{`INSERT INTO resource_policies(organization_id,scope_type,scope_id,maintenance_enabled) VALUES($1,'environment',$2,true)`, []any{organizationID, environmentID}},
	}
	for _, statement := range statements {
		if _, err := pool.Exec(ctx, statement.query, statement.args...); err != nil {
			t.Fatal(err)
		}
	}
	candidate := ReconciliationCandidate{ServiceID: serviceID, OrganizationID: organizationID, StackName: "test"}
	for i := 0; i < 2; i++ {
		if repair, err := db.RecordReconciliation(ctx, candidate, "missing", "missing"); err != nil || repair != nil {
			t.Fatalf("maintenance repair=%#v err=%v", repair, err)
		}
	}
	if _, err := pool.Exec(ctx, `UPDATE resource_policies SET maintenance_enabled=false WHERE scope_id=$1`, environmentID); err != nil {
		t.Fatal(err)
	}
	if repair, err := db.RecordReconciliation(ctx, candidate, "missing", "missing"); err != nil || repair != nil {
		t.Fatalf("source without effective snapshot repair=%#v err=%v", repair, err)
	}
	var detail string
	if err := pool.QueryRow(ctx, `SELECT detail FROM service_reconciliations WHERE compose_service_id=$1`, serviceID).Scan(&detail); err != nil || detail == "" {
		t.Fatalf("detail=%q err=%v", detail, err)
	}
	if _, err := pool.Exec(ctx, `UPDATE deployments SET effective_compose='services: {api: {image: registry.example/app@sha256:known}}' WHERE compose_service_id=$1`, serviceID); err != nil {
		t.Fatal(err)
	}
	if _, err := db.QueueDeployment(ctx, organizationID, serviceID, uuid.Nil, "manual"); err != nil {
		t.Fatal(err)
	}
	if repair, err := db.RecordReconciliation(ctx, candidate, "missing", "deployment active"); err != nil || repair != nil {
		t.Fatalf("active deployment repair=%#v err=%v", repair, err)
	}
	var deployments int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM deployments WHERE compose_service_id=$1 AND trigger='reconcile'`, serviceID).Scan(&deployments); err != nil || deployments != 0 {
		t.Fatalf("unsafe repairs=%d err=%v", deployments, err)
	}
}

func TestRemoteReconciliationWaitsForFreshCapacityAfterPartition(t *testing.T) {
	pool, ctx := migrationTestPool(t)
	if err := Migrate(ctx, pool); err != nil {
		t.Fatal(err)
	}
	db := &Store{Pool: pool}
	organizationID, projectID, environmentID, serviceID, clusterID := uuid.New(), uuid.New(), uuid.New(), uuid.New(), uuid.New()
	statements := []struct {
		query string
		args  []any
	}{
		{`INSERT INTO organizations(id,name,slug) VALUES($1,'Remote reconcile',$2)`, []any{organizationID, "remote-reconcile-" + organizationID.String()}},
		{`INSERT INTO projects(id,organization_id,name,slug) VALUES($1,$2,'Project','project')`, []any{projectID, organizationID}},
		{`INSERT INTO clusters(id,organization_id,name,slug,state,labels,capacity,last_seen_at) VALUES($1,$2,'Remote','remote','active','{"region":"eu"}', '{"schedulableNodes":3,"nanoCpus":6000000000,"memoryBytes":12884901888}',now())`, []any{clusterID, organizationID}},
		{`INSERT INTO environments(id,project_id,cluster_id,name,slug,placement_selector,minimum_nodes,minimum_nano_cpus,minimum_memory_bytes) VALUES($1,$2,$3,'Production','production','{"region":"eu"}',3,6000000000,12884901888)`, []any{environmentID, projectID, clusterID}},
		{`INSERT INTO compose_services(id,environment_id,name,slug,stack_name,compose_yaml,revision) VALUES($1,$2,'API','api',$3,'services: {api: {image: desired:new}}',2)`, []any{serviceID, environmentID, "remote-reconcile-" + serviceID.String()}},
		{`INSERT INTO deployments(id,compose_service_id,revision,compose_snapshot,effective_compose,status,trigger,finished_at) VALUES($1,$2,1,'services: {api: {image: old}}','services: {api: {image: registry/app@sha256:old}}','succeeded','manual',now())`, []any{uuid.New(), serviceID}},
	}
	for _, statement := range statements {
		if _, err := pool.Exec(ctx, statement.query, statement.args...); err != nil {
			t.Fatal(err)
		}
	}
	candidates, err := db.ListReconciliationCandidates(ctx, 10)
	if err != nil || len(candidates) != 1 || candidates[0].ServiceID != serviceID {
		t.Fatalf("fresh candidates=%#v err=%v", candidates, err)
	}
	candidate := candidates[0]
	if repair, err := db.RecordReconciliation(ctx, candidate, "missing", "first observation"); err != nil || repair != nil {
		t.Fatalf("first observation repair=%#v err=%v", repair, err)
	}
	if _, err = pool.Exec(ctx, `UPDATE clusters SET last_seen_at=now()-interval '10 minutes' WHERE id=$1`, clusterID); err != nil {
		t.Fatal(err)
	}
	if candidates, err = db.ListReconciliationCandidates(ctx, 10); err != nil || len(candidates) != 0 {
		t.Fatalf("partitioned candidates=%#v err=%v", candidates, err)
	}
	if repair, err := db.RecordReconciliation(ctx, candidate, "missing", "partitioned"); err != nil || repair != nil {
		t.Fatalf("partition repair=%#v err=%v", repair, err)
	}
	if _, err = pool.Exec(ctx, `UPDATE clusters SET last_seen_at=now(),capacity=jsonb_set(capacity,'{schedulableNodes}','2') WHERE id=$1`, clusterID); err != nil {
		t.Fatal(err)
	}
	if repair, err := db.RecordReconciliation(ctx, candidate, "degraded", "capacity unavailable"); err != nil || repair != nil {
		t.Fatalf("capacity repair=%#v err=%v", repair, err)
	}
	if _, err = pool.Exec(ctx, `UPDATE clusters SET capacity=jsonb_set(capacity,'{schedulableNodes}','3') WHERE id=$1`, clusterID); err != nil {
		t.Fatal(err)
	}
	repair, err := db.RecordReconciliation(ctx, candidate, "degraded", "capacity restored")
	if err != nil || repair == nil || repair.Trigger != "reconcile" || repair.Revision != 1 {
		t.Fatalf("recovered repair=%#v err=%v", repair, err)
	}
	var repairCount int
	if err = pool.QueryRow(ctx, `SELECT count(*) FROM deployments WHERE compose_service_id=$1 AND trigger='reconcile'`, serviceID).Scan(&repairCount); err != nil || repairCount != 1 {
		t.Fatalf("repair deployments=%d err=%v", repairCount, err)
	}
}
