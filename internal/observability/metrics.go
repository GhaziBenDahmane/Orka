package observability

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/jackc/pgx/v5"
)

var durationBuckets = [...]float64{0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10, 30, 60, 300, 900, 2700}

type Queryer interface {
	Query(context.Context, string, ...any) (pgx.Rows, error)
	QueryRow(context.Context, string, ...any) pgx.Row
}

type observation struct {
	Count   uint64
	Sum     float64
	Buckets [len(durationBuckets)]uint64
}

type Metrics struct {
	mu           sync.RWMutex
	http         map[string]*observation
	operations   map[string]*observation
	certificates map[string]time.Time
}

func NewMetrics() *Metrics {
	return &Metrics{http: make(map[string]*observation), operations: make(map[string]*observation), certificates: make(map[string]time.Time)}
}

func (m *Metrics) SetCertificateExpiry(name string, expiresAt time.Time) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if expiresAt.IsZero() {
		delete(m.certificates, name)
		return
	}
	m.certificates[name] = expiresAt
}

func (m *Metrics) ObserveHTTP(method, route string, status int, elapsed time.Duration) {
	if route == "" {
		route = "unmatched"
	}
	m.observe(m.http, strings.Join([]string{method, route, strconv.Itoa(status)}, "\x00"), elapsed)
}

func (m *Metrics) ObserveOperation(kind, status string, elapsed time.Duration) {
	m.observe(m.operations, kind+"\x00"+status, elapsed)
}

func (m *Metrics) observe(target map[string]*observation, key string, elapsed time.Duration) {
	seconds := elapsed.Seconds()
	m.mu.Lock()
	o := target[key]
	if o == nil {
		o = &observation{}
		target[key] = o
	}
	o.Count++
	o.Sum += seconds
	for i, upper := range durationBuckets {
		if seconds <= upper {
			o.Buckets[i]++
		}
	}
	m.mu.Unlock()
}

func (m *Metrics) Handler(db Queryer) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
		defer cancel()
		var output bytes.Buffer
		if err := m.renderDatabase(ctx, &output, db); err != nil {
			http.Error(w, "metrics unavailable", http.StatusServiceUnavailable)
			return
		}
		m.renderRuntime(&output)
		fmt.Fprintln(&output, "# HELP dockyard_up Whether the controller can serve metrics.")
		fmt.Fprintln(&output, "# TYPE dockyard_up gauge")
		fmt.Fprintln(&output, "dockyard_up 1")
		w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
		_, _ = w.Write(output.Bytes())
	})
}

func (m *Metrics) renderDatabase(ctx context.Context, w io.Writer, db Queryer) error {
	type family struct {
		name, help, query string
		labels            []string
	}
	families := []family{
		{"dockyard_jobs", "Durable jobs by kind and state.", `SELECT kind,status,count(*)::float8 FROM jobs GROUP BY kind,status`, []string{"kind", "status"}},
		{"dockyard_job_oldest_age_seconds", "Age of the oldest durable job by kind and state.", `SELECT kind,status,COALESCE(extract(epoch FROM now()-min(created_at)),0)::float8 FROM jobs GROUP BY kind,status`, []string{"kind", "status"}},
		{"dockyard_deployments", "Deployments by state.", `SELECT status,count(*)::float8 FROM deployments GROUP BY status`, []string{"status"}},
		{"dockyard_database_backups", "Database backups by state.", `SELECT status,count(*)::float8 FROM database_backups GROUP BY status`, []string{"status"}},
		{"dockyard_database_restores", "Database restores by kind and state.", `SELECT kind,status,count(*)::float8 FROM database_restores GROUP BY kind,status`, []string{"kind", "status"}},
		{"dockyard_database_migrations", "Dokploy native database migrations by engine and state.", `SELECT source_engine,status,count(*)::float8 FROM database_migrations GROUP BY source_engine,status`, []string{"engine", "status"}},
		{"dockyard_deployment_last_duration_seconds", "Duration of the most recently finished deployment by final state.", `SELECT DISTINCT ON (status) status,extract(epoch FROM finished_at-started_at)::float8 FROM deployments WHERE started_at IS NOT NULL AND finished_at IS NOT NULL ORDER BY status,finished_at DESC`, []string{"status"}},
		{"dockyard_database_backup_last_success_age_seconds", "Age of the most recent successful database backup.", `SELECT 'all',extract(epoch FROM now()-max(finished_at))::float8 FROM database_backups WHERE status='succeeded' HAVING max(finished_at) IS NOT NULL`, []string{"scope"}},
		{"dockyard_database_restore_last_success_age_seconds", "Age of the most recent successful restore by kind.", `SELECT kind,extract(epoch FROM now()-max(finished_at))::float8 FROM database_restores WHERE status='succeeded' GROUP BY kind`, []string{"kind"}},
		{"dockyard_database_migration_active_age_seconds", "Age of each queued or running Dokploy database migration.", `SELECT database_instance_id::text,extract(epoch FROM now()-created_at)::float8 FROM database_migrations WHERE status IN ('queued','running')`, []string{"database"}},
		{"dockyard_database_migration_last_duration_seconds", "Duration of the most recently completed Dokploy database migration by engine and final state.", `SELECT DISTINCT ON (source_engine,status) source_engine,status,extract(epoch FROM finished_at-started_at)::float8 FROM database_migrations WHERE started_at IS NOT NULL AND finished_at IS NOT NULL ORDER BY source_engine,status,finished_at DESC`, []string{"engine", "status"}},
		{"dockyard_database_migration_last_failure_age_seconds", "Age of the most recent failed Dokploy database migration.", `SELECT 'all',extract(epoch FROM now()-max(finished_at))::float8 FROM database_migrations WHERE status='failed' HAVING max(finished_at) IS NOT NULL`, []string{"scope"}},
		{"dockyard_restore_drill_last_duration_seconds", "Duration of the most recent successful restore drill for each database.", `SELECT DISTINCT ON (d.id) d.id::text,extract(epoch FROM r.finished_at-r.started_at)::float8 FROM database_restores r JOIN database_backups b ON b.id=r.database_backup_id JOIN database_instances d ON d.id=b.database_instance_id WHERE r.kind='drill' AND r.status='succeeded' AND r.started_at IS NOT NULL AND r.finished_at IS NOT NULL ORDER BY d.id,r.finished_at DESC`, []string{"database"}},
		{"dockyard_restore_drill_overdue", "Whether a database with restore verification enabled lacks a successful drill within twice its backup interval.", `SELECT d.id::text,CASE WHEN max(r.finished_at) IS NULL OR max(r.finished_at)<now()-(greatest(bp.interval_seconds*2,86400)::text||' seconds')::interval THEN 1::float8 ELSE 0::float8 END FROM backup_policies bp JOIN database_instances d ON d.id=bp.database_instance_id LEFT JOIN database_backups b ON b.database_instance_id=d.id LEFT JOIN database_restores r ON r.database_backup_id=b.id AND r.kind='drill' AND r.status='succeeded' WHERE bp.enabled AND bp.verify_restore GROUP BY d.id,bp.interval_seconds`, []string{"database"}},
		{"dockyard_maintenance_scopes", "Resource scopes currently in maintenance mode.", `SELECT scope_type,count(*)::float8 FROM resource_policies WHERE maintenance_enabled GROUP BY scope_type`, []string{"scope_type"}},
		{"dockyard_notification_deliveries", "Notification deliveries by event and state.", `SELECT event_type,status,count(*)::float8 FROM notification_deliveries GROUP BY event_type,status`, []string{"event", "status"}},
		{"dockyard_clusters", "Registered clusters by lifecycle state.", `SELECT state,count(*)::float8 FROM clusters GROUP BY state`, []string{"state"}},
		{"dockyard_cluster_commands", "Remote cluster commands by state and kind.", `SELECT kind,status,count(*)::float8 FROM cluster_commands GROUP BY kind,status`, []string{"kind", "status"}},
		{"dockyard_cluster_heartbeat_age_seconds", "Age of the last heartbeat from each active remote cluster.", `SELECT organization_id::text,slug,extract(epoch FROM now()-last_seen_at)::float8 FROM clusters WHERE state IN ('active','draining') AND last_seen_at IS NOT NULL`, []string{"organization", "cluster"}},
		{"dockyard_cluster_heartbeat_missing", "Whether an active remote cluster has never heartbeated or has been silent for more than two minutes.", `SELECT organization_id::text,slug,CASE WHEN last_seen_at IS NULL OR last_seen_at<now()-interval '2 minutes' THEN 1::float8 ELSE 0::float8 END FROM clusters WHERE state IN ('active','draining')`, []string{"organization", "cluster"}},
		{"dockyard_cluster_agent_update_failure", "Whether a remote cluster reports a paused or rolled-back agent update.", `SELECT organization_id::text,slug,agent_update_state,1::float8 FROM clusters WHERE state IN ('active','draining') AND agent_update_state IN ('paused','rollback_started','rollback_paused','rollback_completed')`, []string{"organization", "cluster", "state"}},
		{"dockyard_agent_upgrade_verification_overdue", "Agent upgrades still awaiting target-image confirmation after their verification deadline.", `SELECT c.organization_id::text,c.slug,count(*)::float8 FROM cluster_commands command JOIN clusters c ON c.id=command.cluster_id WHERE command.kind='agent.upgrade' AND command.status='verifying' AND command.run_after<=now() GROUP BY c.organization_id,c.slug`, []string{"organization", "cluster"}},
		{"dockyard_agent_upgrade_active_age_seconds", "Age of the active agent upgrade for each remote cluster.", `SELECT c.organization_id::text,c.slug,command.status,extract(epoch FROM now()-command.created_at)::float8 FROM cluster_commands command JOIN clusters c ON c.id=command.cluster_id WHERE command.kind='agent.upgrade' AND command.status IN ('pending','leased','verifying')`, []string{"organization", "cluster", "status"}},
		{"dockyard_cluster_certificate_expiry_seconds", "Seconds until the active remote cluster certificate expires.", `SELECT organization_id::text,slug,extract(epoch FROM certificate_not_after-now())::float8 FROM clusters WHERE state IN ('active','draining') AND certificate_not_after IS NOT NULL`, []string{"organization", "cluster"}},
		{"dockyard_cluster_certificate_rotation_pending_age_seconds", "Age of an issued agent certificate that has not authenticated successfully yet.", `SELECT organization_id::text,slug,extract(epoch FROM now()-pending_certificate_created_at)::float8 FROM clusters WHERE state IN ('active','draining') AND pending_certificate_serial<>'' AND pending_certificate_created_at IS NOT NULL`, []string{"organization", "cluster"}},
		{"dockyard_controller_leases", "Controller singleton leases by validity.", `SELECT name,CASE WHEN expires_at>now() THEN 'active' ELSE 'expired' END,count(*)::float8 FROM controller_leases GROUP BY name,CASE WHEN expires_at>now() THEN 'active' ELSE 'expired' END`, []string{"name", "state"}},
		{"dockyard_service_reconciliation", "Compose services by observed reconciliation state.", `SELECT state,count(*)::float8 FROM service_reconciliations GROUP BY state`, []string{"state"}},
		{"dockyard_service_reconciliation_age_seconds", "Age of the most recent reconciliation observation for each service.", `SELECT compose_service_id::text,extract(epoch FROM now()-last_checked_at)::float8 FROM service_reconciliations`, []string{"service"}},
		{"dockyard_ai_audit_runs", "AI audit runs by lifecycle state.", `SELECT states.status,count(r.id)::float8 FROM (VALUES ('running'),('completed'),('failed')) states(status) LEFT JOIN ai_audit_runs r ON r.status=states.status GROUP BY states.status`, []string{"status"}},
		{"dockyard_ai_audit_last_completed_age_seconds", "Age of the most recent completed AI audit for each organization.", `SELECT organization_id::text,greatest(extract(epoch FROM now()-max(completed_at)),0)::float8 FROM ai_audit_runs WHERE status='completed' AND completed_at IS NOT NULL GROUP BY organization_id`, []string{"organization"}},
		{"dockyard_ai_audit_last_failure_age_seconds", "Age of the most recent failed AI audit for each organization.", `SELECT organization_id::text,greatest(extract(epoch FROM now()-max(completed_at)),0)::float8 FROM ai_audit_runs WHERE status='failed' AND completed_at IS NOT NULL GROUP BY organization_id`, []string{"organization"}},
		{"dockyard_ai_audit_running_age_seconds", "Age of the oldest running AI audit for each organization.", `SELECT organization_id::text,greatest(extract(epoch FROM now()-min(started_at)),0)::float8 FROM ai_audit_runs WHERE status='running' GROUP BY organization_id`, []string{"organization"}},
		{"dockyard_ai_audit_completion_overdue", "Whether an organization with an active auditor token has lacked a completed AI audit for more than 48 hours.", `WITH auditor_organizations AS (SELECT a.organization_id,min(t.created_at) AS enabled_at FROM service_accounts a JOIN service_account_tokens t ON t.service_account_id=a.id AND t.revoked_at IS NULL AND t.expires_at>now() WHERE a.enabled AND a.role='auditor' GROUP BY a.organization_id), completions AS (SELECT organization_id,max(completed_at) AS completed_at FROM ai_audit_runs WHERE status='completed' AND completed_at IS NOT NULL GROUP BY organization_id) SELECT a.organization_id::text,CASE WHEN COALESCE(c.completed_at,a.enabled_at)<now()-interval '48 hours' THEN 1::float8 ELSE 0::float8 END FROM auditor_organizations a LEFT JOIN completions c ON c.organization_id=a.organization_id`, []string{"organization"}},
	}
	for _, f := range families {
		fmt.Fprintf(w, "# HELP %s %s\n# TYPE %s gauge\n", f.name, f.help, f.name)
		rows, err := db.Query(ctx, f.query)
		if err != nil {
			return err
		}
		for rows.Next() {
			values := make([]string, len(f.labels))
			dest := make([]any, 0, len(values)+1)
			for i := range values {
				dest = append(dest, &values[i])
			}
			var value float64
			dest = append(dest, &value)
			if err := rows.Scan(dest...); err != nil {
				rows.Close()
				return err
			}
			fmt.Fprintf(w, "%s%s %g\n", f.name, labels(f.labels, values), value)
		}
		if err := rows.Err(); err != nil {
			rows.Close()
			return err
		}
		rows.Close()
	}
	var stale float64
	if err := db.QueryRow(ctx, `SELECT count(*)::float8 FROM jobs WHERE status='running' AND locked_at<now()-interval '30 seconds'`).Scan(&stale); err != nil {
		return err
	}
	fmt.Fprintln(w, "# HELP dockyard_job_stale_leases Running jobs whose worker heartbeat is stale.")
	fmt.Fprintln(w, "# TYPE dockyard_job_stale_leases gauge")
	fmt.Fprintf(w, "dockyard_job_stale_leases %g\n", stale)
	return nil
}

func (m *Metrics) renderRuntime(w io.Writer) {
	m.mu.RLock()
	httpItems := clone(m.http)
	operationItems := clone(m.operations)
	certificateExpiries := make(map[string]time.Time, len(m.certificates))
	for name, expiresAt := range m.certificates {
		certificateExpiries[name] = expiresAt
	}
	m.mu.RUnlock()
	renderCounter(w, "dockyard_http_requests_total", "HTTP requests by method, route, and status.", httpItems, []string{"method", "route", "status"})
	renderHistogram(w, "dockyard_http_request_duration_seconds", "HTTP request latency.", httpItems, []string{"method", "route", "status"})
	renderCounter(w, "dockyard_operations_total", "Completed background operations by kind and status.", operationItems, []string{"kind", "status"})
	renderHistogram(w, "dockyard_operation_duration_seconds", "Background operation latency.", operationItems, []string{"kind", "status"})
	fmt.Fprintln(w, "# HELP dockyard_control_plane_certificate_expiry_seconds Seconds until a configured control-plane certificate expires.")
	fmt.Fprintln(w, "# TYPE dockyard_control_plane_certificate_expiry_seconds gauge")
	names := make([]string, 0, len(certificateExpiries))
	for name := range certificateExpiries {
		names = append(names, name)
	}
	sort.Strings(names)
	now := time.Now()
	for _, name := range names {
		fmt.Fprintf(w, "dockyard_control_plane_certificate_expiry_seconds%s %g\n", labels([]string{"certificate"}, []string{name}), certificateExpiries[name].Sub(now).Seconds())
	}
}

func clone(source map[string]*observation) map[string]observation {
	result := make(map[string]observation, len(source))
	for key, value := range source {
		result[key] = *value
	}
	return result
}

func renderHistogram(w io.Writer, name, help string, items map[string]observation, labelNames []string) {
	fmt.Fprintf(w, "# HELP %s %s\n# TYPE %s histogram\n", name, help, name)
	keys := make([]string, 0, len(items))
	for key := range items {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		o := items[key]
		values := strings.Split(key, "\x00")
		for i, upper := range durationBuckets {
			fmt.Fprintf(w, "%s_bucket%s %d\n", name, labels(append(labelNames, "le"), append(values, strconv.FormatFloat(upper, 'g', -1, 64))), o.Buckets[i])
		}
		fmt.Fprintf(w, "%s_bucket%s %d\n", name, labels(append(labelNames, "le"), append(values, "+Inf")), o.Count)
		fmt.Fprintf(w, "%s_sum%s %g\n", name, labels(labelNames, values), o.Sum)
		fmt.Fprintf(w, "%s_count%s %d\n", name, labels(labelNames, values), o.Count)
	}
}

func renderCounter(w io.Writer, name, help string, items map[string]observation, labelNames []string) {
	fmt.Fprintf(w, "# HELP %s %s\n# TYPE %s counter\n", name, help, name)
	keys := make([]string, 0, len(items))
	for key := range items {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		fmt.Fprintf(w, "%s%s %d\n", name, labels(labelNames, strings.Split(key, "\x00")), items[key].Count)
	}
}

func labels(names, values []string) string {
	parts := make([]string, len(names))
	for i := range names {
		parts[i] = names[i] + "=\"" + prometheusEscape(values[i]) + "\""
	}
	return "{" + strings.Join(parts, ",") + "}"
}

func prometheusEscape(value string) string {
	value = strings.ReplaceAll(value, `\`, `\\`)
	value = strings.ReplaceAll(value, "\n", `\n`)
	return strings.ReplaceAll(value, `"`, `\"`)
}
