package store

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"sort"
	"strings"

	"github.com/bendahma/dokploy-go/internal/cryptox"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

const masterKeyRotationLock int64 = 721046141

// MasterKeyRotationReport contains only non-secret operational metadata.
type MasterKeyRotationReport struct {
	DryRun         bool           `json:"dryRun"`
	Validated      int            `json:"validated"`
	Rotated        int            `json:"rotated"`
	ByTable        map[string]int `json:"byTable"`
	OldFingerprint string         `json:"oldFingerprint"`
	NewFingerprint string         `json:"newFingerprint"`
}

type encryptedColumnSpec struct {
	table         string
	column        string
	idColumn      string
	contextColumn string
	contextKind   string
	legacyContext string
}

var masterKeyEncryptedColumns = []encryptedColumnSpec{
	{table: "application_artifacts", column: "encrypted_archive", idColumn: "compose_service_id", contextColumn: "compose_service_id", contextKind: "application-artifact"},
	{table: "application_sources", column: "encrypted_build_config", idColumn: "compose_service_id", contextColumn: "compose_service_id", contextKind: "application-build-config"},
	{table: "backup_destinations", column: "encrypted_credentials", idColumn: "id", contextColumn: "id", contextKind: "backup-destination", legacyContext: "backup-destination"},
	{table: "cluster_commands", column: "encrypted_payload", idColumn: "id", contextColumn: "id", contextKind: "cluster-command"},
	{table: "cluster_commands", column: "encrypted_result", idColumn: "id", contextColumn: "id", contextKind: "cluster-command-result"},
	{table: "commit_status_deliveries", column: "encrypted_credential", idColumn: "id", contextColumn: "credential_id", contextKind: "source-credential", legacyContext: "source-credential"},
	{table: "compose_services", column: "encrypted_env", idColumn: "id", contextColumn: "id", contextKind: "compose-env", legacyContext: "compose-env"},
	{table: "database_backups", column: "encrypted_data_key", idColumn: "id", contextColumn: "id", contextKind: "backup-data-key"},
	{table: "database_instances", column: "encrypted_credentials", idColumn: "id", contextColumn: "id", contextKind: "database-credentials", legacyContext: "database-credentials"},
	{table: "database_migrations", column: "encrypted_source_config", idColumn: "id", contextColumn: "id", contextKind: "database-migration-source"},
	{table: "notification_endpoints", column: "encrypted_secret", idColumn: "id", contextColumn: "id", contextKind: "notification-secret"},
	{table: "notification_endpoints", column: "encrypted_url", idColumn: "id", contextColumn: "id", contextKind: "notification-url"},
	{table: "oidc_providers", column: "encrypted_client_secret", idColumn: "id", contextColumn: "id", contextKind: "oidc-client-secret"},
	{table: "saml_providers", column: "encrypted_private_key", idColumn: "id", contextColumn: "id", contextKind: "saml-private-key"},
	{table: "saml_providers", column: "pending_encrypted_private_key", idColumn: "id", contextColumn: "id", contextKind: "saml-private-key"},
	{table: "source_credentials", column: "encrypted_secret", idColumn: "id", contextColumn: "id", contextKind: "source-credential", legacyContext: "source-credential"},
	{table: "template_instances", column: "encrypted_overrides", idColumn: "compose_service_id", contextColumn: "compose_service_id", contextKind: "template-overrides"},
	{table: "template_instances", column: "encrypted_variables", idColumn: "compose_service_id", contextColumn: "compose_service_id", contextKind: "template-variables"},
	{table: "template_repositories", column: "encrypted_webhook_secret", idColumn: "id", contextColumn: "id", contextKind: "template-repository-webhook"},
	{table: "volume_backups", column: "encrypted_data_key", idColumn: "id", contextColumn: "id", contextKind: "volume-backup-data-key"},
	{table: "webhook_integrations", column: "encrypted_secret", idColumn: "id", contextColumn: "id", contextKind: "webhook-secret"},
}

// RotateMasterKey validates every ciphertext before changing any row, then
// re-encrypts and verifies each value in one transaction. Controllers and
// workers must be stopped before calling it.
func RotateMasterKey(ctx context.Context, pool *pgxpool.Pool, oldKey, newKey []byte, dryRun bool) (report MasterKeyRotationReport, err error) {
	report.DryRun = dryRun
	report.ByTable = map[string]int{}
	report.OldFingerprint = MasterKeyFingerprint(oldKey)
	report.NewFingerprint = MasterKeyFingerprint(newKey)
	if len(oldKey) != 32 || len(newKey) != 32 {
		return report, errors.New("old and new master keys must each contain exactly 32 bytes")
	}
	if bytes.Equal(oldKey, newKey) {
		return report, errors.New("new master key must differ from old master key")
	}
	oldBox, err := cryptox.New(oldKey)
	if err != nil {
		return report, err
	}
	newBox, err := cryptox.New(newKey)
	if err != nil {
		return report, err
	}
	tx, err := pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.Serializable})
	if err != nil {
		return report, fmt.Errorf("begin master-key rotation: %w", err)
	}
	defer tx.Rollback(context.Background())
	var acquired bool
	if err = tx.QueryRow(ctx, `SELECT pg_try_advisory_xact_lock($1)`, masterKeyRotationLock).Scan(&acquired); err != nil {
		return report, fmt.Errorf("acquire master-key rotation lock: %w", err)
	}
	if !acquired {
		return report, errors.New("another master-key rotation is already running")
	}
	if _, err = tx.Exec(ctx, `SET LOCAL lock_timeout = '5s'`); err != nil {
		return report, err
	}
	if err = lockRotationTables(ctx, tx); err != nil {
		return report, fmt.Errorf("lock application tables (are all controllers stopped?): %w", err)
	}
	if err = validateEncryptedColumnInventory(ctx, tx); err != nil {
		return report, err
	}
	if err = validateOfflineState(ctx, tx); err != nil {
		return report, err
	}

	// The first pass authenticates the entire data set before any row changes.
	for _, spec := range masterKeyEncryptedColumns {
		count, validateErr := validateEncryptedRows(ctx, tx, oldBox, spec)
		if validateErr != nil {
			return report, validateErr
		}
		report.ByTable[spec.table] += count
		report.Validated += count
	}
	if dryRun {
		return report, nil
	}
	// The tables are exclusively locked, so the validated rows cannot change
	// between passes. Process one row at a time to bound secret-bearing memory.
	for _, spec := range masterKeyEncryptedColumns {
		if err = rotateEncryptedRows(ctx, tx, oldBox, newBox, spec); err != nil {
			return report, err
		}
	}
	if err = tx.Commit(ctx); err != nil {
		return report, fmt.Errorf("commit master-key rotation: %w", err)
	}
	report.Rotated = report.Validated
	return report, nil
}

func lockRotationTables(ctx context.Context, tx pgx.Tx) error {
	tables := []string{"controller_leases", "jobs"}
	seen := map[string]bool{"controller_leases": true, "jobs": true}
	for _, spec := range masterKeyEncryptedColumns {
		if !seen[spec.table] {
			tables = append(tables, spec.table)
			seen[spec.table] = true
		}
	}
	sort.Strings(tables)
	quoted := make([]string, len(tables))
	for i, table := range tables {
		quoted[i] = pgx.Identifier{table}.Sanitize()
	}
	_, err := tx.Exec(ctx, "LOCK TABLE "+strings.Join(quoted, ", ")+" IN ACCESS EXCLUSIVE MODE")
	return err
}

func validateEncryptedColumnInventory(ctx context.Context, tx pgx.Tx) error {
	rows, err := tx.Query(ctx, `SELECT table_name,column_name FROM information_schema.columns WHERE table_schema=current_schema() AND column_name LIKE '%encrypted\_%' ESCAPE '\' ORDER BY table_name,column_name`)
	if err != nil {
		return fmt.Errorf("inspect encrypted columns: %w", err)
	}
	defer rows.Close()
	actual := []string{}
	for rows.Next() {
		var table, column string
		if err = rows.Scan(&table, &column); err != nil {
			return err
		}
		actual = append(actual, table+"."+column)
	}
	if err = rows.Err(); err != nil {
		return err
	}
	expected := make([]string, 0, len(masterKeyEncryptedColumns))
	for _, spec := range masterKeyEncryptedColumns {
		expected = append(expected, spec.table+"."+spec.column)
	}
	sort.Strings(expected)
	if strings.Join(actual, "\n") != strings.Join(expected, "\n") {
		return fmt.Errorf("encrypted column inventory mismatch; refusing rotation: schema has [%s], command supports [%s]", strings.Join(actual, ", "), strings.Join(expected, ", "))
	}
	return nil
}

func validateOfflineState(ctx context.Context, tx pgx.Tx) error {
	var leases, jobs int
	if err := tx.QueryRow(ctx, `SELECT count(*) FROM controller_leases WHERE expires_at>now()`).Scan(&leases); err != nil {
		return fmt.Errorf("inspect controller leases: %w", err)
	}
	if err := tx.QueryRow(ctx, `SELECT count(*) FROM jobs WHERE status='running'`).Scan(&jobs); err != nil {
		return fmt.Errorf("inspect running jobs: %w", err)
	}
	if leases != 0 || jobs != 0 {
		return fmt.Errorf("offline rotation requires stopped controllers and quiesced workers: active controller leases=%d running jobs=%d", leases, jobs)
	}
	return nil
}

func validateEncryptedRows(ctx context.Context, tx pgx.Tx, box *cryptox.Box, spec encryptedColumnSpec) (int, error) {
	query := fmt.Sprintf("SELECT %s::text,COALESCE(%s,''),COALESCE(%s::text,'') FROM %s ORDER BY %s", identifier(spec.idColumn), identifier(spec.column), identifier(spec.contextColumn), identifier(spec.table), identifier(spec.idColumn))
	rows, err := tx.Query(ctx, query)
	if err != nil {
		return 0, fmt.Errorf("read %s.%s: %w", spec.table, spec.column, err)
	}
	defer rows.Close()
	count := 0
	for rows.Next() {
		var id, ciphertext, contextID string
		if err = rows.Scan(&id, &ciphertext, &contextID); err != nil {
			return 0, err
		}
		if ciphertext == "" {
			continue
		}
		if contextID == "" {
			return 0, fmt.Errorf("%s.%s row %s has ciphertext but no authentication context", spec.table, spec.column, id)
		}
		plain, decryptErr := decryptRotationValue(box, ciphertext, spec, contextID)
		if decryptErr != nil {
			return 0, fmt.Errorf("authenticate %s.%s row %s: %w", spec.table, spec.column, id, decryptErr)
		}
		clear(plain)
		count++
	}
	if err = rows.Err(); err != nil {
		return 0, err
	}
	return count, nil
}

func rotateEncryptedRows(ctx context.Context, tx pgx.Tx, oldBox, newBox *cryptox.Box, spec encryptedColumnSpec) error {
	var lastID any
	for {
		query := fmt.Sprintf("SELECT %s::text,COALESCE(%s,''),COALESCE(%s::text,'') FROM %s WHERE ($1::uuid IS NULL OR %s>$1::uuid) AND COALESCE(%s,'')<>'' ORDER BY %s LIMIT 1", identifier(spec.idColumn), identifier(spec.column), identifier(spec.contextColumn), identifier(spec.table), identifier(spec.idColumn), identifier(spec.column), identifier(spec.idColumn))
		var id, ciphertext, contextID string
		err := tx.QueryRow(ctx, query, lastID).Scan(&id, &ciphertext, &contextID)
		if errors.Is(err, pgx.ErrNoRows) {
			return nil
		}
		if err != nil {
			return fmt.Errorf("read %s.%s during rotation: %w", spec.table, spec.column, err)
		}
		plain, err := decryptRotationValue(oldBox, ciphertext, spec, contextID)
		if err != nil {
			return fmt.Errorf("re-authenticate %s.%s row %s: %w", spec.table, spec.column, id, err)
		}
		contextValue := cryptox.ResourceContext(spec.contextKind, contextID)
		replacement, err := newBox.Encrypt(plain, contextValue)
		clear(plain)
		if err != nil {
			return fmt.Errorf("encrypt %s.%s row %s: %w", spec.table, spec.column, id, err)
		}
		verified, err := newBox.Decrypt(replacement, contextValue)
		if err != nil {
			return fmt.Errorf("verify %s.%s row %s: %w", spec.table, spec.column, id, err)
		}
		clear(verified)
		update := fmt.Sprintf("UPDATE %s SET %s=$1 WHERE %s=$2::uuid", identifier(spec.table), identifier(spec.column), identifier(spec.idColumn))
		tag, err := tx.Exec(ctx, update, replacement, id)
		if err != nil {
			return fmt.Errorf("update %s.%s row %s: %w", spec.table, spec.column, id, err)
		}
		if tag.RowsAffected() != 1 {
			return fmt.Errorf("update %s.%s row %s affected %d rows", spec.table, spec.column, id, tag.RowsAffected())
		}
		lastID = id
	}
}

func decryptRotationValue(box *cryptox.Box, ciphertext string, spec encryptedColumnSpec, contextID string) ([]byte, error) {
	if spec.legacyContext != "" {
		return box.DecryptResource(ciphertext, spec.contextKind, contextID, spec.legacyContext)
	}
	return box.Decrypt(ciphertext, cryptox.ResourceContext(spec.contextKind, contextID))
}

func identifier(value string) string { return pgx.Identifier{value}.Sanitize() }

func MasterKeyFingerprint(key []byte) string {
	if len(key) == 0 {
		return ""
	}
	sum := sha256.Sum256(key)
	return fmt.Sprintf("sha256:%x", sum[:8])
}
