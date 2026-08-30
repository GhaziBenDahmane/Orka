package store

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"errors"
	"fmt"
	"sort"
	"strings"

	"github.com/bendahma/dokploy-go/internal/cryptox"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

const masterKeyRotationLock int64 = 721046141

const (
	masterKeyVerifierContext   = "master-key-verifier:control-plane"
	masterKeyVerifierPlaintext = "dockyard-master-key-verifier-v1"
)

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
	{table: "deployments", column: "encrypted_registry_credential", idColumn: "id", contextColumn: "registry_credential_id", contextKind: "source-credential", legacyContext: "source-credential"},
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

// VerifyOrInitializeMasterKey fails closed before the controller starts any
// workers or listeners. Existing installations are bootstrapped only after
// every persisted ciphertext authenticates with the supplied key.
func VerifyOrInitializeMasterKey(ctx context.Context, pool *pgxpool.Pool, box *cryptox.Box) error {
	if box == nil {
		return errors.New("master-key verifier requires an encryption key")
	}
	// Read committed is intentional: a second HA replica may begin while the
	// first holds the advisory lock and must see the verifier after that first
	// transaction commits rather than retaining a stale pre-lock snapshot.
	tx, err := pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("begin master-key verification: %w", err)
	}
	defer tx.Rollback(context.Background())
	if _, err = tx.Exec(ctx, `SELECT pg_advisory_xact_lock($1)`, masterKeyRotationLock); err != nil {
		return fmt.Errorf("acquire master-key verification lock: %w", err)
	}
	var ciphertext string
	err = tx.QueryRow(ctx, `SELECT ciphertext FROM master_key_verifier WHERE singleton=true FOR UPDATE`).Scan(&ciphertext)
	if err == nil {
		if err = authenticateMasterKeyVerifier(box, ciphertext); err != nil {
			return err
		}
		return tx.Commit(ctx)
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		return fmt.Errorf("read master-key verifier: %w", err)
	}
	if _, err = tx.Exec(ctx, `SET LOCAL lock_timeout = '5s'`); err != nil {
		return err
	}
	if err = lockEncryptedTables(ctx, tx, "SHARE"); err != nil {
		return fmt.Errorf("lock encrypted tables while initializing master-key verifier: %w", err)
	}
	if err = validateEncryptedColumnInventory(ctx, tx); err != nil {
		return err
	}
	for _, spec := range masterKeyEncryptedColumns {
		if _, err = validateEncryptedRows(ctx, tx, box, spec); err != nil {
			return fmt.Errorf("initialize master-key verifier: %w", err)
		}
	}
	ciphertext, err = encryptMasterKeyVerifier(box)
	if err != nil {
		return err
	}
	if _, err = tx.Exec(ctx, `INSERT INTO master_key_verifier(singleton,ciphertext) VALUES(true,$1)`, ciphertext); err != nil {
		return fmt.Errorf("store master-key verifier: %w", err)
	}
	if err = tx.Commit(ctx); err != nil {
		return fmt.Errorf("commit master-key verification: %w", err)
	}
	return nil
}

func verifyMasterKeyIfInitialized(ctx context.Context, pool *pgxpool.Pool, box *cryptox.Box) error {
	return verifyMasterKey(ctx, pool, box, false)
}

func verifyMasterKeyRequired(ctx context.Context, pool *pgxpool.Pool, box *cryptox.Box) error {
	return verifyMasterKey(ctx, pool, box, true)
}

func verifyMasterKey(ctx context.Context, pool *pgxpool.Pool, box *cryptox.Box, required bool) error {
	if box == nil {
		return errors.New("master-key verifier requires an encryption key")
	}
	tx, err := pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("begin master-key preflight: %w", err)
	}
	defer tx.Rollback(context.Background())
	if _, err = tx.Exec(ctx, `SELECT pg_advisory_xact_lock($1)`, masterKeyRotationLock); err != nil {
		return fmt.Errorf("acquire master-key preflight lock: %w", err)
	}
	var tableExists bool
	if err = tx.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM information_schema.tables WHERE table_schema=current_schema() AND table_name='master_key_verifier')`).Scan(&tableExists); err != nil {
		return fmt.Errorf("inspect master-key verifier schema: %w", err)
	}
	if !tableExists {
		if required {
			return errors.New("master-key verifier is not initialized; start the controller before running a dry run")
		}
		return tx.Commit(ctx)
	}
	verifierExists, err := validateMasterKeyVerifier(ctx, tx, box)
	if err != nil {
		return err
	}
	if required && !verifierExists {
		return errors.New("master-key verifier is not initialized; start the controller before running a dry run")
	}
	return tx.Commit(ctx)
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
	verifierExists, err := validateMasterKeyVerifier(ctx, tx, oldBox)
	if err != nil {
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
	verifier, err := encryptMasterKeyVerifier(newBox)
	if err != nil {
		return report, err
	}
	if verifierExists {
		_, err = tx.Exec(ctx, `UPDATE master_key_verifier SET ciphertext=$1,updated_at=now() WHERE singleton=true`, verifier)
	} else {
		_, err = tx.Exec(ctx, `INSERT INTO master_key_verifier(singleton,ciphertext) VALUES(true,$1)`, verifier)
	}
	if err != nil {
		return report, fmt.Errorf("rotate master-key verifier: %w", err)
	}
	if err = tx.Commit(ctx); err != nil {
		return report, fmt.Errorf("commit master-key rotation: %w", err)
	}
	report.Rotated = report.Validated
	return report, nil
}

func lockRotationTables(ctx context.Context, tx pgx.Tx) error {
	tables := []string{"controller_leases", "jobs", "master_key_verifier"}
	seen := map[string]bool{"controller_leases": true, "jobs": true, "master_key_verifier": true}
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

func lockEncryptedTables(ctx context.Context, tx pgx.Tx, mode string) error {
	tables := make([]string, 0, len(masterKeyEncryptedColumns))
	seen := map[string]bool{}
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
	if mode != "SHARE" {
		return errors.New("unsupported encrypted-table lock mode")
	}
	_, err := tx.Exec(ctx, "LOCK TABLE "+strings.Join(quoted, ", ")+" IN "+mode+" MODE")
	return err
}

func validateMasterKeyVerifier(ctx context.Context, tx pgx.Tx, box *cryptox.Box) (bool, error) {
	var ciphertext string
	err := tx.QueryRow(ctx, `SELECT ciphertext FROM master_key_verifier WHERE singleton=true`).Scan(&ciphertext)
	if errors.Is(err, pgx.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("read master-key verifier: %w", err)
	}
	if err = authenticateMasterKeyVerifier(box, ciphertext); err != nil {
		return true, err
	}
	return true, nil
}

func authenticateMasterKeyVerifier(box *cryptox.Box, ciphertext string) error {
	plaintext, err := box.Decrypt(ciphertext, masterKeyVerifierContext)
	if err != nil || subtle.ConstantTimeCompare(plaintext, []byte(masterKeyVerifierPlaintext)) != 1 {
		clear(plaintext)
		return errors.New("master key does not match encrypted control-plane data")
	}
	clear(plaintext)
	return nil
}

func encryptMasterKeyVerifier(box *cryptox.Box) (string, error) {
	value, err := box.Encrypt([]byte(masterKeyVerifierPlaintext), masterKeyVerifierContext)
	if err != nil {
		return "", fmt.Errorf("encrypt master-key verifier: %w", err)
	}
	return value, nil
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
