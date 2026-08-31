package store

import (
	"context"
	"crypto/sha256"
	"embed"
	"errors"
	"fmt"
	"sort"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

const migrationAdvisoryLock int64 = 721046140

//go:embed migrations/*.sql
var migrations embed.FS

// knownMigrationRepairs are exact, one-way bridges for development builds
// that applied a migration before its first committed form was finalized. A
// repair must apply only the missing statements and then atomically advance the
// recorded checksum to the embedded migration. Unknown mismatches still fail
// closed.
var knownMigrationRepairs = map[string]map[string]string{
	"081_database_storage_node.sql": {
		"9509f0a111e3f606030742a4f00231928635d097601394c4dcf4d57e4842d39f": `ALTER TABLE cluster_commands DROP CONSTRAINT cluster_commands_kind_check;
ALTER TABLE cluster_commands ADD CONSTRAINT cluster_commands_kind_check
    CHECK (kind IN ('swarm.deploy','swarm.remove','swarm.logs','swarm.nodes','swarm.storage-node','swarm.prune-volumes','container.run','database.utility','agent.upgrade','database.transfer'));`,
	},
}

type embeddedMigration struct {
	name     string
	sql      []byte
	checksum string
}

type migrationRows interface {
	Query(context.Context, string, ...any) (pgx.Rows, error)
}

func Migrate(ctx context.Context, pool *pgxpool.Pool) error {
	return migrateThrough(ctx, pool, "")
}

// migrateThrough exists so release-gate tests can reproduce an upgrade from a
// historical schema. Production always calls Migrate, which applies every
// embedded migration.
func migrateThrough(ctx context.Context, pool *pgxpool.Pool, lastVersion string) error {
	entries, err := embeddedMigrations(lastVersion)
	if err != nil {
		return err
	}
	conn, err := pool.Acquire(ctx)
	if err != nil {
		return fmt.Errorf("acquire migration connection: %w", err)
	}
	if _, err = conn.Exec(ctx, `SELECT pg_advisory_lock($1)`, migrationAdvisoryLock); err != nil {
		conn.Release()
		return fmt.Errorf("lock migrations: %w", err)
	}
	defer releaseMigrationLock(conn)
	var migrationTableExists bool
	if err = conn.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM information_schema.tables WHERE table_schema=current_schema() AND table_name='schema_migrations')`).Scan(&migrationTableExists); err != nil {
		return fmt.Errorf("inspect migration schema: %w", err)
	}
	if migrationTableExists {
		if err = rejectUnknownAppliedMigrations(ctx, conn, entries); err != nil {
			return err
		}
	}
	if _, err := conn.Exec(ctx, `CREATE TABLE IF NOT EXISTS schema_migrations (version text PRIMARY KEY, checksum text NOT NULL DEFAULT '', applied_at timestamptz NOT NULL DEFAULT now())`); err != nil {
		return fmt.Errorf("create migrations table: %w", err)
	}
	if _, err := conn.Exec(ctx, `ALTER TABLE schema_migrations ADD COLUMN IF NOT EXISTS checksum text NOT NULL DEFAULT ''`); err != nil {
		return fmt.Errorf("add migration checksums: %w", err)
	}
	for _, entry := range entries {
		var recordedChecksum string
		err = conn.QueryRow(ctx, `SELECT checksum FROM schema_migrations WHERE version=$1`, entry.name).Scan(&recordedChecksum)
		if err == nil {
			if recordedChecksum == "" {
				if _, err := conn.Exec(ctx, `UPDATE schema_migrations SET checksum=$2 WHERE version=$1 AND checksum=''`, entry.name, entry.checksum); err != nil {
					return fmt.Errorf("backfill migration checksum %s: %w", entry.name, err)
				}
			} else if recordedChecksum != entry.checksum {
				repaired, repairErr := repairKnownMigration(ctx, conn, entry.name, recordedChecksum, entry.checksum)
				if repairErr != nil {
					return repairErr
				}
				if !repaired {
					return fmt.Errorf("migration %s checksum mismatch: applied migration was modified", entry.name)
				}
			}
			continue
		}
		if !errors.Is(err, pgx.ErrNoRows) {
			return fmt.Errorf("read migration state %s: %w", entry.name, err)
		}
		tx, err := conn.Begin(ctx)
		if err != nil {
			return err
		}
		if _, err = tx.Exec(ctx, string(entry.sql)); err == nil {
			_, err = tx.Exec(ctx, `INSERT INTO schema_migrations(version,checksum) VALUES($1,$2)`, entry.name, entry.checksum)
		}
		if err != nil {
			_ = tx.Rollback(ctx)
			return fmt.Errorf("apply migration %s: %w", entry.name, err)
		}
		if err := tx.Commit(ctx); err != nil {
			return err
		}
	}
	return validateAppliedMigrations(ctx, conn, entries)
}

// releaseMigrationLock never returns a connection that may still own the
// session-level migration lock to the pool. Closing a connection is the
// PostgreSQL fail-safe that releases all of its session locks.
func releaseMigrationLock(conn *pgxpool.Conn) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	var unlocked bool
	if err := conn.QueryRow(ctx, `SELECT pg_advisory_unlock($1)`, migrationAdvisoryLock).Scan(&unlocked); err != nil || !unlocked {
		_ = conn.Conn().Close(ctx)
	}
	conn.Release()
}

func rejectUnknownAppliedMigrations(ctx context.Context, database migrationRows, expected []embeddedMigration) error {
	wanted := make(map[string]bool, len(expected))
	for _, entry := range expected {
		wanted[entry.name] = true
	}
	rows, err := database.Query(ctx, `SELECT version FROM schema_migrations ORDER BY version`)
	if err != nil {
		return fmt.Errorf("read applied migration versions: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var version string
		if err = rows.Scan(&version); err != nil {
			return err
		}
		if !wanted[version] {
			return fmt.Errorf("database contains unknown migration %s; refusing to run an older binary", version)
		}
	}
	return rows.Err()
}

// ValidateMigrationState performs the same exact-version and checksum check as
// startup without creating, repairing, or applying anything.
func ValidateMigrationState(ctx context.Context, pool *pgxpool.Pool) error {
	var exists bool
	if err := pool.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM information_schema.tables WHERE table_schema=current_schema() AND table_name='schema_migrations')`).Scan(&exists); err != nil {
		return fmt.Errorf("inspect migration schema: %w", err)
	}
	if !exists {
		return errors.New("database schema is not initialized; start the controller before running a dry run")
	}
	entries, err := embeddedMigrations("")
	if err != nil {
		return err
	}
	return validateAppliedMigrations(ctx, pool, entries)
}

func embeddedMigrations(lastVersion string) ([]embeddedMigration, error) {
	entries, err := migrations.ReadDir("migrations")
	if err != nil {
		return nil, fmt.Errorf("read migrations: %w", err)
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].Name() < entries[j].Name() })
	result := make([]embeddedMigration, 0, len(entries))
	for _, entry := range entries {
		if entry.IsDir() || (lastVersion != "" && entry.Name() > lastVersion) {
			continue
		}
		sql, err := migrations.ReadFile("migrations/" + entry.Name())
		if err != nil {
			return nil, err
		}
		result = append(result, embeddedMigration{name: entry.Name(), sql: sql, checksum: fmt.Sprintf("%x", sha256.Sum256(sql))})
	}
	return result, nil
}

func validateAppliedMigrations(ctx context.Context, database migrationRows, expected []embeddedMigration) error {
	wanted := make(map[string]string, len(expected))
	for _, entry := range expected {
		wanted[entry.name] = entry.checksum
	}
	rows, err := database.Query(ctx, `SELECT version,checksum FROM schema_migrations ORDER BY version`)
	if err != nil {
		return fmt.Errorf("read applied migrations: %w", err)
	}
	defer rows.Close()
	seen := make(map[string]bool, len(expected))
	for rows.Next() {
		var version, checksum string
		if err = rows.Scan(&version, &checksum); err != nil {
			return err
		}
		wantedChecksum, known := wanted[version]
		if !known {
			return fmt.Errorf("database contains unknown migration %s; refusing to run an older binary", version)
		}
		if checksum == "" || checksum != wantedChecksum {
			return fmt.Errorf("migration %s checksum mismatch: applied migration was modified", version)
		}
		seen[version] = true
	}
	if err = rows.Err(); err != nil {
		return err
	}
	for _, entry := range expected {
		if !seen[entry.name] {
			return fmt.Errorf("database is missing migration %s; start the controller before running a dry run", entry.name)
		}
	}
	return nil
}

func repairKnownMigration(ctx context.Context, conn *pgxpool.Conn, version, recordedChecksum, currentChecksum string) (bool, error) {
	repairs := knownMigrationRepairs[version]
	repairSQL, ok := repairs[recordedChecksum]
	if !ok {
		return false, nil
	}
	tx, err := conn.Begin(ctx)
	if err != nil {
		return true, fmt.Errorf("begin migration repair %s: %w", version, err)
	}
	defer tx.Rollback(ctx)
	if _, err = tx.Exec(ctx, repairSQL); err != nil {
		return true, fmt.Errorf("repair migration %s: %w", version, err)
	}
	tag, err := tx.Exec(ctx, `UPDATE schema_migrations SET checksum=$3 WHERE version=$1 AND checksum=$2`, version, recordedChecksum, currentChecksum)
	if err != nil {
		return true, fmt.Errorf("record migration repair %s: %w", version, err)
	}
	if tag.RowsAffected() != 1 {
		return true, fmt.Errorf("record migration repair %s: migration state changed concurrently", version)
	}
	if err = tx.Commit(ctx); err != nil {
		return true, fmt.Errorf("commit migration repair %s: %w", version, err)
	}
	return true, nil
}
