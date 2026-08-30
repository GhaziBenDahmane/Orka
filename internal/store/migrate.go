package store

import (
	"context"
	"crypto/sha256"
	"embed"
	"errors"
	"fmt"
	"sort"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

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

func Migrate(ctx context.Context, pool *pgxpool.Pool) error {
	return migrateThrough(ctx, pool, "")
}

// migrateThrough exists so release-gate tests can reproduce an upgrade from a
// historical schema. Production always calls Migrate, which applies every
// embedded migration.
func migrateThrough(ctx context.Context, pool *pgxpool.Pool, lastVersion string) error {
	conn, err := pool.Acquire(ctx)
	if err != nil {
		return fmt.Errorf("acquire migration connection: %w", err)
	}
	defer conn.Release()
	if _, err = conn.Exec(ctx, `SELECT pg_advisory_lock(721046140)`); err != nil {
		return fmt.Errorf("lock migrations: %w", err)
	}
	defer conn.Exec(context.Background(), `SELECT pg_advisory_unlock(721046140)`)
	if _, err := conn.Exec(ctx, `CREATE TABLE IF NOT EXISTS schema_migrations (version text PRIMARY KEY, checksum text NOT NULL DEFAULT '', applied_at timestamptz NOT NULL DEFAULT now())`); err != nil {
		return fmt.Errorf("create migrations table: %w", err)
	}
	if _, err := conn.Exec(ctx, `ALTER TABLE schema_migrations ADD COLUMN IF NOT EXISTS checksum text NOT NULL DEFAULT ''`); err != nil {
		return fmt.Errorf("add migration checksums: %w", err)
	}
	entries, err := migrations.ReadDir("migrations")
	if err != nil {
		return fmt.Errorf("read migrations: %w", err)
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].Name() < entries[j].Name() })
	for _, entry := range entries {
		if entry.IsDir() || (lastVersion != "" && entry.Name() > lastVersion) {
			continue
		}
		sql, err := migrations.ReadFile("migrations/" + entry.Name())
		if err != nil {
			return err
		}
		checksum := fmt.Sprintf("%x", sha256.Sum256(sql))
		var recordedChecksum string
		err = conn.QueryRow(ctx, `SELECT checksum FROM schema_migrations WHERE version=$1`, entry.Name()).Scan(&recordedChecksum)
		if err == nil {
			if recordedChecksum == "" {
				if _, err := conn.Exec(ctx, `UPDATE schema_migrations SET checksum=$2 WHERE version=$1 AND checksum=''`, entry.Name(), checksum); err != nil {
					return fmt.Errorf("backfill migration checksum %s: %w", entry.Name(), err)
				}
			} else if recordedChecksum != checksum {
				repaired, repairErr := repairKnownMigration(ctx, conn, entry.Name(), recordedChecksum, checksum)
				if repairErr != nil {
					return repairErr
				}
				if !repaired {
					return fmt.Errorf("migration %s checksum mismatch: applied migration was modified", entry.Name())
				}
			}
			continue
		}
		if !errors.Is(err, pgx.ErrNoRows) {
			return fmt.Errorf("read migration state %s: %w", entry.Name(), err)
		}
		tx, err := conn.Begin(ctx)
		if err != nil {
			return err
		}
		if _, err = tx.Exec(ctx, string(sql)); err == nil {
			_, err = tx.Exec(ctx, `INSERT INTO schema_migrations(version,checksum) VALUES($1,$2)`, entry.Name(), checksum)
		}
		if err != nil {
			_ = tx.Rollback(ctx)
			return fmt.Errorf("apply migration %s: %w", entry.Name(), err)
		}
		if err := tx.Commit(ctx); err != nil {
			return err
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
