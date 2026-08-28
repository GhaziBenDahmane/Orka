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
				return fmt.Errorf("migration %s checksum mismatch: applied migration was modified", entry.Name())
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
