package persist

import (
	"context"
	"embed"
	"fmt"
	"sort"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

const migrationAdvisoryLockID int64 = 0x4950454d494752

//go:embed migrations/*.sql
var migrationFiles embed.FS

func applyMigrations(ctx context.Context, pool *pgxpool.Pool) error {
	if _, err := pool.Exec(ctx, `
CREATE SCHEMA IF NOT EXISTS ipesign;
CREATE TABLE IF NOT EXISTS ipesign.schema_migrations (
    version TEXT PRIMARY KEY,
    applied_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
REVOKE ALL ON SCHEMA ipesign FROM PUBLIC;
REVOKE ALL ON TABLE ipesign.schema_migrations FROM PUBLIC;`); err != nil {
		return fmt.Errorf("initialize postgres migrations: %w", err)
	}

	entries, err := migrationFiles.ReadDir("migrations")
	if err != nil {
		return fmt.Errorf("read embedded postgres migrations: %w", err)
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].Name() < entries[j].Name() })

	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		version := entry.Name()
		sql, err := migrationFiles.ReadFile("migrations/" + version)
		if err != nil {
			return fmt.Errorf("read postgres migration %s: %w", version, err)
		}
		if err := applyMigration(ctx, pool, version, string(sql)); err != nil {
			return err
		}
	}
	return nil
}

func applyMigration(ctx context.Context, pool *pgxpool.Pool, version, migrationSQL string) error {
	tx, err := pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return fmt.Errorf("begin postgres migration %s: %w", version, err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock($1)`, migrationAdvisoryLockID); err != nil {
		return fmt.Errorf("lock postgres migrations: %w", err)
	}

	var applied bool
	if err := tx.QueryRow(ctx, `
SELECT EXISTS(
    SELECT 1 FROM ipesign.schema_migrations WHERE version = $1
)`, version).Scan(&applied); err != nil {
		return fmt.Errorf("check postgres migration %s: %w", version, err)
	}
	if applied {
		return tx.Commit(ctx)
	}

	if _, err := tx.Exec(ctx, migrationSQL); err != nil {
		return fmt.Errorf("apply postgres migration %s: %w", version, err)
	}
	if _, err := tx.Exec(ctx, `
INSERT INTO ipesign.schema_migrations (version) VALUES ($1)`, version); err != nil {
		return fmt.Errorf("record postgres migration %s: %w", version, err)
	}
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("commit postgres migration %s: %w", version, err)
	}
	return nil
}
