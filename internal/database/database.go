package database

import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"embed"
	"fmt"
	"io/fs"
	"sort"
	"time"

	_ "github.com/jackc/pgx/v5/stdlib"
)

//go:embed migrations/*.sql
var migrationFiles embed.FS

const migrationLockID int64 = 7319460281541

type PoolConfig struct {
	MaxOpenConns    int
	MaxIdleConns    int
	ConnMaxLifetime time.Duration
	ConnMaxIdleTime time.Duration
}

func Open(ctx context.Context, databaseURL string, pool PoolConfig) (*sql.DB, error) {
	db, err := sql.Open("pgx", databaseURL)
	if err != nil {
		return nil, fmt.Errorf("configure PostgreSQL connection: %w", err)
	}
	db.SetMaxOpenConns(pool.MaxOpenConns)
	db.SetMaxIdleConns(pool.MaxIdleConns)
	db.SetConnMaxLifetime(pool.ConnMaxLifetime)
	db.SetConnMaxIdleTime(pool.ConnMaxIdleTime)

	if err := db.PingContext(ctx); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("connect to PostgreSQL: %w", err)
	}

	if err := applyMigrations(ctx, db); err != nil {
		_ = db.Close()
		return nil, err
	}

	return db, nil
}

func applyMigrations(ctx context.Context, db *sql.DB) error {
	entries, err := fs.Glob(migrationFiles, "migrations/*.sql")
	if err != nil {
		return fmt.Errorf("list database migrations: %w", err)
	}
	sort.Strings(entries)

	for _, name := range entries {
		if err := applyMigration(ctx, db, name); err != nil {
			return err
		}
	}
	return nil
}

func applyMigration(ctx context.Context, db *sql.DB, name string) error {
	source, err := migrationFiles.ReadFile(name)
	if err != nil {
		return fmt.Errorf("read database migration %s: %w", name, err)
	}

	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin database migration %s: %w", name, err)
	}
	defer func() { _ = tx.Rollback() }()

	if _, err := tx.ExecContext(ctx, "SELECT pg_advisory_xact_lock($1)", migrationLockID); err != nil {
		return fmt.Errorf("lock database migrations: %w", err)
	}
	if _, err := tx.ExecContext(ctx, `
		CREATE TABLE IF NOT EXISTS schema_migrations (
			version TEXT PRIMARY KEY,
			checksum BYTEA NOT NULL CHECK (octet_length(checksum) = 32),
			applied_at TIMESTAMPTZ NOT NULL DEFAULT now()
		)`); err != nil {
		return fmt.Errorf("create migration history: %w", err)
	}

	var checksum []byte
	if err := tx.QueryRowContext(ctx,
		"SELECT checksum FROM schema_migrations WHERE version = $1", name,
	).Scan(&checksum); err != nil && err != sql.ErrNoRows {
		return fmt.Errorf("check database migration %s: %w", name, err)
	}
	if checksum != nil {
		expected := sha256.Sum256(source)
		if !bytes.Equal(checksum, expected[:]) {
			return fmt.Errorf("database migration %s checksum does not match the applied migration", name)
		}
		if err := tx.Commit(); err != nil {
			return fmt.Errorf("finish database migration check %s: %w", name, err)
		}
		return nil
	}

	if _, err := tx.ExecContext(ctx, string(source)); err != nil {
		return fmt.Errorf("apply database migration %s: %w", name, err)
	}
	migrationChecksum := sha256.Sum256(source)
	if _, err := tx.ExecContext(ctx,
		"INSERT INTO schema_migrations (version, checksum) VALUES ($1, $2)", name, migrationChecksum[:],
	); err != nil {
		return fmt.Errorf("record database migration %s: %w", name, err)
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit database migration %s: %w", name, err)
	}
	return nil
}
