// Package store: programmatic migration runner using goose + embedded SQL.
package store

import (
	"context"
	"database/sql"
	"embed"
	"fmt"

	"github.com/pressly/goose/v3"
)

// MigrationsFS receives the embedded migrations FS from the caller
// (main.go) to avoid cyclic embed paths.
type MigrationsFS = embed.FS

// RunMigrations applies all pending migrations against db using goose.
// dialect is hard-coded to MySQL/MariaDB. Pass the embed.FS containing
// migrations/*.sql files (root dir = "migrations").
func RunMigrations(ctx context.Context, db *sql.DB, fs embed.FS, dir string) error {
	goose.SetBaseFS(fs)
	if err := goose.SetDialect("mysql"); err != nil {
		return fmt.Errorf("goose dialect: %w", err)
	}
	// Serialize concurrent boots (multi-replica / rolling deploy) so two
	// processes can't double-apply and race goose_db_version. goose's session
	// locker is Postgres-only; GET_LOCK is the MariaDB-native equivalent (a
	// server-wide named lock that blocks other connections until released).
	conn, err := db.Conn(ctx)
	if err != nil {
		return fmt.Errorf("migrate lock conn: %w", err)
	}
	defer conn.Close()
	var got sql.NullInt64
	if err := conn.QueryRowContext(ctx, "SELECT GET_LOCK('hpg_goose_migrate', 60)").Scan(&got); err != nil {
		return fmt.Errorf("acquire migrate lock: %w", err)
	}
	if !got.Valid || got.Int64 != 1 {
		return fmt.Errorf("migrate lock timeout: another instance is migrating")
	}
	// Release on a fresh context: ctx may be cancelled by the time we unwind.
	defer func() { _, _ = conn.ExecContext(context.Background(), "DO RELEASE_LOCK('hpg_goose_migrate')") }()

	if err := goose.UpContext(ctx, db, dir); err != nil {
		return fmt.Errorf("goose up: %w", err)
	}
	return nil
}
