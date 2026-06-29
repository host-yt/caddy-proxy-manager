// Package store: programmatic migration runner using goose + embedded SQL.
package store

import (
	"bytes"
	"context"
	"database/sql"
	"embed"
	"fmt"
	"io"
	"io/fs"
	"strings"
	"time"

	"github.com/pressly/goose/v3"
)

// MigrationsFS receives the embedded migrations FS from the caller
// (main.go) to avoid cyclic embed paths.
type MigrationsFS = embed.FS

// sqliteFS wraps an fs.FS and transforms .sql files for SQLite compatibility.
type sqliteFS struct{ base fs.FS }

func (s sqliteFS) Open(name string) (fs.File, error) {
	f, err := s.base.Open(name)
	if err != nil {
		return nil, err
	}
	if !strings.HasSuffix(name, ".sql") {
		return f, nil
	}
	b, err := io.ReadAll(f)
	_ = f.Close()
	if err != nil {
		return nil, err
	}
	transformed := []byte(TransformForSQLite(string(b)))
	return &memFile{name: name, r: bytes.NewReader(transformed)}, nil
}

// memFile is an in-memory fs.File for transformed content.
type memFile struct {
	name string
	r    *bytes.Reader
}

func (m *memFile) Read(b []byte) (int, error) { return m.r.Read(b) }
func (m *memFile) Close() error               { return nil }
func (m *memFile) Stat() (fs.FileInfo, error) {
	return &memFileInfo{name: m.name, size: m.r.Size()}, nil
}

type memFileInfo struct {
	name string
	size int64
}

func (i *memFileInfo) Name() string       { return i.name }
func (i *memFileInfo) Size() int64        { return i.size }
func (i *memFileInfo) Mode() fs.FileMode  { return 0o444 }
func (i *memFileInfo) ModTime() time.Time { return time.Time{} }
func (i *memFileInfo) IsDir() bool        { return false }
func (i *memFileInfo) Sys() any           { return nil }

// RunMigrations applies all pending migrations against db using goose.
// Dialect is selected based on the active driver. Pass the embed.FS containing
// migrations/*.sql files (root dir = "migrations").
// AllowMissing lets out-of-order migrations (added retroactively) be applied.
func RunMigrations(ctx context.Context, db *sql.DB, fsys embed.FS, dir string) error {
	subFS, err := fs.Sub(fsys, dir)
	if err != nil {
		return fmt.Errorf("migrations sub-fs: %w", err)
	}

	var migFS fs.FS = subFS
	dialect := goose.DialectMySQL
	if Driver() == "sqlite3" {
		dialect = goose.DialectSQLite3
		migFS = sqliteFS{base: subFS}
	}

	p, err := goose.NewProvider(dialect, db, migFS,
		goose.WithAllowOutofOrder(true),
	)
	if err != nil {
		return fmt.Errorf("goose provider: %w", err)
	}

	if Driver() != "sqlite3" {
		// Serialize concurrent boots (multi-replica / rolling deploy) so two
		// processes can't double-apply and race goose_db_version. goose's session
		// locker is Postgres-only; GET_LOCK is the MariaDB-native equivalent (a
		// server-wide named lock that blocks other connections until released).
		// SQLite is single-process - no distributed lock needed.
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
		defer func() { _, _ = conn.ExecContext(context.Background(), "DO RELEASE_LOCK('hpg_goose_migrate')") }()
	}

	if _, err := p.Up(ctx); err != nil {
		return fmt.Errorf("goose up: %w", err)
	}
	return nil
}
