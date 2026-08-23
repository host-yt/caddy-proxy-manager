// Package store: programmatic migration runner using goose + embedded SQL.
package store

import (
	"bytes"
	"context"
	"database/sql"
	"embed"
	"fmt"
	"io/fs"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/pressly/goose/v3"
)

// MigrationsFS receives the embedded migrations FS from the caller
// (main.go) to avoid cyclic embed paths.
type MigrationsFS = embed.FS

// sqliteFS wraps an fs.FS and transforms .sql files for SQLite compatibility.
// Every migration is planned up front, in version order, because resolving the
// guards SQLite can't express needs the schema built by the earlier ones
// (see schemaTracker). Doing it here rather than per Open also keeps the result
// stable no matter how often, or in what order, goose reads a file.
type sqliteFS struct {
	base fs.FS
	once sync.Once
	plan map[string]string
	err  error
}

func (s *sqliteFS) build() {
	names, err := fs.Glob(s.base, "*.sql")
	if err != nil {
		s.err = fmt.Errorf("sqlite plan: glob: %w", err)
		return
	}
	sort.Strings(names)
	tracker := newSchemaTracker()
	s.plan = make(map[string]string, len(names))
	for _, n := range names {
		b, err := fs.ReadFile(s.base, n)
		if err != nil {
			s.err = fmt.Errorf("sqlite plan: read %s: %w", n, err)
			return
		}
		s.plan[n] = tracker.apply(TransformForSQLite(string(b)))
	}
}

func (s *sqliteFS) Open(name string) (fs.File, error) {
	s.once.Do(s.build)
	if s.err != nil {
		return nil, s.err
	}
	if sqlText, ok := s.plan[name]; ok {
		return &memFile{name: name, r: bytes.NewReader([]byte(sqlText))}, nil
	}
	return s.base.Open(name)
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
	return runMigrations(ctx, db, fsys, dir, 0)
}

// runMigrations is the shared implementation: upTo == 0 means "all pending".
func runMigrations(ctx context.Context, db *sql.DB, fsys embed.FS, dir string, upTo int64) error {
	subFS, err := fs.Sub(fsys, dir)
	if err != nil {
		return fmt.Errorf("migrations sub-fs: %w", err)
	}

	var migFS fs.FS = subFS
	dialect := goose.DialectMySQL
	if Driver() == "sqlite3" {
		dialect = goose.DialectSQLite3
		migFS = &sqliteFS{base: subFS}
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

	if upTo > 0 {
		if _, err := p.UpTo(ctx, upTo); err != nil {
			return fmt.Errorf("goose up-to %d: %w", upTo, err)
		}
		return nil
	}
	if _, err := p.Up(ctx); err != nil {
		return fmt.Errorf("goose up: %w", err)
	}
	return nil
}

// MigrateUpTo applies migrations only as far as version, leaving anything newer
// pending. Used to stand up an "as of release N-1" schema so the upgrade to N
// can be exercised the way a real upgrade runs it - a full apply from empty
// never touches that path.
func MigrateUpTo(ctx context.Context, db *sql.DB, fsys embed.FS, dir string, version int64) error {
	return runMigrations(ctx, db, fsys, dir, version)
}

// LatestMigrationVersion returns the highest version present in the embedded
// migration set.
func LatestMigrationVersion(fsys embed.FS, dir string) (int64, error) {
	entries, err := fs.ReadDir(fsys, dir)
	if err != nil {
		return 0, err
	}
	var latest int64
	for _, e := range entries {
		name := e.Name()
		if !strings.HasSuffix(name, ".sql") {
			continue
		}
		num, _, ok := strings.Cut(name, "_")
		if !ok {
			continue
		}
		v, err := strconv.ParseInt(num, 10, 64)
		if err != nil {
			continue
		}
		if v > latest {
			latest = v
		}
	}
	if latest == 0 {
		return 0, fmt.Errorf("no migrations found in %s", dir)
	}
	return latest, nil
}
