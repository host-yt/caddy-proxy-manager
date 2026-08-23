package backup

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"database/sql"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"testing"
	"time"

	_ "modernc.org/sqlite"

	"github.com/host-yt/caddy-proxy-manager/internal/store"
)

// TestBackupRestoreRoundTripSQLite is the drill the release checklist asks for:
// take a backup of a populated panel, then restore it into an empty
// installation and prove the data - including the values most likely to be
// mangled by escaping - comes back byte for byte.
func TestBackupRestoreRoundTripSQLite(t *testing.T) {
	prev := store.Driver()
	store.SetDriver("sqlite3")
	t.Cleanup(func() { store.SetDriver(prev) })

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	dir := t.TempDir()

	src := openRoundTripDB(t, ctx, filepath.Join(dir, "src.db"))
	seedRoundTripData(t, src)

	// A state file so the archive's other members are exercised too.
	statePath := filepath.Join(dir, "install_state.json")
	if err := os.WriteFile(statePath, []byte(`{"installed":true}`), 0o600); err != nil {
		t.Fatalf("write state: %v", err)
	}

	svc := &Service{DB: func() *sql.DB { return src }, StateFilePath: statePath}
	var archive bytes.Buffer
	if err := svc.writeArchive(ctx, &archive); err != nil {
		t.Fatalf("writeArchive: %v", err)
	}

	members := readArchive(t, archive.Bytes())
	dump, ok := members["dump.sql"]
	if !ok {
		t.Fatalf("archive has no dump.sql: %v", keysOf(members))
	}
	if _, ok := members["install_state.json"]; !ok {
		t.Errorf("archive has no install_state.json: %v", keysOf(members))
	}
	var manifest map[string]any
	if err := json.Unmarshal(members["manifest.json"], &manifest); err != nil {
		t.Fatalf("manifest: %v", err)
	}

	// Restore into an empty installation.
	dst := openRoundTripDB(t, ctx, filepath.Join(dir, "restored.db"))
	for _, stmt := range SplitSQLStatements(string(dump)) {
		if _, err := dst.ExecContext(ctx, stmt); err != nil {
			t.Fatalf("restore statement failed: %v\n%s", err, stmt)
		}
	}

	// Same rows, same values.
	var routeCount int
	if err := dst.QueryRowContext(ctx, "SELECT COUNT(*) FROM routes").Scan(&routeCount); err != nil {
		t.Fatalf("count routes after restore: %v", err)
	}
	if routeCount != 3 {
		t.Fatalf("restored %d routes, want 3", routeCount)
	}
	for _, want := range roundTripRows {
		var notes sql.NullString
		if err := dst.QueryRowContext(ctx,
			"SELECT notes FROM routes WHERE domain = ?", want.domain).Scan(&notes); err != nil {
			t.Fatalf("route %s missing after restore: %v", want.domain, err)
		}
		if notes.String != want.notes {
			t.Errorf("route %s notes = %q, want %q", want.domain, notes.String, want.notes)
		}
	}
	// A NULL must come back as NULL, not as the string "NULL".
	var nullable sql.NullString
	if err := dst.QueryRowContext(ctx,
		"SELECT notes FROM routes WHERE domain = 'null.example'").Scan(&nullable); err != nil {
		t.Fatalf("null row: %v", err)
	}
	if nullable.Valid {
		t.Errorf("NULL column restored as %q", nullable.String)
	}
	// Binary data survives (hex literals, not mangled text).
	var blob []byte
	if err := dst.QueryRowContext(ctx, "SELECT secret FROM route_secrets WHERE id = 1").Scan(&blob); err != nil {
		t.Fatalf("blob row: %v", err)
	}
	if !bytes.Equal(blob, []byte{0x00, 0x01, 0xff, 0xfe, '\'', '"'}) {
		t.Errorf("blob restored as % x", blob)
	}
	// Indexes come back too, so the restored schema still enforces uniqueness.
	if _, err := dst.ExecContext(ctx,
		"INSERT INTO routes (id, domain, notes) VALUES (99, 'a.example', 'dup')"); err == nil {
		t.Error("unique index on domain not restored: duplicate insert succeeded")
	}
}

type roundTripRow struct{ domain, notes string }

var roundTripRows = []roundTripRow{
	{"a.example", "plain"},
	// The escaping cases a naive dump gets wrong.
	{"quote.example", `it's a "test"; DROP TABLE routes; --`},
}

func openRoundTripDB(t *testing.T, ctx context.Context, path string) *sql.DB {
	t.Helper()
	db, err := store.Open(ctx, "sqlite3", path, 10*time.Second)
	if err != nil {
		t.Fatalf("open sqlite %s: %v", path, err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return db
}

func seedRoundTripData(t *testing.T, db *sql.DB) {
	t.Helper()
	stmts := []string{
		`CREATE TABLE routes (id INTEGER PRIMARY KEY, domain TEXT NOT NULL, notes TEXT)`,
		`CREATE UNIQUE INDEX uq_routes_domain ON routes (domain)`,
		`CREATE TABLE route_secrets (id INTEGER PRIMARY KEY, secret BLOB)`,
	}
	for _, s := range stmts {
		if _, err := db.Exec(s); err != nil {
			t.Fatalf("seed schema %q: %v", s, err)
		}
	}
	for i, r := range roundTripRows {
		if _, err := db.Exec(`INSERT INTO routes (id, domain, notes) VALUES (?, ?, ?)`, i+1, r.domain, r.notes); err != nil {
			t.Fatalf("seed row %s: %v", r.domain, err)
		}
	}
	if _, err := db.Exec(`INSERT INTO routes (id, domain, notes) VALUES (3, 'null.example', NULL)`); err != nil {
		t.Fatalf("seed null row: %v", err)
	}
	if _, err := db.Exec(`INSERT INTO route_secrets (id, secret) VALUES (1, ?)`,
		[]byte{0x00, 0x01, 0xff, 0xfe, '\'', '"'}); err != nil {
		t.Fatalf("seed blob: %v", err)
	}
}

// readArchive returns the tar.gz members by name.
func readArchive(t *testing.T, raw []byte) map[string][]byte {
	t.Helper()
	gz, err := gzip.NewReader(bytes.NewReader(raw))
	if err != nil {
		t.Fatalf("gzip: %v", err)
	}
	defer gz.Close()
	out := map[string][]byte{}
	tr := tar.NewReader(gz)
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatalf("tar: %v", err)
		}
		data, err := io.ReadAll(tr)
		if err != nil {
			t.Fatalf("read %s: %v", hdr.Name, err)
		}
		out[hdr.Name] = data
	}
	return out
}

func keysOf(m map[string][]byte) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}
