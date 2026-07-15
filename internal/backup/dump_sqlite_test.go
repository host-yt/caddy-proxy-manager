package backup

import (
	"bytes"
	"context"
	"database/sql"
	"path/filepath"
	"testing"

	"github.com/host-yt/caddy-proxy-manager/internal/store"
	_ "modernc.org/sqlite"
)

// Round-trip: dump a SQLite database and restore it into a fresh file via
// SplitSQLStatements - the same path the restore drill takes. Values are
// chosen to break naive quoting: embedded quotes, raw newlines, semicolons
// (which also stress the splitter), NULLs and blobs.
func TestSQLiteDumpRestoreRoundTrip(t *testing.T) {
	prev := store.Driver()
	store.SetDriver("sqlite3")
	t.Cleanup(func() { store.SetDriver(prev) })

	ctx := context.Background()
	dir := t.TempDir()

	src, err := sql.Open("sqlite", filepath.Join(dir, "src.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer src.Close()
	for _, stmt := range []string{
		"CREATE TABLE notes (id INTEGER PRIMARY KEY, body TEXT, data BLOB, score REAL)",
		"CREATE INDEX idx_notes_score ON notes(score)",
		`INSERT INTO notes VALUES (1, 'it''s a test; with -- tricks' || char(10) || 'second line', X'00ff10', 3.5)`,
		"INSERT INTO notes VALUES (2, NULL, NULL, NULL)",
	} {
		if _, err := src.Exec(stmt); err != nil {
			t.Fatalf("seed %q: %v", stmt, err)
		}
	}

	var dump bytes.Buffer
	if err := DumpDatabase(ctx, src, &dump); err != nil {
		t.Fatalf("dump: %v", err)
	}

	dst, err := sql.Open("sqlite", filepath.Join(dir, "dst.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer dst.Close()
	for _, stmt := range SplitSQLStatements(dump.String()) {
		if _, err := dst.Exec(stmt); err != nil {
			t.Fatalf("restore stmt failed:\n%s\nerr: %v", stmt, err)
		}
	}

	var n int
	if err := dst.QueryRow("SELECT COUNT(*) FROM notes").Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != 2 {
		t.Fatalf("restored %d rows, want 2", n)
	}
	var body string
	var blob []byte
	if err := dst.QueryRow("SELECT body, data FROM notes WHERE id=1").Scan(&body, &blob); err != nil {
		t.Fatal(err)
	}
	want := "it's a test; with -- tricks\nsecond line"
	if body != want {
		t.Errorf("body = %q, want %q", body, want)
	}
	if len(blob) != 3 || blob[0] != 0x00 || blob[1] != 0xff || blob[2] != 0x10 {
		t.Errorf("blob = %x, want 00ff10", blob)
	}
	var idx int
	dst.QueryRow("SELECT COUNT(*) FROM sqlite_master WHERE type='index' AND name='idx_notes_score'").Scan(&idx)
	if idx != 1 {
		t.Error("secondary index was not restored")
	}
}
