package store

import (
	"database/sql"
	"testing"

	_ "modernc.org/sqlite"
)

// The runtime SQL is MySQL-dialect; these functions are registered on the
// SQLite driver so the shared queries run unchanged. Exercise them through a
// real connection, the way the queries reach them.
func TestSQLiteMySQLCompatFuncs(t *testing.T) {
	db, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	cases := []struct {
		name string
		expr string
		want string
	}{
		{"GREATEST picks the larger", "GREATEST(3, 7)", "7"},
		{"GREATEST guards a zero divisor", "GREATEST(0, 1)", "1"},
		{"GREATEST is NULL if any arg is", "COALESCE(CAST(GREATEST(1, NULL) AS TEXT), 'null')", "null"},
		{"LEAST picks the smaller", "LEAST(3, 7)", "3"},
		{"LEAST compares timestamps lexically", "LEAST('2026-01-02 00:00:00', '2026-01-01 00:00:00')", "2026-01-01 00:00:00"},
		{"DATE_FORMAT renders the panel's list format", "DATE_FORMAT('2026-07-15 08:04:05', '%Y-%m-%d %H:%i')", "2026-07-15 08:04"},
		{"DATE_FORMAT renders the API's RFC3339 format", "DATE_FORMAT('2026-07-15 08:04:05', '%Y-%m-%dT%H:%i:%sZ')", "2026-07-15T08:04:05Z"},
		{"DATE_FORMAT is NULL-safe", "COALESCE(DATE_FORMAT(NULL, '%Y-%m-%d'), 'null')", "null"},
		{"DATEDIFF counts whole days", "DATEDIFF('2026-07-15', '2026-07-10')", "5"},
		{"TIMESTAMPDIFF counts seconds", "TIMESTAMPDIFF('SECOND', '2026-07-15 08:00:00', '2026-07-15 08:01:30')", "90"},
		{"TIMESTAMPDIFF counts days", "TIMESTAMPDIFF('DAY', '2026-07-10 00:00:00', '2026-07-15 00:00:00')", "5"},
		{"UNIX_TIMESTAMP returns epoch seconds", "UNIX_TIMESTAMP('2026-01-01 00:00:00')", "1767225600"},
		{"UNIX_TIMESTAMP is NULL-safe", "COALESCE(CAST(UNIX_TIMESTAMP(NULL) AS TEXT), 'null')", "null"},
		{"LEFT takes a prefix", "LEFT('abcdef', 3)", "abc"},
		{"LEFT tolerates over-long n", "LEFT('ab', 9)", "ab"},
		{"LOCATE is 1-based", "LOCATE('b', 'abc')", "2"},
		{"LOCATE returns 0 when absent", "LOCATE('z', 'abc')", "0"},
		{"SUBSTRING_INDEX takes the first field", "SUBSTRING_INDEX('host:443', ':', 1)", "host"},
		{"SUBSTRING_INDEX passes through a missing delimiter", "SUBSTRING_INDEX('host', ':', 1)", "host"},
		// The driver binds time.Time as its String() form; both functions must
		// parse it or every driver-written timestamp column yields NULL.
		{"DATE_FORMAT reads a driver-written time.Time", "DATE_FORMAT('2026-07-15 08:04:05.123456789 +0000 UTC', '%Y-%m-%d %H:%i')", "2026-07-15 08:04"},
		{"UNIX_TIMESTAMP reads a driver-written time.Time", "UNIX_TIMESTAMP('2026-01-01 00:00:00 +0000 UTC')", "1767225600"},
		{"SHA2/256 matches crypto/sha256", "SHA2('abc', 256)", "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"},
		{"SHA2 is NULL-safe", "COALESCE(SHA2(NULL, 256), 'null')", "null"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var got string
			if err := db.QueryRow("SELECT CAST(" + tc.expr + " AS TEXT)").Scan(&got); err != nil {
				t.Fatalf("%s: %v", tc.expr, err)
			}
			if got != tc.want {
				t.Errorf("%s = %q, want %q", tc.expr, got, tc.want)
			}
		})
	}

	// NOW() must be comparable against a stored timestamp: an "expires_at >
	// NOW()" check is what every token in the panel hangs on.
	var live bool
	if err := db.QueryRow(
		"SELECT datetime('now', '+10 minutes') > NOW() AND datetime('now', '-10 minutes') < NOW()").Scan(&live); err != nil {
		t.Fatalf("NOW(): %v", err)
	}
	if !live {
		t.Error("NOW() does not order against SQLite's own datetime('now')")
	}
}

// The dialect helpers must emit each engine's own syntax; SQLite parses no
// INTERVAL keyword at all.
func TestDateSubDialects(t *testing.T) {
	prev := Driver()
	t.Cleanup(func() { SetDriver(prev) })

	SetDriver("mysql")
	if got, want := DateSub(3, "MINUTE"), "(NOW() - INTERVAL 3 MINUTE)"; got != want {
		t.Errorf("mysql DateSub = %q, want %q", got, want)
	}
	SetDriver("sqlite3")
	if got, want := DateSub(3, "MINUTE"), "datetime('now', '-3 minutes')"; got != want {
		t.Errorf("sqlite DateSub = %q, want %q", got, want)
	}

	// The SQLite form has to survive a real parse, parameter and all.
	db, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	var ok bool
	if err := db.QueryRow(
		"SELECT datetime('now') > "+DateSubParam("MINUTE"), 5).Scan(&ok); err != nil {
		t.Fatalf("DateSubParam does not execute: %v", err)
	}
	if !ok {
		t.Error("now is not later than 5 minutes ago")
	}
}

// ForUpdate and IntDiv paper over syntax, not functions, so each has to be
// spelled per dialect - and the SQLite spelling has to actually parse.
func TestSyntaxHelperDialects(t *testing.T) {
	prev := Driver()
	t.Cleanup(func() { SetDriver(prev) })

	SetDriver("mysql")
	if got := ForUpdate(); got != " FOR UPDATE" {
		t.Errorf("mysql ForUpdate = %q", got)
	}
	if got := IntDiv(); got != "DIV" {
		t.Errorf("mysql IntDiv = %q", got)
	}
	if got, want := Upsert("name", "url", "events"),
		"ON DUPLICATE KEY UPDATE url=VALUES(url), events=VALUES(events)"; got != want {
		t.Errorf("mysql Upsert = %q, want %q", got, want)
	}

	SetDriver("sqlite3")
	if got := ForUpdate(); got != "" {
		t.Errorf("sqlite ForUpdate = %q, want empty (no such syntax)", got)
	}
	if got, want := Upsert("name", "url", "events"),
		"ON CONFLICT(name) DO UPDATE SET url=excluded.url, events=excluded.events"; got != want {
		t.Errorf("sqlite Upsert = %q, want %q", got, want)
	}

	db, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if _, err := db.Exec(`CREATE TABLE t (k TEXT PRIMARY KEY, v INT)`); err != nil {
		t.Fatal(err)
	}
	// A SELECT ... FOR UPDATE must degrade to a plain SELECT, not a parse error.
	var v int
	if err := db.QueryRow(`SELECT 1 FROM t WHERE k='x' LIMIT 1` + ForUpdate()).Scan(&v); err != nil && err != sql.ErrNoRows {
		t.Errorf("ForUpdate does not parse on sqlite: %v", err)
	}
	// Integer division must truncate, the way MySQL's DIV does.
	var q int
	if err := db.QueryRow(`SELECT 7 ` + IntDiv() + ` 2`).Scan(&q); err != nil {
		t.Fatalf("IntDiv does not parse: %v", err)
	}
	if q != 3 {
		t.Errorf("7 %s 2 = %d, want 3", IntDiv(), q)
	}
	// The upsert clause has to apply, not just parse.
	ins := `INSERT INTO t (k,v) VALUES ('a',1) ` + Upsert("k", "v")
	if _, err := db.Exec(ins); err != nil {
		t.Fatalf("upsert insert: %v", err)
	}
	if _, err := db.Exec(`INSERT INTO t (k,v) VALUES ('a',9) ` + Upsert("k", "v")); err != nil {
		t.Fatalf("upsert conflict: %v", err)
	}
	if err := db.QueryRow(`SELECT v FROM t WHERE k='a'`).Scan(&v); err != nil {
		t.Fatal(err)
	}
	if v != 9 {
		t.Errorf("v after upsert = %d, want 9", v)
	}
}
