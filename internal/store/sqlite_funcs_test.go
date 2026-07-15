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
