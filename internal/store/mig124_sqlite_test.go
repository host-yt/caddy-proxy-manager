package store

import (
	"database/sql"
	"os"
	"regexp"
	"strings"
	"testing"

	_ "modernc.org/sqlite"
)

// HPG-015/HPG-016: migration 00124 now uses ELSEIF + SIGNAL for shape
// verification (a MySQL-only concern - a fresh SQLite DB can never hit the
// wrong-shape branch). This proves the transform strips that branch cleanly
// instead of emitting "ELSEIF"/"SIGNAL" as literal (invalid) SQLite SQL.
func TestMig124ResellersSQLite(t *testing.T) {
	raw, err := os.ReadFile("../../migrations/00124_resellers.sql")
	if err != nil {
		t.Fatal(err)
	}
	up := string(raw)
	if i := strings.Index(up, "-- +goose Down"); i >= 0 {
		up = up[:i]
	}
	sqlText := TransformForSQLite(up)

	if strings.Contains(strings.ToUpper(sqlText), "ELSEIF") || strings.Contains(strings.ToUpper(sqlText), "SIGNAL") {
		t.Fatalf("transform left MySQL-only ELSEIF/SIGNAL in the SQLite output:\n%s", sqlText)
	}

	db, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	for _, stmt := range []string{
		`CREATE TABLE clients (id INTEGER PRIMARY KEY)`,
		`CREATE TABLE plans (id INTEGER PRIMARY KEY)`,
		`CREATE TABLE users (id INTEGER PRIMARY KEY)`,
	} {
		if _, err := db.Exec(stmt); err != nil {
			t.Fatalf("prereq %q: %v", stmt, err)
		}
	}

	clean := regexp.MustCompile(`(?m)^\s*--.*$`).ReplaceAllString(sqlText, "")
	for _, stmt := range strings.Split(clean, ";") {
		stmt = strings.TrimSpace(stmt)
		if stmt == "" {
			continue
		}
		if _, err := db.Exec(stmt); err != nil {
			t.Fatalf("exec failed:\n%s\nerr: %v", stmt, err)
		}
	}

	var n int
	if err := db.QueryRow(`SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='resellers'`).Scan(&n); err != nil || n != 1 {
		t.Fatalf("resellers table missing: n=%d err=%v", n, err)
	}
	for _, table := range []string{"clients", "plans", "users"} {
		if _, err := db.Exec(`UPDATE ` + table + ` SET reseller_id = 1`); err != nil {
			t.Errorf("%s.reseller_id missing or wrong: %v", table, err)
		}
	}
}
