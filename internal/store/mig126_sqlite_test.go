package store

import (
	"database/sql"
	"os"
	"regexp"
	"strings"
	"testing"

	_ "modernc.org/sqlite"
)

// Guards migration 00126 on SQLite: the MySQL->SQLite transform is comment-blind,
// so DDL-looking text in a comment (e.g. "ALTER TABLE ...") corrupts the output.
// Also checks the Unlimited seed + backfill (role/owner/package) apply cleanly.
func TestMig126ResellerPlansSQLite(t *testing.T) {
	raw, err := os.ReadFile("../../migrations/00126_reseller_plans.sql")
	if err != nil {
		t.Fatal(err)
	}
	// take only the Up section
	up := string(raw)
	if i := strings.Index(up, "-- +goose Down"); i >= 0 {
		up = up[:i]
	}
	sqlText := TransformForSQLite(up)

	db, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	// minimal prerequisite schema the migration references
	pre := []string{
		`CREATE TABLE node_groups (id INTEGER PRIMARY KEY, name TEXT)`,
		`CREATE TABLE users (id INTEGER PRIMARY KEY, role TEXT, reseller_id INTEGER)`,
		`CREATE TABLE resellers (id INTEGER PRIMARY KEY, name TEXT, status TEXT)`,
		`INSERT INTO node_groups (id,name) VALUES (1,'default'),(2,'edge')`,
		`INSERT INTO resellers (id,name,status) VALUES (1,'acme','active')`,
		`INSERT INTO users (id,role,reseller_id) VALUES (10,'admin',1),(11,'admin',1),(12,'client',NULL)`,
	}
	for _, s := range pre {
		if _, err := db.Exec(s); err != nil {
			t.Fatalf("pre %q: %v", s, err)
		}
	}

	// strip goose annotation lines, split on ; and exec each
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

	// assertions: Unlimited plan seeded, all pools + features granted, backfill applied
	var pools, feats, rplan int
	db.QueryRow(`SELECT COUNT(*) FROM reseller_plan_node_groups`).Scan(&pools)
	db.QueryRow(`SELECT COUNT(*) FROM reseller_plan_features`).Scan(&feats)
	db.QueryRow(`SELECT reseller_plan_id FROM resellers WHERE id=1`).Scan(&rplan)
	if pools != 2 {
		t.Errorf("pools granted = %d, want 2", pools)
	}
	if feats != 12 {
		t.Errorf("features granted = %d, want 12", feats)
	}
	if rplan == 0 {
		t.Error("reseller not backfilled to Unlimited")
	}
	var owner sql.NullInt64
	db.QueryRow(`SELECT owner_user_id FROM resellers WHERE id=1`).Scan(&owner)
	if !owner.Valid || owner.Int64 != 10 {
		t.Errorf("owner_user_id = %v, want 10", owner)
	}
	// F1 intentionally does NOT flip role yet (guards still key off reseller_id).
	var role string
	db.QueryRow(`SELECT role FROM users WHERE id=10`).Scan(&role)
	if role != "admin" {
		t.Errorf("user 10 role = %q, want admin (role flip is F2)", role)
	}
}
