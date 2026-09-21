package store

import (
	"database/sql"
	"os"
	"regexp"
	"strings"
	"testing"

	_ "modernc.org/sqlite"
)

// HPG-015: migration 00126 uses the same ELSEIF + SIGNAL shape-verification
// procedure as 00124 - a MySQL-only concern a fresh SQLite DB can never hit.
// This proves the transform strips that branch cleanly, the MODIFY COLUMN
// role statement is skipped (role stays TEXT), and the seed/backfill
// statements still run.
func TestMig126ResellerPlansSQLite(t *testing.T) {
	raw, err := os.ReadFile("../../migrations/00126_reseller_plans.sql")
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
	if strings.Contains(strings.ToUpper(sqlText), "MODIFY") {
		t.Fatalf("transform left a MODIFY COLUMN statement in the SQLite output (role must stay untouched/TEXT):\n%s", sqlText)
	}

	db, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	for _, stmt := range []string{
		`CREATE TABLE resellers (id INTEGER PRIMARY KEY)`,
		`CREATE TABLE node_groups (id INTEGER PRIMARY KEY, name TEXT NOT NULL)`,
		`CREATE TABLE users (id INTEGER PRIMARY KEY, role TEXT NOT NULL DEFAULT 'client', reseller_id INTEGER)`,
	} {
		if _, err := db.Exec(stmt); err != nil {
			t.Fatalf("prereq %q: %v", stmt, err)
		}
	}
	if _, err := db.Exec(`INSERT INTO node_groups (name) VALUES ('default'), ('edge')`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO resellers DEFAULT VALUES`); err != nil {
		t.Fatal(err)
	}
	// Two admins linked to the reseller - owner_user_id backfill must pick the
	// earliest (MIN id), matching the original F1 backfill semantics.
	if _, err := db.Exec(`INSERT INTO users (role, reseller_id) VALUES ('admin', 1), ('admin', 1), ('client', NULL)`); err != nil {
		t.Fatal(err)
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

	var planCount int
	if err := db.QueryRow(`SELECT COUNT(*) FROM reseller_plans WHERE name='Unlimited'`).Scan(&planCount); err != nil || planCount != 1 {
		t.Fatalf("Unlimited plan missing: n=%d err=%v", planCount, err)
	}

	var groupGrants int
	if err := db.QueryRow(`SELECT COUNT(*) FROM reseller_plan_node_groups`).Scan(&groupGrants); err != nil || groupGrants != 2 {
		t.Fatalf("expected 2 node_group grants, got %d err=%v", groupGrants, err)
	}

	var featureGrants int
	if err := db.QueryRow(`SELECT COUNT(*) FROM reseller_plan_features`).Scan(&featureGrants); err != nil || featureGrants != 12 {
		t.Fatalf("expected 12 feature grants, got %d err=%v", featureGrants, err)
	}

	var planID sql.NullInt64
	if err := db.QueryRow(`SELECT reseller_plan_id FROM resellers WHERE id=1`).Scan(&planID); err != nil || !planID.Valid {
		t.Fatalf("resellers.reseller_plan_id not backfilled: %v err=%v", planID, err)
	}

	// F1 backfill semantics: owner = earliest (MIN id) linked user.
	var owner sql.NullInt64
	if err := db.QueryRow(`SELECT owner_user_id FROM resellers WHERE id=1`).Scan(&owner); err != nil {
		t.Fatalf("check owner_user_id: %v", err)
	}
	var wantOwner int64
	if err := db.QueryRow(`SELECT MIN(id) FROM users WHERE reseller_id=1`).Scan(&wantOwner); err != nil {
		t.Fatal(err)
	}
	if !owner.Valid || owner.Int64 != wantOwner {
		t.Errorf("owner_user_id = %v, want %d (earliest linked user)", owner, wantOwner)
	}

	// F1 intentionally does NOT flip role yet (guards still key off reseller_id).
	var nonAdmin int
	db.QueryRow(`SELECT COUNT(*) FROM users WHERE reseller_id=1 AND role<>'admin'`).Scan(&nonAdmin)
	if nonAdmin != 0 {
		t.Errorf("%d reseller-linked admins were unexpectedly flipped off 'admin'", nonAdmin)
	}

	for _, col := range []string{"overselling_allowed", "can_create_plans"} {
		if _, err := db.Exec(`UPDATE resellers SET ` + col + ` = ` + col); err != nil {
			t.Errorf("resellers.%s missing: %v", col, err)
		}
	}
}
