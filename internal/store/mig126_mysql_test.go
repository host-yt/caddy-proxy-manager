package store

import (
	"context"
	"database/sql"
	"fmt"
	"os"
	"os/exec"
	"regexp"
	"strings"
	"testing"
	"time"

	_ "github.com/go-sql-driver/mysql"
)

// openIsolatedMySQLTestDB126 mirrors openIsolatedMySQLTestDB (mig124_mysql_test.go)
// with its own name prefix - a throw-away schema, dropped on cleanup, never the
// shared hpg_test3 fixture DB.
func openIsolatedMySQLTestDB126(t *testing.T) *sql.DB {
	t.Helper()
	dsn := os.Getenv("TEST_DB_DSN")
	if dsn == "" {
		t.Skip("TEST_DB_DSN not set - skipping DB-backed test")
	}
	base, err := sql.Open("mysql", dsn)
	if err != nil {
		t.Fatalf("sql.Open: %v", err)
	}
	if err := base.Ping(); err != nil {
		base.Close()
		t.Skipf("DB not reachable: %v", err)
	}

	name := fmt.Sprintf("hpg_mig126_test_%d", time.Now().UnixNano())
	if _, err := base.Exec("CREATE DATABASE " + name); err != nil {
		base.Close()
		t.Skipf("cannot create isolated test database (need CREATE privilege): %v", err)
	}
	t.Cleanup(func() {
		base.Exec("DROP DATABASE IF EXISTS " + name)
		base.Close()
	})

	dbNameRe := regexp.MustCompile(`/[^/?]+(\?|$)`)
	testDSN := dbNameRe.ReplaceAllString(dsn, "/"+name+"$1")
	db, err := sql.Open("mysql", testDSN)
	if err != nil {
		t.Fatalf("sql.Open isolated db: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	return db
}

// mig126UpSQL returns the Up section of migrations/00126_reseller_plans.sql, with
// the goose annotation lines stripped so it can be sent straight to MySQL.
func mig126UpSQL(t *testing.T) string {
	t.Helper()
	raw, err := os.ReadFile("../../migrations/00126_reseller_plans.sql")
	if err != nil {
		t.Fatal(err)
	}
	return stripGooseAnnotations(t, string(raw))
}

// preFixMig126UpSQL reconstructs the original, unguarded Up section exactly as
// it shipped before HPG-015 hardening (git blob HEAD~N at the time this test
// was written), via `git show`. Used only to prove the regression this
// migration now guards against actually reproduces on the old form.
func preFixMig126UpSQL(t *testing.T) string {
	t.Helper()
	out, err := exec.Command("git", "-C", "../..", "show", "2be3462:migrations/00126_reseller_plans.sql").Output()
	if err != nil {
		t.Skipf("cannot read pre-fix blob from git history: %v", err)
	}
	return stripGooseAnnotations(t, string(out))
}

func stripGooseAnnotations(t *testing.T, raw string) string {
	t.Helper()
	up := raw
	if i := strings.Index(up, "-- +goose Down"); i >= 0 {
		up = up[:i]
	}
	var lines []string
	for _, l := range strings.Split(up, "\n") {
		if strings.HasPrefix(strings.TrimSpace(l), "-- +goose") {
			continue
		}
		lines = append(lines, l)
	}
	return strings.Join(lines, "\n")
}

func seedMig126PrereqSchema(t *testing.T, db *sql.DB, ctx context.Context) {
	t.Helper()
	for _, stmt := range []string{
		`CREATE TABLE resellers (id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY) ENGINE=InnoDB`,
		`CREATE TABLE node_groups (id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY, name VARCHAR(128) NOT NULL) ENGINE=InnoDB`,
		`CREATE TABLE users (
			id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
			role ENUM('super_admin','admin','support','client','api') NOT NULL DEFAULT 'client',
			reseller_id BIGINT UNSIGNED NULL
		) ENGINE=InnoDB`,
	} {
		if _, err := db.ExecContext(ctx, stmt); err != nil {
			t.Fatalf("prereq schema %q: %v", stmt, err)
		}
	}
	if _, err := db.ExecContext(ctx, `INSERT INTO node_groups (name) VALUES ('default'), ('edge')`); err != nil {
		t.Fatalf("seed node_groups: %v", err)
	}
	if _, err := db.ExecContext(ctx, `INSERT INTO resellers () VALUES ()`); err != nil {
		t.Fatalf("seed resellers: %v", err)
	}
	// Two admins linked to the reseller - owner_user_id backfill must pick the
	// earliest (MIN id), matching the original F1 backfill semantics.
	if _, err := db.ExecContext(ctx, `INSERT INTO users (role, reseller_id) VALUES ('admin', 1), ('admin', 1), ('client', NULL)`); err != nil {
		t.Fatalf("seed users: %v", err)
	}
}

func assertMig126Applied(t *testing.T, db *sql.DB, ctx context.Context) {
	t.Helper()

	var planCount int
	if err := db.QueryRowContext(ctx, `SELECT COUNT(*) FROM reseller_plans WHERE name='Unlimited'`).Scan(&planCount); err != nil {
		t.Fatalf("count Unlimited plans: %v", err)
	}
	if planCount != 1 {
		t.Errorf("expected exactly 1 'Unlimited' reseller_plan, got %d", planCount)
	}

	var groupCount, ngTotal int
	db.QueryRowContext(ctx, `SELECT COUNT(*) FROM node_groups`).Scan(&ngTotal)
	if err := db.QueryRowContext(ctx, `SELECT COUNT(*) FROM reseller_plan_node_groups`).Scan(&groupCount); err != nil {
		t.Fatalf("count reseller_plan_node_groups: %v", err)
	}
	if groupCount != ngTotal {
		t.Errorf("expected Unlimited grant for every node_group (%d), got %d rows", ngTotal, groupCount)
	}

	var featureCount int
	if err := db.QueryRowContext(ctx, `SELECT COUNT(*) FROM reseller_plan_features`).Scan(&featureCount); err != nil {
		t.Fatalf("count reseller_plan_features: %v", err)
	}
	if featureCount != 12 {
		t.Errorf("expected 12 features granted to Unlimited, got %d", featureCount)
	}

	for _, q := range []struct{ col, dataType string }{
		{"reseller_plan_id", "bigint"}, {"owner_user_id", "bigint"},
		{"overselling_allowed", "tinyint"}, {"can_create_plans", "tinyint"},
	} {
		var n int
		var dt string
		if err := db.QueryRowContext(ctx,
			`SELECT COUNT(*), COALESCE(MAX(DATA_TYPE), '') FROM information_schema.COLUMNS
			 WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='resellers' AND COLUMN_NAME=?`, q.col).
			Scan(&n, &dt); err != nil {
			t.Fatalf("check resellers.%s: %v", q.col, err)
		}
		if n != 1 {
			t.Errorf("resellers.%s missing after migration", q.col)
		} else if dt != q.dataType {
			t.Errorf("resellers.%s has type %q, want %q", q.col, dt, q.dataType)
		}
	}

	for _, idx := range []string{"idx_resellers_plan", "idx_resellers_owner"} {
		var n int
		db.QueryRowContext(ctx,
			`SELECT COUNT(*) FROM information_schema.STATISTICS WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='resellers' AND INDEX_NAME=?`,
			idx).Scan(&n)
		if n < 1 {
			t.Errorf("index %s missing after migration", idx)
		}
	}

	var roleType string
	if err := db.QueryRowContext(ctx,
		`SELECT COLUMN_TYPE FROM information_schema.COLUMNS WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='users' AND COLUMN_NAME='role'`).
		Scan(&roleType); err != nil {
		t.Fatalf("check users.role: %v", err)
	}
	if !strings.Contains(roleType, "reseller") {
		t.Errorf("users.role does not include 'reseller' after migration: %s", roleType)
	}

	var unset int
	db.QueryRowContext(ctx, `SELECT COUNT(*) FROM resellers WHERE reseller_plan_id IS NULL`).Scan(&unset)
	if unset != 0 {
		t.Errorf("%d resellers still lack a reseller_plan_id after backfill", unset)
	}

	// F1 backfill semantics: owner = earliest (MIN id) user linked via reseller_id.
	var owner sql.NullInt64
	if err := db.QueryRowContext(ctx, `SELECT owner_user_id FROM resellers WHERE id=1`).Scan(&owner); err != nil {
		t.Fatalf("check owner_user_id: %v", err)
	}
	var wantOwner int64
	if err := db.QueryRowContext(ctx, `SELECT MIN(id) FROM users WHERE reseller_id=1`).Scan(&wantOwner); err != nil {
		t.Fatalf("compute expected owner: %v", err)
	}
	if !owner.Valid || owner.Int64 != wantOwner {
		t.Errorf("owner_user_id = %v, want %d (earliest linked user)", owner, wantOwner)
	}

	// F1 intentionally does NOT promote existing admins to role='reseller' yet
	// (guards still key off users.reseller_id; the flip is 00127/F2) - only the
	// enum VALUE is added, so no existing row's role should change.
	var nonAdmin int
	db.QueryRowContext(ctx, `SELECT COUNT(*) FROM users WHERE reseller_id=1 AND role<>'admin'`).Scan(&nonAdmin)
	if nonAdmin != 0 {
		t.Errorf("%d reseller-linked admins were unexpectedly flipped off 'admin'", nonAdmin)
	}
}

// HPG-015: migration 00126 must apply cleanly from scratch.
func TestMig126AppliesFromScratch(t *testing.T) {
	db := openIsolatedMySQLTestDB126(t)
	ctx := context.Background()
	seedMig126PrereqSchema(t, db, ctx)

	if _, err := db.ExecContext(ctx, mig126UpSQL(t)); err != nil {
		t.Fatalf("migration failed: %v", err)
	}
	assertMig126Applied(t, db, ctx)
}

// HPG-015: re-running the whole migration on an already-fully-applied DB must
// be a clean no-op, not an error - including the seed INSERTs (no second
// 'Unlimited' package, no duplicate grants) and the backfill UPDATEs.
func TestMig126IsFullyIdempotent(t *testing.T) {
	db := openIsolatedMySQLTestDB126(t)
	ctx := context.Background()
	seedMig126PrereqSchema(t, db, ctx)

	sqlText := mig126UpSQL(t)
	if _, err := db.ExecContext(ctx, sqlText); err != nil {
		t.Fatalf("first run: %v", err)
	}
	if _, err := db.ExecContext(ctx, sqlText); err != nil {
		t.Fatalf("second run (idempotency): %v", err)
	}
	assertMig126Applied(t, db, ctx)
}

// HPG-015 core regression: a run interrupted right after the three CREATE
// TABLEs (MySQL DDL implicit-commits, so that much survives a crash) must be
// resumable by simply re-running the same migration. This test first proves
// the PRE-FIX (unguarded) migration actually dies with "table already
// exists" in that exact scenario, then proves the current guarded file
// resumes cleanly from the same starting point.
func TestMig126ResumesAfterPartialApply(t *testing.T) {
	partialApply := func(t *testing.T, db *sql.DB, ctx context.Context) {
		t.Helper()
		for _, stmt := range []string{
			`CREATE TABLE reseller_plans (
				id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT, name VARCHAR(128) NOT NULL,
				max_clients INT NOT NULL DEFAULT 0, max_domains_total INT NOT NULL DEFAULT 0,
				max_services_total INT NOT NULL DEFAULT 0, rate_limit_rpm_cap INT NOT NULL DEFAULT 0,
				created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
				PRIMARY KEY (id), UNIQUE KEY uq_reseller_plan_name (name)
			) ENGINE=InnoDB`,
			`CREATE TABLE reseller_plan_node_groups (
				reseller_plan_id BIGINT UNSIGNED NOT NULL, node_group_id BIGINT UNSIGNED NOT NULL,
				PRIMARY KEY (reseller_plan_id, node_group_id),
				CONSTRAINT fk_rpng_plan FOREIGN KEY (reseller_plan_id) REFERENCES reseller_plans(id) ON DELETE CASCADE,
				CONSTRAINT fk_rpng_ng FOREIGN KEY (node_group_id) REFERENCES node_groups(id) ON DELETE CASCADE
			) ENGINE=InnoDB`,
			`CREATE TABLE reseller_plan_features (
				reseller_plan_id BIGINT UNSIGNED NOT NULL, feature VARCHAR(32) NOT NULL,
				PRIMARY KEY (reseller_plan_id, feature),
				CONSTRAINT fk_rpf_plan FOREIGN KEY (reseller_plan_id) REFERENCES reseller_plans(id) ON DELETE CASCADE
			) ENGINE=InnoDB`,
		} {
			if _, err := db.ExecContext(ctx, stmt); err != nil {
				t.Fatalf("simulate partial apply: %v", err)
			}
		}
	}

	t.Run("pre-fix migration dies on resume", func(t *testing.T) {
		db := openIsolatedMySQLTestDB126(t)
		ctx := context.Background()
		seedMig126PrereqSchema(t, db, ctx)
		partialApply(t, db, ctx)

		_, err := db.ExecContext(ctx, preFixMig126UpSQL(t))
		if err == nil {
			t.Fatal("expected the pre-fix migration to fail resuming from a partial apply, got no error")
		}
		if !strings.Contains(strings.ToLower(err.Error()), "already exists") {
			t.Fatalf("expected an 'already exists' error, got: %v", err)
		}
	})

	t.Run("guarded migration resumes cleanly", func(t *testing.T) {
		db := openIsolatedMySQLTestDB126(t)
		ctx := context.Background()
		seedMig126PrereqSchema(t, db, ctx)
		partialApply(t, db, ctx)

		if _, err := db.ExecContext(ctx, mig126UpSQL(t)); err != nil {
			t.Fatalf("resumed migration failed: %v", err)
		}
		assertMig126Applied(t, db, ctx)
	})
}

// HPG-015: a blind `IF NOT EXISTS` would silently accept a same-named table
// or column with the wrong shape. This must be a hard failure instead, so an
// operator investigates rather than the migrator quietly building on broken
// ground. Covers both a wrong-shaped new table and a wrong-typed added column.
func TestMig126RejectsWrongShapedObjects(t *testing.T) {
	t.Run("wrong-shaped reseller_plans table", func(t *testing.T) {
		db := openIsolatedMySQLTestDB126(t)
		ctx := context.Background()
		seedMig126PrereqSchema(t, db, ctx)

		if _, err := db.ExecContext(ctx, `CREATE TABLE reseller_plans (id BIGINT UNSIGNED PRIMARY KEY, name VARCHAR(128))`); err != nil {
			t.Fatalf("simulate wrong shape: %v", err)
		}

		if _, err := db.ExecContext(ctx, mig126UpSQL(t)); err == nil {
			t.Fatal("expected the migration to reject a wrong-shaped reseller_plans table, got no error")
		}
	})

	t.Run("wrong-typed resellers.reseller_plan_id column", func(t *testing.T) {
		db := openIsolatedMySQLTestDB126(t)
		ctx := context.Background()
		seedMig126PrereqSchema(t, db, ctx)

		if _, err := db.ExecContext(ctx, `ALTER TABLE resellers ADD COLUMN reseller_plan_id VARCHAR(32) NULL`); err != nil {
			t.Fatalf("simulate wrong type: %v", err)
		}

		if _, err := db.ExecContext(ctx, mig126UpSQL(t)); err == nil {
			t.Fatal("expected the migration to reject a wrong-typed reseller_plan_id column, got no error")
		}
	})
}
