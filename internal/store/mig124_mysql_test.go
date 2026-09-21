package store

import (
	"context"
	"database/sql"
	"fmt"
	"os"
	"regexp"
	"strings"
	"testing"
	"time"

	_ "github.com/go-sql-driver/mysql"
)

// openIsolatedMySQLTestDB spins up a throw-away schema next to TEST_DB_DSN's
// target and drops it on cleanup - this test runs raw DDL against a
// hand-built prerequisite schema, so it must not touch the shared fixture DB.
func openIsolatedMySQLTestDB(t *testing.T) *sql.DB {
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

	name := fmt.Sprintf("hpg_mig124_test_%d", time.Now().UnixNano())
	if _, err := base.Exec("CREATE DATABASE " + name); err != nil {
		base.Close()
		t.Skipf("cannot create isolated test database (need CREATE privilege): %v", err)
	}
	// DROP before Close - base was only deferred-closed before, which ran at
	// this function's return and left the later cleanup dropping through an
	// already-closed *sql.DB (silently, since its error went unchecked) and
	// leaking every isolated test database this ever created.
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

// mig124UpSQL returns the Up section of migrations/00124_resellers.sql, with
// the goose annotation lines stripped so it can be sent straight to MySQL.
func mig124UpSQL(t *testing.T) string {
	t.Helper()
	raw, err := os.ReadFile("../../migrations/00124_resellers.sql")
	if err != nil {
		t.Fatal(err)
	}
	up := string(raw)
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

func seedMig124PrereqSchema(t *testing.T, db *sql.DB, ctx context.Context) {
	t.Helper()
	for _, stmt := range []string{
		`CREATE TABLE clients (id BIGINT UNSIGNED PRIMARY KEY) ENGINE=InnoDB`,
		`CREATE TABLE plans (id BIGINT UNSIGNED PRIMARY KEY) ENGINE=InnoDB`,
		`CREATE TABLE users (id BIGINT UNSIGNED PRIMARY KEY) ENGINE=InnoDB`,
	} {
		if _, err := db.ExecContext(ctx, stmt); err != nil {
			t.Fatalf("prereq schema %q: %v", stmt, err)
		}
	}
}

func assertMig124Applied(t *testing.T, db *sql.DB, ctx context.Context) {
	t.Helper()
	for _, q := range []struct{ table, col string }{
		{"clients", "reseller_id"}, {"plans", "reseller_id"}, {"users", "reseller_id"},
	} {
		var n int
		if err := db.QueryRowContext(ctx,
			`SELECT COUNT(*) FROM information_schema.COLUMNS WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME=? AND COLUMN_NAME=?`,
			q.table, q.col).Scan(&n); err != nil {
			t.Fatalf("check %s.%s: %v", q.table, q.col, err)
		}
		if n != 1 {
			t.Errorf("%s.%s missing after migration", q.table, q.col)
		}
	}
	for _, q := range []struct{ table, fk string }{
		{"clients", "fk_clients_reseller"}, {"plans", "fk_plans_reseller"}, {"users", "fk_users_reseller"},
	} {
		var n int
		if err := db.QueryRowContext(ctx,
			`SELECT COUNT(*) FROM information_schema.TABLE_CONSTRAINTS WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME=? AND CONSTRAINT_NAME=? AND CONSTRAINT_TYPE='FOREIGN KEY'`,
			q.table, q.fk).Scan(&n); err != nil {
			t.Fatalf("check FK %s: %v", q.fk, err)
		}
		if n != 1 {
			t.Errorf("FK %s missing after migration", q.fk)
		}
	}
	var tables int
	db.QueryRowContext(ctx, `SELECT COUNT(*) FROM information_schema.TABLES WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='resellers'`).Scan(&tables)
	if tables != 1 {
		t.Error("resellers table missing after migration")
	}
}

// HPG-015: migration 00124 must apply cleanly from scratch.
func TestMig124AppliesFromScratch(t *testing.T) {
	db := openIsolatedMySQLTestDB(t)
	ctx := context.Background()
	seedMig124PrereqSchema(t, db, ctx)

	if _, err := db.ExecContext(ctx, mig124UpSQL(t)); err != nil {
		t.Fatalf("migration failed: %v", err)
	}
	assertMig124Applied(t, db, ctx)
}

// HPG-015: re-running the whole migration on an already-fully-applied DB
// (the case goose itself never exercises, since it records the version -
// but an operator re-running the raw SQL, or a future refactor of the
// runner, must not break) must be a clean no-op, not an error.
func TestMig124IsFullyIdempotent(t *testing.T) {
	db := openIsolatedMySQLTestDB(t)
	ctx := context.Background()
	seedMig124PrereqSchema(t, db, ctx)

	sqlText := mig124UpSQL(t)
	if _, err := db.ExecContext(ctx, sqlText); err != nil {
		t.Fatalf("first run: %v", err)
	}
	if _, err := db.ExecContext(ctx, sqlText); err != nil {
		t.Fatalf("second run (idempotency): %v", err)
	}
	assertMig124Applied(t, db, ctx)
}

// HPG-015 core regression: a run interrupted right after `CREATE TABLE
// resellers` (MySQL DDL implicit-commits, so that much survives a crash)
// must be resumable by simply re-running the same migration - the original
// unguarded version failed here with "table already exists" and halted the
// whole migrator.
func TestMig124ResumesAfterPartialApply(t *testing.T) {
	db := openIsolatedMySQLTestDB(t)
	ctx := context.Background()
	seedMig124PrereqSchema(t, db, ctx)

	// Simulate exactly what an interrupt after the first DDL statement
	// leaves behind: `resellers` exists, correctly shaped, but none of the
	// clients/plans/users ALTERs ran yet.
	if _, err := db.ExecContext(ctx, `CREATE TABLE resellers (
		id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
		name VARCHAR(120) NOT NULL, slug VARCHAR(64) NOT NULL,
		status ENUM('active','suspended') NOT NULL DEFAULT 'active',
		brand_name VARCHAR(120) NULL, logo_url VARCHAR(512) NULL,
		support_email VARCHAR(255) NULL, primary_color VARCHAR(16) NULL,
		created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
		updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
		UNIQUE KEY uq_reseller_slug (slug)
	) ENGINE=InnoDB`); err != nil {
		t.Fatalf("simulate partial apply: %v", err)
	}

	if _, err := db.ExecContext(ctx, mig124UpSQL(t)); err != nil {
		t.Fatalf("resumed migration failed: %v", err)
	}
	assertMig124Applied(t, db, ctx)
}

// HPG-015: a blind `IF NOT EXISTS` would silently accept a same-named table
// with the wrong shape. This must be a hard failure instead, so an operator
// investigates rather than the migrator quietly building on broken ground.
func TestMig124RejectsWrongShapedResellersTable(t *testing.T) {
	db := openIsolatedMySQLTestDB(t)
	ctx := context.Background()
	seedMig124PrereqSchema(t, db, ctx)

	// A `resellers` table missing most of the expected columns - not what
	// this migration would ever have created.
	if _, err := db.ExecContext(ctx, `CREATE TABLE resellers (id BIGINT UNSIGNED PRIMARY KEY, name VARCHAR(120))`); err != nil {
		t.Fatalf("simulate wrong shape: %v", err)
	}

	if _, err := db.ExecContext(ctx, mig124UpSQL(t)); err == nil {
		t.Fatal("expected the migration to reject a wrong-shaped resellers table, got no error")
	}
}
