package reseller

import (
	"context"
	"database/sql"
	"fmt"
	"os"
	"regexp"
	"testing"
	"time"

	_ "github.com/go-sql-driver/mysql"
)

// openIsolatedMySQLTestDB spins up a throw-away schema next to TEST_DB_DSN's
// target and drops it on cleanup, so this doesn't touch the shared fixture
// DB other packages' tests rely on.
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

	name := fmt.Sprintf("hpg_reseller_test_%d", time.Now().UnixNano())
	if _, err := base.Exec("CREATE DATABASE " + name); err != nil {
		base.Close()
		t.Skipf("cannot create isolated test database (need CREATE privilege): %v", err)
	}
	// DROP before Close - a deferred Close before this point ran at this
	// function's return and left the cleanup below dropping through an
	// already-closed *sql.DB, leaking every isolated test database this
	// ever created.
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

// HPG-016 cross-engine invariant: Store.Delete's explicit reseller_id
// cleanup must produce the same end state whether or not the engine also
// has a working ON DELETE SET NULL FK. This runs the exact shape migration
// 00124 creates on MySQL (FK included), so it proves the fix doesn't
// conflict with the FK there - the SQLite test in reseller_test.go proves
// the same assertions hold with no FK at all.
func TestDeleteResetsOwnershipMySQL(t *testing.T) {
	db := openIsolatedMySQLTestDB(t)
	ctx := context.Background()

	for _, stmt := range []string{
		`CREATE TABLE resellers (
			id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
			name VARCHAR(120) NOT NULL, slug VARCHAR(64) NOT NULL UNIQUE,
			status VARCHAR(16) NOT NULL DEFAULT 'active',
			brand_name VARCHAR(120) NULL, logo_url VARCHAR(512) NULL,
			support_email VARCHAR(255) NULL, primary_color VARCHAR(16) NULL
		) ENGINE=InnoDB`,
		`CREATE TABLE clients (id BIGINT UNSIGNED PRIMARY KEY, reseller_id BIGINT UNSIGNED NULL,
			CONSTRAINT fk_clients_reseller FOREIGN KEY (reseller_id) REFERENCES resellers(id) ON DELETE SET NULL) ENGINE=InnoDB`,
		`CREATE TABLE plans (id BIGINT UNSIGNED PRIMARY KEY, reseller_id BIGINT UNSIGNED NULL,
			CONSTRAINT fk_plans_reseller FOREIGN KEY (reseller_id) REFERENCES resellers(id) ON DELETE SET NULL) ENGINE=InnoDB`,
		`CREATE TABLE users (id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY, email VARCHAR(255) UNIQUE,
			password_hash VARCHAR(255), password_set TINYINT(1), role VARCHAR(32), full_name VARCHAR(255),
			is_active TINYINT(1), is_restricted TINYINT(1) NOT NULL DEFAULT 0, reseller_id BIGINT UNSIGNED NULL,
			CONSTRAINT fk_users_reseller FOREIGN KEY (reseller_id) REFERENCES resellers(id) ON DELETE SET NULL) ENGINE=InnoDB`,
		`INSERT INTO clients (id) VALUES (100)`,
		`INSERT INTO plans (id) VALUES (200)`,
	} {
		if _, err := db.ExecContext(ctx, stmt); err != nil {
			t.Fatalf("schema setup %q: %v", stmt, err)
		}
	}

	s := New(func() *sql.DB { return db })
	id, err := s.Create(ctx, Reseller{Name: "Acme", Slug: "acme"})
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if err := s.AssignClient(ctx, 100, &id); err != nil {
		t.Fatalf("assign client: %v", err)
	}
	if _, err := db.ExecContext(ctx, `UPDATE plans SET reseller_id=? WHERE id=200`, id); err != nil {
		t.Fatalf("seed plan ownership: %v", err)
	}

	if err := s.Delete(ctx, id); err != nil {
		t.Fatalf("delete: %v", err)
	}

	var clientReseller, planReseller sql.NullInt64
	if err := db.QueryRowContext(ctx, `SELECT reseller_id FROM clients WHERE id=100`).Scan(&clientReseller); err != nil {
		t.Fatalf("read client: %v", err)
	}
	if clientReseller.Valid {
		t.Errorf("clients.reseller_id left dangling at %d after reseller delete", clientReseller.Int64)
	}
	if err := db.QueryRowContext(ctx, `SELECT reseller_id FROM plans WHERE id=200`).Scan(&planReseller); err != nil {
		t.Fatalf("read plan: %v", err)
	}
	if planReseller.Valid {
		t.Errorf("plans.reseller_id left dangling at %d after reseller delete", planReseller.Int64)
	}
}
