package jobs

import (
	"bytes"
	"context"
	"database/sql"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	_ "github.com/go-sql-driver/mysql"

	"github.com/host-yt/caddy-proxy-manager/internal/backup"
	"github.com/host-yt/caddy-proxy-manager/internal/store"
	"github.com/host-yt/caddy-proxy-manager/internal/store/sqlitetest"
)

func TestAllowedDrillSQL(t *testing.T) {
	allowed := []string{
		"SET NAMES utf8mb4",
		"SET FOREIGN_KEY_CHECKS = 0",
		"SET SQL_MODE = 'NO_AUTO_VALUE_ON_ZERO'",
		"PRAGMA foreign_keys=OFF",
		"DROP TABLE IF EXISTS `users`",
		"CREATE TABLE `users` (\n  `id` bigint NOT NULL\n) ENGINE=InnoDB",
		"CREATE UNIQUE INDEX uq_x ON users (email)",
		"INSERT INTO `users` (`id`, `email`) VALUES\n(1,'a')",
		"INSERT INTO `users` (`id`) VALUES (1)",
	}
	denied := []string{
		"/* x */ DROP DATABASE hostyt_proxy",
		"DROP DATABASE hostyt_proxy",
		"DROP TABLE IF EXISTS `prod`.`users`",
		"INSERT INTO `prod`.`users` (`id`) VALUES (1)",
		"SET GLOBAL read_only = 1",
		"SET NAMES utf8mb4, GLOBAL read_only = 1",
		"ATTACH DATABASE '/data/panel.db' AS prod",
		"GRANT ALL ON *.* TO x",
		"CREATE TABLE `t` (a int) DATA DIRECTORY = '/var/lib'",
		"CREATE TABLE `t` (a int) ENGINE=FEDERATED CONNECTION='mysql://x'",
		"CREATE TABLE `t` (a int) SELECT * FROM prod.users",
		"CREATE PROCEDURE p() BEGIN END",
		"DELETE FROM `users`",
		"UPDATE `users` SET role='admin'",
	}
	for _, s := range allowed {
		if !allowedDrillSQL(s) {
			t.Errorf("rejected dumper statement: %q", s)
		}
	}
	for _, s := range denied {
		if allowedDrillSQL(s) {
			t.Errorf("allowed foreign statement: %q", s)
		}
	}
}

// Every statement our own dumpers produce for the full schema must pass the allowlist.
func TestAllowedDrillSQLAcceptsRealDumps(t *testing.T) {
	ctx := context.Background()
	check := func(name string, stmts []string) {
		n := 0
		for _, s := range stmts {
			s = stripLeadingComments(s)
			if s == "" {
				continue
			}
			n++
			if !allowedDrillSQL(s) {
				t.Errorf("%s: rejected %q", name, drillTruncate(s, 120))
			}
		}
		if n < 50 {
			t.Errorf("%s: only %d statements, dump looks empty", name, n)
		}
	}

	db := openDrillSQLite(t)
	var buf bytes.Buffer
	if err := backup.DumpDatabase(ctx, db, &buf); err != nil {
		t.Fatal(err)
	}
	check("sqlite", backup.SplitSQLStatements(buf.String()))

	dsn := os.Getenv("TEST_DB_DSN")
	if dsn == "" {
		t.Skip("TEST_DB_DSN not set - mysql half skipped")
	}
	store.SetDriver("mysql")
	my, err := sql.Open("mysql", dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer my.Close()
	buf.Reset()
	if err := backup.DumpDatabase(ctx, my, &buf); err != nil {
		t.Fatal(err)
	}
	store.SetDriver("sqlite3")
	check("mysql", strings.Split(buf.String(), ";\n"))
}

func openDrillSQLite(t *testing.T) *sql.DB {
	t.Helper()
	prev := store.Driver()
	store.SetDriver("sqlite3")
	t.Cleanup(func() { store.SetDriver(prev) })
	db, err := store.Open(context.Background(), "sqlite3", sqlitetest.MigratedCopy(t, "panel.db"), 10*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	return db
}

// End-to-end on SQLite: a real backup passes the drill, a modified artifact does not.
func TestRunDrillRejectsModifiedArtifact(t *testing.T) {
	db := openDrillSQLite(t)
	ctx := context.Background()
	root := t.TempDir()
	for _, q := range []string{
		`INSERT INTO users (email, password_hash, role) VALUES ('a@example.com', 'x', 'super_admin')`,
		`INSERT INTO backup_destinations (name, kind, config_enc) VALUES ('loc', 'local', 'plain:{"path":"` + root + `"}')`,
	} {
		if _, err := db.Exec(q); err != nil {
			t.Fatal(err)
		}
	}
	svc := &backup.Service{DB: func() *sql.DB { return db }, Logger: slog.Default()}
	if _, err := svc.Run(ctx, backup.RunOptions{DestinationID: 1}); err != nil {
		t.Fatalf("backup: %v", err)
	}
	j := &BackupDrillJob{DB: func() *sql.DB { return db }, Logger: slog.Default()}
	if _, err := j.runDrill(ctx); err != nil {
		t.Fatalf("drill on a genuine artifact: %v", err)
	}

	var key string
	if err := db.QueryRow(`SELECT artifact_key FROM backup_jobs WHERE status='succeeded'`).Scan(&key); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(root, key)
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	raw[len(raw)/2] ^= 0xff
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := j.runDrill(ctx); err == nil || !strings.Contains(err.Error(), "sha256 mismatch") {
		t.Fatalf("modified artifact: want sha256 mismatch, got %v", err)
	}
}
