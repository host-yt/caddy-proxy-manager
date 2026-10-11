package backup

import (
	"bytes"
	"context"
	"database/sql"
	"fmt"
	"os"
	"regexp"
	"strings"
	"testing"
	"time"

	_ "github.com/go-sql-driver/mysql"

	"github.com/host-yt/caddy-proxy-manager/internal/store"
)

// openIsolatedMySQLTestDB spins up a throw-away schema next to TEST_DB_DSN's
// target and drops it on cleanup. The dump snapshot test writes concurrently
// while dumping, so it must not run against the shared fixture DB other
// packages' tests rely on.
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

	name := fmt.Sprintf("hpg_backup_dump_test_%d", time.Now().UnixNano())
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

// HPG-012: the dump must read every table from one consistent snapshot, not
// one autocommit SELECT per table. This proves it directly: pin a snapshot
// via the same connection dumpRows uses, commit a write from a completely
// separate connection, then dump through the pinned connection and assert
// the write is invisible - exactly what a real backup must guarantee so it
// never captures a combination of rows that never coexisted.
func TestDumpMySQLSnapshotIsolatesConcurrentWrites(t *testing.T) {
	prev := store.Driver()
	store.SetDriver("mysql")
	t.Cleanup(func() { store.SetDriver(prev) })

	db := openIsolatedMySQLTestDB(t)
	ctx := context.Background()

	if _, err := db.ExecContext(ctx, "CREATE TABLE t1 (id INT PRIMARY KEY, name VARCHAR(32)) ENGINE=InnoDB"); err != nil {
		t.Fatalf("create table: %v", err)
	}
	if _, err := db.ExecContext(ctx, "INSERT INTO t1 (id, name) VALUES (1, 'before')"); err != nil {
		t.Fatalf("seed row: %v", err)
	}

	conn, err := db.Conn(ctx)
	if err != nil {
		t.Fatalf("db.Conn: %v", err)
	}
	defer conn.Close()

	// Pin the snapshot exactly as dumpMySQL does, before the concurrent write.
	if _, err := conn.ExecContext(ctx, "SET TRANSACTION ISOLATION LEVEL REPEATABLE READ"); err != nil {
		t.Fatalf("set isolation: %v", err)
	}
	if _, err := conn.ExecContext(ctx, "START TRANSACTION WITH CONSISTENT SNAPSHOT, READ ONLY"); err != nil {
		t.Fatalf("start snapshot: %v", err)
	}
	defer conn.ExecContext(context.Background(), "ROLLBACK")

	// A totally separate connection commits a new row AFTER the snapshot
	// was pinned - this must never show up in the dump read through conn.
	if _, err := db.ExecContext(ctx, "INSERT INTO t1 (id, name) VALUES (2, 'after-snapshot')"); err != nil {
		t.Fatalf("concurrent insert: %v", err)
	}

	var buf bytes.Buffer
	if err := dumpRows(ctx, conn, "t1", &buf); err != nil {
		t.Fatalf("dumpRows: %v", err)
	}
	dump := buf.String()
	if strings.Contains(dump, "after-snapshot") {
		t.Fatalf("dump saw a row committed after its snapshot was pinned:\n%s", dump)
	}
	if !strings.Contains(dump, "before") {
		t.Fatalf("dump missing the pre-snapshot row:\n%s", dump)
	}

	// Contrast: reading straight from the pool (the pre-fix behavior - one
	// autocommit SELECT per table, no pinned snapshot) DOES see the
	// concurrent write. This is what proves the isolation above comes from
	// the snapshot, not from timing luck - and is exactly the HPG-012 bug.
	var plain bytes.Buffer
	if err := dumpRows(ctx, db, "t1", &plain); err != nil {
		t.Fatalf("dumpRows via pool: %v", err)
	}
	if !strings.Contains(plain.String(), "after-snapshot") {
		t.Fatalf("expected the unpinned pool read to see the concurrent write (sanity check of the test itself)")
	}
}

// End-to-end sanity: DumpDatabase itself (the real entry point, including
// connection acquisition and the transaction wrapper) still produces a
// restorable dump against a real MySQL/MariaDB server.
func TestDumpMySQLEndToEnd(t *testing.T) {
	prev := store.Driver()
	store.SetDriver("mysql")
	t.Cleanup(func() { store.SetDriver(prev) })

	db := openIsolatedMySQLTestDB(t)
	ctx := context.Background()

	if _, err := db.ExecContext(ctx, "CREATE TABLE items (id INT PRIMARY KEY, label VARCHAR(64))"); err != nil {
		t.Fatalf("create table: %v", err)
	}
	if _, err := db.ExecContext(ctx, "INSERT INTO items (id, label) VALUES (1, 'a'), (2, 'b')"); err != nil {
		t.Fatalf("seed: %v", err)
	}

	var buf bytes.Buffer
	if err := DumpDatabase(ctx, db, &buf); err != nil {
		t.Fatalf("DumpDatabase: %v", err)
	}
	dump := buf.String()
	if !strings.Contains(dump, "CREATE TABLE") || !strings.Contains(dump, "INSERT INTO `items`") {
		t.Fatalf("dump missing expected content:\n%s", dump)
	}

	// The connection must be usable afterwards - a leaked open transaction
	// would leave it stuck and block later queries on the (size-1 for
	// sqlite, pooled for mysql) connection.
	var n int
	if err := db.QueryRowContext(ctx, "SELECT COUNT(*) FROM items").Scan(&n); err != nil {
		t.Fatalf("post-dump query: %v", err)
	}
	if n != 2 {
		t.Fatalf("post-dump query got %d rows, want 2", n)
	}
}

// Binary columns must survive dump+replay byte-for-byte, including bytes that
// are invalid utf8mb4 or would need escaping in a quoted literal.
func TestDumpMySQLBinaryColumnsRoundTrip(t *testing.T) {
	prev := store.Driver()
	store.SetDriver("mysql")
	t.Cleanup(func() { store.SetDriver(prev) })

	db := openIsolatedMySQLTestDB(t)
	ctx := context.Background()

	if _, err := db.ExecContext(ctx, `CREATE TABLE bin (id INT PRIMARY KEY,
		b BINARY(16), vb VARBINARY(64), bl BLOB, mbl MEDIUMBLOB, txt VARCHAR(32))`); err != nil {
		t.Fatalf("create table: %v", err)
	}
	val := []byte("\x00\xff\xfe'\\\"\n\r\x1a;\x80\xc3(abc")
	if _, err := db.ExecContext(ctx, "INSERT INTO bin VALUES (1, ?, ?, ?, ?, ?)",
		val, val, val, val, "plain 'text'"); err != nil {
		t.Fatalf("seed: %v", err)
	}

	var buf bytes.Buffer
	if err := DumpDatabase(ctx, db, &buf); err != nil {
		t.Fatalf("DumpDatabase: %v", err)
	}
	if _, err := db.ExecContext(ctx, "DROP TABLE bin"); err != nil {
		t.Fatalf("drop: %v", err)
	}
	conn, err := db.Conn(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	for _, stmt := range SplitSQLStatements(buf.String()) {
		if _, err := conn.ExecContext(ctx, stmt); err != nil {
			t.Fatalf("replay %q: %v", stmt, err)
		}
	}

	var b, vb, bl, mbl []byte
	var txt string
	if err := db.QueryRowContext(ctx, "SELECT b, vb, bl, mbl, txt FROM bin WHERE id=1").
		Scan(&b, &vb, &bl, &mbl, &txt); err != nil {
		t.Fatalf("select: %v", err)
	}
	for name, got := range map[string][]byte{"binary": b, "varbinary": vb, "blob": bl, "mediumblob": mbl} {
		if !bytes.Equal(got, val) {
			t.Errorf("%s: got %x want %x", name, got, val)
		}
	}
	if txt != "plain 'text'" {
		t.Errorf("text column: got %q", txt)
	}
}
