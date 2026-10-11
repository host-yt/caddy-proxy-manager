package webhook

import (
	"context"
	"database/sql"
	"fmt"
	"os"
	"testing"
	"time"

	_ "github.com/go-sql-driver/mysql"
)

// A due delivery can be claimed exactly once until its lease expires.
func TestClaimIsExclusive(t *testing.T) {
	dsn := os.Getenv("TEST_DB_DSN")
	if dsn == "" {
		t.Skip("TEST_DB_DSN not set")
	}
	db, err := sql.Open("mysql", dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	ctx := context.Background()
	res, err := db.ExecContext(ctx,
		`INSERT INTO webhook_endpoints (name, url, events) VALUES (?, 'https://example.com/h', '*')`,
		fmt.Sprintf("claim-test-%d", time.Now().UnixNano()))
	if err != nil {
		t.Skipf("schema not migrated: %v", err)
	}
	epID, _ := res.LastInsertId()
	t.Cleanup(func() { _, _ = db.ExecContext(ctx, "DELETE FROM webhook_endpoints WHERE id = ?", epID) })
	res, err = db.ExecContext(ctx,
		`INSERT INTO webhook_deliveries (endpoint_id, event_type, payload, status, next_retry_at)
		 VALUES (?, 'x', '{}', 'pending', NOW())`, epID)
	if err != nil {
		t.Fatal(err)
	}
	id, _ := res.LastInsertId()

	s := &Service{DB: func() *sql.DB { return db }}
	if !s.claim(ctx, db, id) {
		t.Fatal("first claim failed")
	}
	if s.claim(ctx, db, id) {
		t.Fatal("second claim succeeded while leased")
	}
}
