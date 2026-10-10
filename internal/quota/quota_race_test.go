package quota

import (
	"context"
	"database/sql"
	"fmt"
	"os"
	"sync"
	"testing"
	"time"

	_ "github.com/go-sql-driver/mysql"

	"github.com/host-yt/caddy-proxy-manager/internal/store"
)

// Parallel client creates under a 1-client package must not all see the free slot.
func TestConcurrentClientCreateHonoursQuota(t *testing.T) {
	dsn := os.Getenv("TEST_DB_DSN")
	if dsn == "" {
		t.Skip("TEST_DB_DSN not set - skipping DB-backed test")
	}
	db, err := sql.Open("mysql", dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	store.SetDriver("mysql")
	ctx := context.Background()
	tag := fmt.Sprintf("qrace%d", time.Now().UnixNano())

	res, err := db.ExecContext(ctx, `INSERT INTO reseller_plans (name, max_clients, max_services_total, max_domains_total) VALUES (?, 1, 0, 0)`, tag)
	if err != nil {
		t.Fatal(err)
	}
	planID, _ := res.LastInsertId()
	res, err = db.ExecContext(ctx, `INSERT INTO resellers (name, slug, reseller_plan_id) VALUES (?, ?, ?)`, tag, tag, planID)
	if err != nil {
		t.Fatal(err)
	}
	rid, _ := res.LastInsertId()
	t.Cleanup(func() {
		db.Exec(`DELETE c, u FROM clients c JOIN users u ON u.id = c.user_id WHERE c.reseller_id=?`, rid)
		db.Exec(`DELETE FROM resellers WHERE id=?`, rid)
		db.Exec(`DELETE FROM reseller_plans WHERE id=?`, planID)
	})

	q := &Service{DB: func() *sql.DB { return db }}
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			tx, err := db.BeginTx(ctx, nil)
			if err != nil {
				return
			}
			defer tx.Rollback() //nolint:errcheck
			if q.CanCreateClient(ctx, tx, rid) != nil {
				return
			}
			res, err := tx.ExecContext(ctx, `INSERT INTO users (email, password_hash, role) VALUES (?, 'x', 'client')`,
				fmt.Sprintf("%s-%d@example.test", tag, i))
			if err != nil {
				return
			}
			uid, _ := res.LastInsertId()
			if _, err := tx.ExecContext(ctx, `INSERT INTO clients (user_id, display_name, reseller_id) VALUES (?, ?, ?)`, uid, tag, rid); err != nil {
				return
			}
			tx.Commit() //nolint:errcheck
		}(i)
	}
	wg.Wait()
	var n int
	if err := db.QueryRowContext(ctx, `SELECT COUNT(*) FROM clients WHERE reseller_id=?`, rid).Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != 1 {
		t.Fatalf("max_clients=1 but %d clients committed", n)
	}
}
