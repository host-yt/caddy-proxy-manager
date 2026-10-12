package aitools

import (
	"context"
	"database/sql"
	"os"
	"testing"
	"time"

	_ "github.com/go-sql-driver/mysql"
)

// TestRouteDetailQueryRunsOnRealSchema catches columns that do not exist on
// routes: the tool used to select a plan-only column and failed every call.
func TestRouteDetailQueryRunsOnRealSchema(t *testing.T) {
	dsn := os.Getenv("TEST_DB_DSN")
	if dsn == "" {
		t.Skip("TEST_DB_DSN not set - skipping DB-backed test")
	}
	db, err := sql.Open("mysql", dsn)
	if err != nil {
		t.Fatalf("sql.Open: %v", err)
	}
	defer db.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := db.PingContext(ctx); err != nil {
		t.Skipf("DB not reachable: %v", err)
	}
	out, err := routeDetailQuery(ctx, db, []byte(`{"identifier":"zz-no-such-route.invalid"}`), "")
	if err != nil {
		t.Fatalf("route detail query failed: %v", err)
	}
	if out != `{"error":"route not found"}` {
		t.Fatalf("unexpected result %s", out)
	}
}
