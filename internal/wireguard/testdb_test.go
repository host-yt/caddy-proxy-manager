package wireguard

import (
	"context"
	"database/sql"
	"fmt"
	"os"
	"testing"
	"time"

	_ "github.com/go-sql-driver/mysql"
)

// openPSKTestDB opens TEST_DB_DSN or skips - same pattern as
// internal/nodejoin/service_test.go.
func openPSKTestDB(t *testing.T) *sql.DB {
	t.Helper()
	dsn := os.Getenv("TEST_DB_DSN")
	if dsn == "" {
		t.Skip("TEST_DB_DSN not set - skipping DB-backed test")
	}
	db, err := sql.Open("mysql", dsn)
	if err != nil {
		t.Fatalf("sql.Open: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := db.PingContext(ctx); err != nil {
		t.Skipf("DB not reachable: %v", err)
	}
	return db
}

func seedGroup(t *testing.T, db *sql.DB) int64 {
	t.Helper()
	res, err := db.ExecContext(context.Background(),
		"INSERT INTO node_groups (name) VALUES (?)", fmt.Sprintf("pskgrp_%d", time.Now().UnixNano()))
	if err != nil {
		t.Fatalf("insert node_group: %v", err)
	}
	id, _ := res.LastInsertId()
	return id
}
