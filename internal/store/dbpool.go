package store

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	_ "github.com/go-sql-driver/mysql"
)

// Open opens a MySQL/MariaDB pool with sensible defaults and pings until
// timeout. Returns the *sql.DB ready to use.
func Open(ctx context.Context, dsn string, timeout time.Duration) (*sql.DB, error) {
	db, err := sql.Open("mysql", dsn)
	if err != nil {
		return nil, fmt.Errorf("sql open: %w", err)
	}
	// Sized for: 6 leader-only background workers + burst logins (each may
	// hold a conn through an Argon2 verify) + concurrent admin/client page
	// loads + Prometheus gauge callbacks. 25 saturated under modest login
	// bursts and starved the background sweeps (they appeared hung).
	db.SetMaxOpenConns(50)
	db.SetMaxIdleConns(15)
	// Shorter lifetime detects stale conns (failovered DB, restarted proxy)
	// faster and recycles idle ones sooner.
	db.SetConnMaxLifetime(15 * time.Minute)
	db.SetConnMaxIdleTime(3 * time.Minute)

	pingCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	for {
		err := db.PingContext(pingCtx)
		if err == nil {
			return db, nil
		}
		if pingCtx.Err() != nil {
			_ = db.Close()
			return nil, fmt.Errorf("db ping timeout: %w", err)
		}
		time.Sleep(500 * time.Millisecond)
	}
}

// Ping is a one-shot connectivity test without holding the pool.
// Used by the install wizard to validate a DSN before saving.
func Ping(ctx context.Context, dsn string) error {
	db, err := sql.Open("mysql", dsn)
	if err != nil {
		return fmt.Errorf("sql open: %w", err)
	}
	defer db.Close()
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	if err := db.PingContext(ctx); err != nil {
		return fmt.Errorf("ping: %w", err)
	}
	return nil
}
