package store

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	_ "github.com/go-sql-driver/mysql"
	_ "modernc.org/sqlite"
)

// sqlDriverName maps our driver name to the sql.Open driver name.
func sqlDriverName(driver string) string {
	if driver == "sqlite3" {
		// modernc.org/sqlite registers as "sqlite".
		return "sqlite"
	}
	return "mysql"
}

// Open opens a DB pool for the given driver with sensible defaults and pings until
// timeout. Returns the *sql.DB ready to use.
func Open(ctx context.Context, driver, dsn string, timeout time.Duration) (*sql.DB, error) {
	db, err := sql.Open(sqlDriverName(driver), dsn)
	if err != nil {
		return nil, fmt.Errorf("sql open: %w", err)
	}

	if driver == "sqlite3" {
		// SQLite is single-writer; one open conn avoids SQLITE_BUSY races.
		// ForUpdate() also leans on this: it drops the FOR UPDATE clause on
		// SQLite precisely because a single connection means the read and the
		// write it guards cannot interleave. Raising this limit reintroduces
		// the races those row locks prevent on MySQL.
		db.SetMaxOpenConns(1)
		db.SetMaxIdleConns(1)
	} else {
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
	}

	SetDriver(driver)

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
func Ping(ctx context.Context, driver, dsn string) error {
	db, err := sql.Open(sqlDriverName(driver), dsn)
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
