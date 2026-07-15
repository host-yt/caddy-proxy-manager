package store

import (
	"fmt"
	"sync"
)

var (
	driverMu sync.RWMutex
	active   = "mysql"
)

// SetDriver records the active DB driver. Called once in Open().
func SetDriver(d string) {
	driverMu.Lock()
	active = d
	driverMu.Unlock()
}

// Driver returns the active DB driver: "mysql" or "sqlite3".
func Driver() string {
	driverMu.RLock()
	defer driverMu.RUnlock()
	return active
}

// InsertOrIgnore returns "INSERT OR IGNORE" for sqlite3, "INSERT IGNORE" otherwise.
func InsertOrIgnore() string {
	if Driver() == "sqlite3" {
		return "INSERT OR IGNORE"
	}
	return "INSERT IGNORE"
}

// UpsertSettingSQL returns a full INSERT...upsert SQL for the settings table.
// The settings table has PRIMARY KEY on `key`.
func UpsertSettingSQL() string {
	if Driver() == "sqlite3" {
		return `INSERT INTO settings ("key", value, is_encrypted) VALUES (?, ?, ?) ON CONFLICT("key") DO UPDATE SET value=excluded.value, is_encrypted=excluded.is_encrypted`
	}
	return "INSERT INTO settings (`key`, value, is_encrypted) VALUES (?, ?, ?) ON DUPLICATE KEY UPDATE value=VALUES(value), is_encrypted=VALUES(is_encrypted)"
}

// sqliteUnit maps a MySQL INTERVAL unit to SQLite's datetime() modifier.
var sqliteUnit = map[string]string{
	"SECOND": "seconds", "MINUTE": "minutes", "HOUR": "hours", "DAY": "days",
}

// DateSub returns SQL for "NOW() - INTERVAL n <unit>". SQLite parses no INTERVAL
// keyword, so registering functions cannot cover this - the expression itself
// has to differ per dialect. unit is one of SECOND/MINUTE/HOUR/DAY.
func DateSub(n int, unit string) string {
	if Driver() == "sqlite3" {
		return fmt.Sprintf("datetime('now', '-%d %s')", n, sqliteUnit[unit])
	}
	return fmt.Sprintf("(NOW() - INTERVAL %d %s)", n, unit)
}

// DateSubParam is DateSub with the amount bound as a parameter.
func DateSubParam(unit string) string {
	if Driver() == "sqlite3" {
		return "datetime('now', '-' || cast(? as text) || ' " + sqliteUnit[unit] + "')"
	}
	return "(NOW() - INTERVAL ? " + unit + ")"
}

// DateAdd returns SQL for "NOW() + INTERVAL n <unit>".
func DateAdd(n int, unit string) string {
	if Driver() == "sqlite3" {
		return fmt.Sprintf("datetime('now', '+%d %s')", n, sqliteUnit[unit])
	}
	return fmt.Sprintf("(NOW() + INTERVAL %d %s)", n, unit)
}

// DateAddParam is DateAdd with the amount bound as a parameter.
func DateAddParam(unit string) string {
	if Driver() == "sqlite3" {
		return "datetime('now', '+' || cast(? as text) || ' " + sqliteUnit[unit] + "')"
	}
	return "(NOW() + INTERVAL ? " + unit + ")"
}

// Now returns the dialect's current-timestamp expression.
func Now() string {
	if Driver() == "sqlite3" {
		return "CURRENT_TIMESTAMP"
	}
	return "NOW()"
}

// DateAddMinutes returns SQL expr for NOW() + N minutes (OTP expiry paths).
func DateAddMinutes(n int) string {
	if Driver() == "sqlite3" {
		return fmt.Sprintf("datetime('now', '+%d minutes')", n)
	}
	return fmt.Sprintf("DATE_ADD(NOW(), INTERVAL %d MINUTE)", n)
}

// DateAddDaysParam returns SQL expr for NOW() + ? days (parameterized interval).
func DateAddDaysParam() string {
	if Driver() == "sqlite3" {
		return "datetime('now', '+' || cast(? as text) || ' days')"
	}
	return "NOW() + INTERVAL ? DAY"
}

// DateAddSecondsParam returns SQL expr for NOW() + ? seconds (webhook retry).
func DateAddSecondsParam() string {
	if Driver() == "sqlite3" {
		return "datetime('now', '+' || cast(? as text) || ' seconds')"
	}
	return "NOW() + INTERVAL ? SECOND"
}
