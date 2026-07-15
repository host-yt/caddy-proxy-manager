package store

import (
	"fmt"
	"strings"
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

// ForUpdate returns the row-lock clause. SQLite has no such syntax and needs
// none: the pool holds a single writer connection, so the read and the write it
// guards cannot interleave with another transaction.
func ForUpdate() string {
	if Driver() == "sqlite3" {
		return ""
	}
	return " FOR UPDATE"
}

// IntDiv returns the integer-division operator. MySQL's "/" yields a decimal
// (which then fails an int64 scan), hence DIV; SQLite's "/" is already integer
// division when both operands are integers.
func IntDiv() string {
	if Driver() == "sqlite3" {
		return "/"
	}
	return "DIV"
}

// Upsert returns the "insert or update the existing row" clause for an INSERT.
// conflictCols names the unique key the insert may collide on - MySQL infers it
// from the table, SQLite requires it spelled out. Each assignment is a bare
// column name; both dialects then set it from the row that was being inserted.
func Upsert(conflictCols string, assignments ...string) string {
	if len(assignments) == 0 {
		return ""
	}
	var b strings.Builder
	if Driver() == "sqlite3" {
		b.WriteString("ON CONFLICT(" + conflictCols + ") DO UPDATE SET ")
		for i, col := range assignments {
			if i > 0 {
				b.WriteString(", ")
			}
			b.WriteString(col + "=excluded." + col)
		}
		return b.String()
	}
	b.WriteString("ON DUPLICATE KEY UPDATE ")
	for i, col := range assignments {
		if i > 0 {
			b.WriteString(", ")
		}
		b.WriteString(col + "=VALUES(" + col + ")")
	}
	return b.String()
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
