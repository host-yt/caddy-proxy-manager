package alert

import (
	"os"
	"strconv"
)

// Config holds tunable thresholds, loaded once from env at boot.
type Config struct {
	// A node must be unhealthy for at least this long before alerting.
	NodeOfflineMinutes int // ALERT_NODE_OFFLINE_MIN, default 5
	// WG handshake older than this is "stale".
	WGStaleSeconds int // ALERT_WG_STALE_SEC, default 300
	// Cert stuck in pending_ssl longer than this is "failing".
	CertStuckMinutes int // ALERT_CERT_STUCK_MIN, default 30
	// DB pool: ratio open/MaxOpenConns at/above this triggers.
	DBPoolSaturationPct float64 // ALERT_DB_POOL_PCT, default 0.90
	// Minimum seconds between repeated fires of the same rule+label.
	CooldownSeconds int // ALERT_COOLDOWN_SEC, default 1800
	// Days of alert_log history to retain.
	RetentionDays int // ALERT_RETENTION_DAYS, default 90
	// Admin email override; empty = first active super_admin from DB.
	AdminEmail string // ALERT_ADMIN_EMAIL
	// Admin phone for SMS; empty = skip SMS fanout.
	AdminPhone string // ALERT_ADMIN_PHONE
}

// LoadConfig reads env with sane defaults. Invalid numerics fall back to
// the default rather than erroring - alerting must never block boot.
func LoadConfig() Config {
	return Config{
		NodeOfflineMinutes:  envInt("ALERT_NODE_OFFLINE_MIN", 5),
		WGStaleSeconds:      envInt("ALERT_WG_STALE_SEC", 300),
		CertStuckMinutes:    envInt("ALERT_CERT_STUCK_MIN", 30),
		DBPoolSaturationPct: envFloat("ALERT_DB_POOL_PCT", 0.90),
		CooldownSeconds:     envInt("ALERT_COOLDOWN_SEC", 1800),
		RetentionDays:       envInt("ALERT_RETENTION_DAYS", 90),
		AdminEmail:          os.Getenv("ALERT_ADMIN_EMAIL"),
		AdminPhone:          os.Getenv("ALERT_ADMIN_PHONE"),
	}
}

func envInt(key string, def int) int {
	if v := os.Getenv(key); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			return n
		}
	}
	return def
}

func envFloat(key string, def float64) float64 {
	if v := os.Getenv(key); v != "" {
		if f, err := strconv.ParseFloat(v, 64); err == nil && f > 0 {
			return f
		}
	}
	return def
}
