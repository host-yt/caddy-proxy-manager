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
	// Telegram bot token; empty = skip Telegram fanout.
	TelegramBotToken string // ALERT_TELEGRAM_BOT_TOKEN
	// Telegram chat ID or @channel; empty = skip Telegram fanout.
	TelegramChatID string // ALERT_TELEGRAM_CHAT_ID
	// Alert when last successful restore drill is older than this many days.
	DrillStaleDays int // ALERT_DRILL_STALE_DAYS, default 7
	// Hours after rotation before alerting that customer never fetched new config.
	WGRotationFetchGraceHours int // ALERT_WG_FETCH_GRACE_HOURS, default 48
	// Days before expiry to alert for manually imported certs.
	ManualCertDaysWarn int // ALERT_MANUAL_CERT_DAYS_WARN, default 30
	// 5xx ratio (0-1) within the window that triggers a high-error-rate alert.
	ErrorRatePct float64 // ALERT_ERROR_RATE_PCT, default 0.25
	// Rolling window size for the error rate calculation.
	ErrorRateWindowMinutes int // ALERT_ERROR_RATE_WINDOW_MIN, default 10
	// Minimum requests in the window required before the rule can fire.
	ErrorRateMinRequests int // ALERT_ERROR_RATE_MIN_REQS, default 10
	// Move routes to a healthy sibling on node_offline when true.
	AutoFailoverEnabled bool // ENABLE_AUTO_FAILOVER, default false
	// Rolling window (minutes) for WAF block-surge detection.
	WAFSurgeWindowMinutes int // ALERT_WAF_SURGE_WINDOW_MIN, default 5
	// Number of WAF blocks in the window that triggers a waf_attack_surge alert.
	WAFSurgeThreshold int // ALERT_WAF_SURGE_THRESHOLD, default 50
}

// LoadConfig reads env with sane defaults. Invalid numerics fall back to
// the default rather than erroring - alerting must never block boot.
func LoadConfig() Config {
	return Config{
		NodeOfflineMinutes:        envInt("ALERT_NODE_OFFLINE_MIN", 5),
		WGStaleSeconds:            envInt("ALERT_WG_STALE_SEC", 300),
		CertStuckMinutes:          envInt("ALERT_CERT_STUCK_MIN", 30),
		DBPoolSaturationPct:       envFloat("ALERT_DB_POOL_PCT", 0.90),
		CooldownSeconds:           envInt("ALERT_COOLDOWN_SEC", 1800),
		RetentionDays:             envInt("ALERT_RETENTION_DAYS", 90),
		AdminEmail:                os.Getenv("ALERT_ADMIN_EMAIL"),
		AdminPhone:                os.Getenv("ALERT_ADMIN_PHONE"),
		TelegramBotToken:          os.Getenv("ALERT_TELEGRAM_BOT_TOKEN"),
		TelegramChatID:            os.Getenv("ALERT_TELEGRAM_CHAT_ID"),
		DrillStaleDays:            envInt("ALERT_DRILL_STALE_DAYS", 7),
		WGRotationFetchGraceHours: envInt("ALERT_WG_FETCH_GRACE_HOURS", 48),
		ManualCertDaysWarn:        envInt("ALERT_MANUAL_CERT_DAYS_WARN", 30),
		ErrorRatePct:              envFloat("ALERT_ERROR_RATE_PCT", 0.25),
		ErrorRateWindowMinutes:    envInt("ALERT_ERROR_RATE_WINDOW_MIN", 10),
		ErrorRateMinRequests:      envInt("ALERT_ERROR_RATE_MIN_REQS", 10),
		AutoFailoverEnabled:       os.Getenv("ENABLE_AUTO_FAILOVER") == "1",
		WAFSurgeWindowMinutes:     envInt("ALERT_WAF_SURGE_WINDOW_MIN", 5),
		WAFSurgeThreshold:         envInt("ALERT_WAF_SURGE_THRESHOLD", 50),
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
