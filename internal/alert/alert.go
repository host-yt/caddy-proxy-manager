// Package alert is a leader-only background evaluator that checks a fixed
// set of rules against existing DB state every tick and fans out fired
// alerts via the existing webhook/mail/sms seams. A dedupe/cooldown layer
// backed by alert_log prevents repeat-alert spam.
package alert

import (
	"context"
	"database/sql"
	"log/slog"
	"strconv"
	"strings"

	"github.com/host-yt/caddy-proxy-manager/internal/mail"
	"github.com/host-yt/caddy-proxy-manager/internal/sms"
	"github.com/host-yt/caddy-proxy-manager/internal/webhook"
)

// Severity is the alert urgency, mirroring the alert_log ENUM.
type Severity string

const (
	SeverityInfo     Severity = "info"
	SeverityWarning  Severity = "warning"
	SeverityCritical Severity = "critical"
)

// Alert is a fired rule instance.
type Alert struct {
	RuleID   string // stable snake_case key, e.g. "node_offline"
	Severity Severity
	Title    string
	Detail   string            // human-readable context
	Labels   map[string]string // e.g. {"node_id":"3","node_name":"eu-1"}
}

// NodeResyncer is the narrow interface the failover logic needs from routes.Service.
type NodeResyncer interface {
	Resync(ctx context.Context, nodeID int64) error
}

// Evaluator holds dependencies; created once in main.go. Every external
// dep is nil-safe so the ticker degrades gracefully before wiring is live.
type Evaluator struct {
	DB       func() *sql.DB
	Logger   *slog.Logger
	Webhooks *webhook.Service
	Mailer   *mail.Mailer
	SMS      *sms.Sender
	Cfg      Config
	RouteSvc NodeResyncer // nil-safe; needed only when AutoFailoverEnabled
}

// Tick is the per-interval entry point called by the leader ticker.
func (e *Evaluator) Tick(ctx context.Context) {
	if e.DB == nil {
		return
	}
	db := e.DB()
	if db == nil {
		return
	}
	for _, a := range e.evaluate(ctx, db) {
		e.dispatch(ctx, db, a)
	}
	e.pruneLog(ctx, db)
}

// mergedCfg returns e.Cfg overlaid with any DB overrides from the settings table.
func (e *Evaluator) mergedCfg(ctx context.Context, db *sql.DB) Config {
	cfg := e.Cfg
	readInt := func(key string, dest *int) {
		var s string
		if db.QueryRowContext(ctx, "SELECT value FROM settings WHERE `key`=?", key).Scan(&s) == nil {
			if n, err := strconv.Atoi(strings.TrimSpace(s)); err == nil && n > 0 {
				*dest = n
			}
		}
	}
	readFloat := func(key string, dest *float64) {
		var s string
		if db.QueryRowContext(ctx, "SELECT value FROM settings WHERE `key`=?", key).Scan(&s) == nil {
			if f, err := strconv.ParseFloat(strings.TrimSpace(s), 64); err == nil && f > 0 {
				*dest = f
			}
		}
	}
	readInt("alert.node_offline_minutes", &cfg.NodeOfflineMinutes)
	readInt("alert.cert_stuck_minutes", &cfg.CertStuckMinutes)
	readInt("alert.cooldown_seconds", &cfg.CooldownSeconds)
	readInt("alert.manual_cert_days_warn", &cfg.ManualCertDaysWarn)
	readInt("alert.error_rate_window_minutes", &cfg.ErrorRateWindowMinutes)
	readFloat("alert.error_rate_pct", &cfg.ErrorRatePct)
	return cfg
}

// evaluate runs every rule against the current DB snapshot.
func (e *Evaluator) evaluate(ctx context.Context, db *sql.DB) []Alert {
	cfg := e.mergedCfg(ctx, db)
	var out []Alert
	out = append(out, nodeOffline(ctx, db, cfg)...)
	out = append(out, routeFailed(ctx, db, cfg)...)
	out = append(out, certFailing(ctx, db, cfg)...)
	out = append(out, wgTunnelStale(ctx, db, cfg)...)
	out = append(out, dbPoolSaturated(ctx, db, cfg)...)
	out = append(out, drillStale(ctx, db, cfg)...)
	out = append(out, wgKeyNotFetched(ctx, db, cfg, e.Logger)...)
	out = append(out, manualCertExpiry(ctx, db, cfg, e.Logger)...)
	out = append(out, highErrorRate(ctx, db, cfg)...)
	out = append(out, wafAttackSurge(ctx, db, cfg)...)
	return out
}
