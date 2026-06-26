// Package alert is a leader-only background evaluator that checks a fixed
// set of rules against existing DB state every tick and fans out fired
// alerts via the existing webhook/mail/sms seams. A dedupe/cooldown layer
// backed by alert_log prevents repeat-alert spam.
package alert

import (
	"context"
	"database/sql"
	"log/slog"

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

// Evaluator holds dependencies; created once in main.go. Every external
// dep is nil-safe so the ticker degrades gracefully before wiring is live.
type Evaluator struct {
	DB       func() *sql.DB
	Logger   *slog.Logger
	Webhooks *webhook.Service
	Mailer   *mail.Mailer
	SMS      *sms.Sender
	Cfg      Config
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

// evaluate runs every rule against the current DB snapshot.
func (e *Evaluator) evaluate(ctx context.Context, db *sql.DB) []Alert {
	var out []Alert
	out = append(out, nodeOffline(ctx, db, e.Cfg)...)
	out = append(out, routeFailed(ctx, db, e.Cfg)...)
	out = append(out, certFailing(ctx, db, e.Cfg)...)
	out = append(out, wgTunnelStale(ctx, db, e.Cfg)...)
	out = append(out, dbPoolSaturated(ctx, db, e.Cfg)...)
	out = append(out, drillStale(ctx, db, e.Cfg)...)
	out = append(out, wgKeyNotFetched(ctx, db, e.Cfg, e.Logger)...)
	return out
}
