package alert

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"net/http"
	"sort"
	"strconv"
	"strings"
)

// eventAlertFired is the webhook event type for fired alerts. Mirrors the
// "<noun>.<verb>" convention in internal/webhook; endpoint filters like
// "alert.*" or "*" match it.
const eventAlertFired = "alert.fired"

// dispatch records the alert in alert_log and fans out to webhook/mail/sms
// unless the rule+label dedupe key is still within its cooldown window.
func (e *Evaluator) dispatch(ctx context.Context, db *sql.DB, a Alert) {
	key := dedupeKey(a)

	// Cooldown: suppress if the same dedupe key fired within the window.
	var lastFired sql.NullTime
	_ = db.QueryRowContext(ctx,
		`SELECT MAX(fired_at) FROM alert_log
		  WHERE dedupe_key = ? AND fired_at > (NOW() - INTERVAL ? SECOND)`,
		key, e.Cfg.CooldownSeconds).Scan(&lastFired)
	if lastFired.Valid {
		return
	}

	// Log first so the row always lands even if a fanout channel fails.
	labelsJSON, _ := json.Marshal(a.Labels)
	if _, err := db.ExecContext(ctx,
		`INSERT INTO alert_log (rule_id, severity, title, detail, labels_json, dedupe_key, fired_at)
		 VALUES (?, ?, ?, ?, ?, ?, NOW())`,
		a.RuleID, string(a.Severity), a.Title, a.Detail, string(labelsJSON), key); err != nil {
		if e.Logger != nil {
			e.Logger.Warn("alert log insert failed", "rule", a.RuleID, "err", err)
		}
		return // do not fan out if we could not record - avoids un-deduped repeat
	}

	if e.Metrics != nil {
		e.Metrics.AlertFired(a.RuleID, string(a.Severity))
	}

	if e.Webhooks != nil {
		e.Webhooks.Emit(ctx, eventAlertFired, map[string]any{
			"rule_id":  a.RuleID,
			"severity": string(a.Severity),
			"title":    a.Title,
			"detail":   a.Detail,
			"labels":   a.Labels,
		})
	}
	if e.Mailer != nil {
		if to := e.resolveAdminEmail(ctx, db); to != "" {
			if err := e.Mailer.Send(ctx, to, "[HPG Alert] "+a.Title, "alert", map[string]any{"Alert": a}); err != nil && e.Logger != nil {
				e.Logger.Warn("alert email failed", "rule", a.RuleID, "err", err)
			}
		}
	}
	if e.SMS != nil && e.Cfg.AdminPhone != "" {
		if err := e.SMS.Send(ctx, e.Cfg.AdminPhone, "[HPG] "+a.Title+": "+a.Detail); err != nil && e.Logger != nil {
			e.Logger.Warn("alert sms failed", "rule", a.RuleID, "err", err)
		}
	}
	if e.Cfg.TelegramBotToken != "" && e.Cfg.TelegramChatID != "" {
		sev := "ℹ️"
		switch a.Severity {
		case SeverityWarning:
			sev = "⚠️"
		case SeverityCritical:
			sev = "🔴"
		}
		msg := fmt.Sprintf("%s <b>[HPG Alert]</b> %s\n%s", sev, a.Title, a.Detail)
		if err := sendTelegram(ctx, e.Cfg.TelegramBotToken, e.Cfg.TelegramChatID, msg); err != nil && e.Logger != nil {
			e.Logger.Warn("telegram alert failed", "rule", a.RuleID, "err", err)
		}
	}

	// Trigger automatic failover for node_offline alerts.
	if a.RuleID == "node_offline" {
		if nodeIDStr := a.Labels["node_id"]; nodeIDStr != "" {
			if id, err := strconv.ParseInt(nodeIDStr, 10, 64); err == nil {
				go e.tryAutoFailover(context.Background(), db, id)
			}
		}
	}
}

// resolveAdminEmail returns the configured override or the first active
// super_admin email from DB.
func (e *Evaluator) resolveAdminEmail(ctx context.Context, db *sql.DB) string {
	if e.Cfg.AdminEmail != "" {
		return e.Cfg.AdminEmail
	}
	var email string
	_ = db.QueryRowContext(ctx,
		`SELECT email FROM users
		  WHERE role = 'super_admin' AND is_active = 1
		  ORDER BY id LIMIT 1`).Scan(&email)
	return email
}

// TestFire dispatches a one-off alert bypassing cooldown deduplication.
func (e *Evaluator) TestFire(ctx context.Context, a Alert) {
	if e.DB == nil {
		return
	}
	db := e.DB()
	if db == nil {
		return
	}
	go e.dispatch(context.Background(), db, a)
}

// pruneLog bounds table size by dropping rows past the retention window.
func (e *Evaluator) pruneLog(ctx context.Context, db *sql.DB) {
	_, _ = db.ExecContext(ctx,
		`DELETE FROM alert_log WHERE fired_at < (NOW() - INTERVAL ? DAY)`,
		e.Cfg.RetentionDays)
}

// sendTelegram posts a message to a Telegram chat via the Bot API.
func sendTelegram(ctx context.Context, token, chatID, text string) error {
	url := "https://api.telegram.org/bot" + token + "/sendMessage"
	body, _ := json.Marshal(map[string]string{
		"chat_id":    chatID,
		"text":       text,
		"parse_mode": "HTML",
	})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("telegram: HTTP %d", resp.StatusCode)
	}
	return nil
}

// dedupeKey builds a stable string from rule_id + labels (sorted keys) so
// the cooldown is per-entity (e.g. "node_offline|node_id=3"), not fleet-wide.
func dedupeKey(a Alert) string {
	keys := make([]string, 0, len(a.Labels))
	for k := range a.Labels {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var b strings.Builder
	b.WriteString(a.RuleID)
	for _, k := range keys {
		b.WriteByte('|')
		b.WriteString(k)
		b.WriteByte('=')
		b.WriteString(a.Labels[k])
	}
	return b.String()
}
