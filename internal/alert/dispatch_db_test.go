package alert

import (
	"context"
	"database/sql"
	"log/slog"
	"testing"
	"time"

	"github.com/host-yt/caddy-proxy-manager/internal/store"
	"github.com/host-yt/caddy-proxy-manager/internal/store/sqlitetest"
)

func openAlertDB(t *testing.T) *sql.DB {
	t.Helper()
	prev := store.Driver()
	store.SetDriver("sqlite3")
	t.Cleanup(func() { store.SetDriver(prev) })
	db, err := store.Open(context.Background(), "sqlite3", sqlitetest.MigratedCopy(t, "panel.db"), 10*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	return db
}

func countAlertLog(t *testing.T, db *sql.DB, rule string) int {
	t.Helper()
	var n int
	if err := db.QueryRow(`SELECT COUNT(*) FROM alert_log WHERE rule_id = ?`, rule).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

// The rotation marker may advance only after the alert is recorded, so a failed
// alert_log insert leaves the peer eligible on the next tick.
func TestWGRotationMarkedOnlyAfterRecord(t *testing.T) {
	ctx := context.Background()
	db := openAlertDB(t)
	db.SetMaxOpenConns(1)
	mustExec := func(q string, args ...any) {
		t.Helper()
		if _, err := db.Exec(q, args...); err != nil {
			t.Fatalf("%s: %v", q, err)
		}
	}
	mustExec(`PRAGMA foreign_keys = OFF`)
	mustExec(`INSERT INTO customer_wg_peer (id, client_id, node_id, name, assigned_ip, last_rotated_at)
		VALUES (1, 1, 1, 'p1', '10.0.0.2', (`+store.DateSubParam("HOUR")+`))`, 100)
	mustExec(`INSERT INTO customer_wg_bootstrap (token, peer_id, created_at, expires_at)
		VALUES ('tok', 1, ` + store.Now() + `, ` + store.Now() + `)`)
	marked := func() bool {
		var sent sql.NullTime
		if err := db.QueryRow(`SELECT rotation_alert_sent_at FROM customer_wg_peer WHERE id = 1`).Scan(&sent); err != nil {
			t.Fatal(err)
		}
		return sent.Valid
	}

	e := &Evaluator{Cfg: Config{CooldownSeconds: 1800}}
	alerts := wgKeyNotFetched(ctx, db, e.Cfg, slog.Default())
	if len(alerts) != 1 || marked() {
		t.Fatalf("alerts = %d, marked = %v; want 1 alert and no mark from evaluation", len(alerts), marked())
	}

	mustExec(`ALTER TABLE alert_log RENAME TO alert_log_off`)
	e.dispatch(ctx, db, e.Cfg, alerts[0])
	if marked() {
		t.Fatal("marked although alert_log insert failed")
	}

	mustExec(`ALTER TABLE alert_log_off RENAME TO alert_log`)
	e.dispatch(ctx, db, e.Cfg, alerts[0])
	if !marked() {
		t.Fatal("not marked after the alert was recorded")
	}
	if got := wgKeyNotFetched(ctx, db, e.Cfg, slog.Default()); len(got) != 0 {
		t.Fatalf("re-fired after mark: %d alerts", len(got))
	}
}

// The DB cooldown override must drive dispatch dedupe, not the boot-time env value.
func TestDispatchUsesRuntimeCooldown(t *testing.T) {
	ctx := context.Background()
	db := openAlertDB(t)
	e := &Evaluator{Cfg: Config{CooldownSeconds: 1800}}
	a := Alert{RuleID: "test_rule", Severity: SeverityInfo, Title: "t", Labels: map[string]string{"x": "1"}}
	if _, err := db.Exec(`INSERT INTO alert_log (rule_id, severity, title, detail, labels_json, dedupe_key, fired_at)
		VALUES ('test_rule', 'info', 't', '', '{}', ?, (`+store.DateSubParam("SECOND")+`))`, dedupeKey(a), 120); err != nil {
		t.Fatal(err)
	}

	e.dispatch(ctx, db, e.mergedCfg(ctx, db), a)
	if n := countAlertLog(t, db, "test_rule"); n != 1 {
		t.Fatalf("env cooldown 1800s: rows = %d, want 1 (suppressed)", n)
	}

	if _, err := db.Exec("INSERT INTO settings (`key`, value) VALUES ('alert.cooldown_seconds', '60')"); err != nil {
		t.Fatal(err)
	}
	e.dispatch(ctx, db, e.mergedCfg(ctx, db), a)
	if n := countAlertLog(t, db, "test_rule"); n != 2 {
		t.Fatalf("DB cooldown 60s: rows = %d, want 2 (fired)", n)
	}
}
