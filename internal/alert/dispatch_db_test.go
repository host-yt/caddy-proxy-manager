package alert

import (
	"context"
	"database/sql"
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
