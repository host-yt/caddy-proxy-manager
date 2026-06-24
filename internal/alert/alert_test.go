package alert

import (
	"database/sql"
	"testing"

	_ "github.com/go-sql-driver/mysql"
)

func TestDedupeKeyStableAndSorted(t *testing.T) {
	a := Alert{RuleID: "node_offline", Labels: map[string]string{"node_name": "eu-1", "node_id": "3"}}
	// Same labels in any insertion order must yield the identical key so the
	// cooldown lookup matches a prior fire.
	b := Alert{RuleID: "node_offline", Labels: map[string]string{"node_id": "3", "node_name": "eu-1"}}
	if dedupeKey(a) != dedupeKey(b) {
		t.Fatalf("dedupeKey not order-stable: %q vs %q", dedupeKey(a), dedupeKey(b))
	}
	want := "node_offline|node_id=3|node_name=eu-1"
	if got := dedupeKey(a); got != want {
		t.Fatalf("dedupeKey = %q, want %q", got, want)
	}
}

func TestDedupeKeyDistinctEntities(t *testing.T) {
	a := Alert{RuleID: "route_failed", Labels: map[string]string{"route_id": "1"}}
	b := Alert{RuleID: "route_failed", Labels: map[string]string{"route_id": "2"}}
	if dedupeKey(a) == dedupeKey(b) {
		t.Fatal("per-entity dedupe keys must differ across entity ids")
	}
}

func TestDBPoolSaturated(t *testing.T) {
	// Stats() works without an open connection, so a never-pinged handle is
	// enough to drive the ratio math.
	db, err := sql.Open("mysql", "user:pass@tcp(127.0.0.1:3306)/db")
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer db.Close()

	// Unlimited pool (MaxOpenConns=0) must never fire.
	if got := dbPoolSaturated(nil, db, Config{DBPoolSaturationPct: 0.9}); got != nil {
		t.Fatalf("unlimited pool should not fire, got %v", got)
	}

	// With a cap but zero open connections, ratio 0 < 0.9 → no alert.
	db.SetMaxOpenConns(2)
	if got := dbPoolSaturated(nil, db, Config{DBPoolSaturationPct: 0.9}); got != nil {
		t.Fatalf("idle pool should not fire, got %v", got)
	}
}

func TestLoadConfigDefaults(t *testing.T) {
	t.Setenv("ALERT_NODE_OFFLINE_MIN", "")
	t.Setenv("ALERT_COOLDOWN_SEC", "bogus") // invalid → falls back to default
	cfg := LoadConfig()
	if cfg.NodeOfflineMinutes != 5 {
		t.Errorf("NodeOfflineMinutes default = %d, want 5", cfg.NodeOfflineMinutes)
	}
	if cfg.CooldownSeconds != 1800 {
		t.Errorf("CooldownSeconds (invalid env) = %d, want default 1800", cfg.CooldownSeconds)
	}
	if cfg.RetentionDays != 90 {
		t.Errorf("RetentionDays default = %d, want 90", cfg.RetentionDays)
	}
}

func TestLoadConfigOverride(t *testing.T) {
	t.Setenv("ALERT_NODE_OFFLINE_MIN", "10")
	t.Setenv("ALERT_DB_POOL_PCT", "0.75")
	cfg := LoadConfig()
	if cfg.NodeOfflineMinutes != 10 {
		t.Errorf("NodeOfflineMinutes = %d, want 10", cfg.NodeOfflineMinutes)
	}
	if cfg.DBPoolSaturationPct != 0.75 {
		t.Errorf("DBPoolSaturationPct = %v, want 0.75", cfg.DBPoolSaturationPct)
	}
}
