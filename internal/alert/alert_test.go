package alert

import (
	"database/sql"
	"strings"
	"testing"
	"time"

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

func TestClassifyManualCert(t *testing.T) {
	now := time.Date(2026, 6, 26, 12, 0, 0, 0, time.UTC)
	date := func(daysOffset int) time.Time {
		return now.Add(time.Duration(daysOffset) * 24 * time.Hour)
	}

	cases := []struct {
		name         string
		notAfter     time.Time
		daysLeft     int // as MySQL would return (truncated toward zero)
		wantSeverity Severity
		wantPhase    string
		wantDetail   string // substring check
	}{
		{
			name:         "healthy - above threshold",
			notAfter:     date(60),
			daysLeft:     60,
			wantSeverity: SeverityWarning,
			wantPhase:    "warn",
			wantDetail:   "expires in 60 days",
		},
		{
			name:         "warning window - 15 days",
			notAfter:     date(15),
			daysLeft:     15,
			wantSeverity: SeverityWarning,
			wantPhase:    "warn",
			wantDetail:   "expires in 15 days",
		},
		{
			name: "days_left=0 but not yet expired (within <24h of expiry)",
			// notAfter is 1 hour in the future; MySQL TIMESTAMPDIFF returns 0
			notAfter:     now.Add(1 * time.Hour),
			daysLeft:     0,
			wantSeverity: SeverityWarning,
			wantPhase:    "warn",
			wantDetail:   "expires in 0 days",
		},
		{
			name: "freshly expired - <24h ago (days_left=0 from MySQL)",
			// notAfter is 1 hour in the past; MySQL TIMESTAMPDIFF returns 0 but cert IS expired
			notAfter:     now.Add(-1 * time.Hour),
			daysLeft:     0,
			wantSeverity: SeverityCritical,
			wantPhase:    "expired",
			wantDetail:   "expired 0 days ago",
		},
		{
			name:         "expired >24h ago",
			notAfter:     date(-3),
			daysLeft:     -3,
			wantSeverity: SeverityCritical,
			wantPhase:    "expired",
			wantDetail:   "expired 3 days ago",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			sev, phase, detail := classifyManualCert(now, tc.notAfter, tc.daysLeft)
			if sev != tc.wantSeverity {
				t.Errorf("severity = %q, want %q", sev, tc.wantSeverity)
			}
			if phase != tc.wantPhase {
				t.Errorf("phase = %q, want %q", phase, tc.wantPhase)
			}
			if !strings.Contains(detail, tc.wantDetail) {
				t.Errorf("detail %q does not contain %q", detail, tc.wantDetail)
			}
		})
	}
}

func TestManualCertPhaseInDedupeKey(t *testing.T) {
	// Warn and Critical alerts for the same cert must have distinct dedupe keys.
	warn := Alert{
		RuleID: "manual_cert_expiry",
		Labels: map[string]string{"cert_id": "7", "cn": "example.com", "phase": "warn"},
	}
	crit := Alert{
		RuleID: "manual_cert_expiry",
		Labels: map[string]string{"cert_id": "7", "cn": "example.com", "phase": "expired"},
	}
	if dedupeKey(warn) == dedupeKey(crit) {
		t.Fatal("warn and expired phases must produce distinct dedupe keys to avoid cooldown suppression")
	}
}
