package handlers

import (
	"database/sql"
	"testing"
	"time"

	"github.com/host-yt/caddy-proxy-manager/internal/wafevents"
)

// wafEventKey must be stable across re-deliveries of the same audit line so the
// panel drops replays, yet differ on any identity field and on node id.
func TestWAFEventKey(t *testing.T) {
	base := wafevents.Event{
		TS:       time.Date(2026, 6, 28, 13, 54, 6, 0, time.UTC),
		RuleID:   "942100",
		Action:   "blocked",
		RemoteIP: "203.0.113.7",
		Host:     "shop.example.com",
		URI:      "/login",
		Message:  "SQLi",
	}

	k1 := wafEventKey(5, base)
	if len(k1) != 64 {
		t.Fatalf("key should be 64 hex chars, got %d", len(k1))
	}

	// Same node + same fields -> same key (the replay case).
	if wafEventKey(5, base) != k1 {
		t.Errorf("identical event produced different keys")
	}

	// route_id must NOT influence the key (it is resolved server-side and may move).
	withRoute := base
	withRoute.RouteID = sql.NullInt64{Int64: 42, Valid: true}
	if wafEventKey(5, withRoute) != k1 {
		t.Errorf("route_id changed the key; replays after a route change would duplicate")
	}

	// Different node -> different key (same attack on two nodes are two events).
	if wafEventKey(6, base) == k1 {
		t.Errorf("different node produced same key")
	}

	// Each identity field must change the key.
	mutators := map[string]func(e *wafevents.Event){
		"ts":        func(e *wafevents.Event) { e.TS = e.TS.Add(time.Second) },
		"rule_id":   func(e *wafevents.Event) { e.RuleID = "999999" },
		"action":    func(e *wafevents.Event) { e.Action = "detected" },
		"remote_ip": func(e *wafevents.Event) { e.RemoteIP = "198.51.100.1" },
		"host":      func(e *wafevents.Event) { e.Host = "other.example.com" },
		"uri":       func(e *wafevents.Event) { e.URI = "/admin" },
		"message":   func(e *wafevents.Event) { e.Message = "XSS" },
	}
	for name, mut := range mutators {
		e := base
		mut(&e)
		if wafEventKey(5, e) == k1 {
			t.Errorf("changing %s did not change the key", name)
		}
	}
}
