package dnssteer

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"testing"

	_ "modernc.org/sqlite"
)

// --- planActions: pure diff logic, no DB/provider involved ---

func TestPlanActions_AddMissing(t *testing.T) {
	candidates := []nodeCandidate{{id: 1, ip: "10.0.0.1", enabled: true, healthy: true}}
	actions := planActions("app.example.com", candidates, nil)
	if len(actions) != 1 || actions[0].kind != "add" || actions[0].rec.Value != "10.0.0.1" || actions[0].rec.Type != "A" {
		t.Fatalf("want one add action for 10.0.0.1, got %+v", actions)
	}
}

func TestPlanActions_RemoveStale(t *testing.T) {
	// Two candidates so removing the unhealthy one doesn't also trip
	// fail-static (that path has its own dedicated test below).
	candidates := []nodeCandidate{
		{id: 1, ip: "10.0.0.1", enabled: true, healthy: true},
		{id: 2, ip: "10.0.0.2", enabled: true, healthy: false},
	}
	existing := []Record{
		{ID: "rec1", Name: "app.example.com", Value: "10.0.0.1", Type: "A"},
		{ID: "rec2", Name: "app.example.com", Value: "10.0.0.2", Type: "A"},
	}
	actions := planActions("app.example.com", candidates, existing)
	if len(actions) != 1 || actions[0].kind != "remove" || actions[0].rec.ID != "rec2" {
		t.Fatalf("want one remove action for rec2, got %+v", actions)
	}
}

func TestPlanActions_NoChangeWhenAlreadyDesired(t *testing.T) {
	candidates := []nodeCandidate{{id: 1, ip: "10.0.0.1", enabled: true, healthy: true}}
	existing := []Record{{ID: "rec1", Name: "app.example.com", Value: "10.0.0.1", Type: "A"}}
	actions := planActions("app.example.com", candidates, existing)
	if len(actions) != 0 {
		t.Fatalf("want no actions, got %+v", actions)
	}
}

func TestPlanActions_FailStaticKeepsLowestNodeID(t *testing.T) {
	candidates := []nodeCandidate{
		{id: 2, ip: "10.0.0.2", enabled: true, healthy: false},
		{id: 1, ip: "10.0.0.1", enabled: true, healthy: false},
	}
	existing := []Record{
		{ID: "rec1", Name: "app.example.com", Value: "10.0.0.1", Type: "A"},
		{ID: "rec2", Name: "app.example.com", Value: "10.0.0.2", Type: "A"},
	}
	actions := planActions("app.example.com", candidates, existing)
	if len(actions) != 1 {
		t.Fatalf("fail-static must keep exactly one record, got %+v", actions)
	}
	if actions[0].nodeID != 2 {
		t.Fatalf("fail-static must remove the higher node ID and keep node 1, removed node %d", actions[0].nodeID)
	}
}

func TestPlanActions_ForeignRecordSurvivesUnmanaged(t *testing.T) {
	// A record at the same name but an IP not owned by any candidate node is
	// left alone entirely - it's not ours to manage, and its mere presence
	// means fail-static doesn't need to kick in for the candidate-owned one.
	candidates := []nodeCandidate{{id: 1, ip: "10.0.0.1", enabled: true, healthy: false}}
	existing := []Record{
		{ID: "rec1", Name: "app.example.com", Value: "10.0.0.1", Type: "A"},
		{ID: "rec-foreign", Name: "app.example.com", Value: "10.9.9.9", Type: "A"},
	}
	actions := planActions("app.example.com", candidates, existing)
	if len(actions) != 1 || actions[0].kind != "remove" || actions[0].rec.ID != "rec1" {
		t.Fatalf("want the candidate-owned record removed, foreign left alone, got %+v", actions)
	}
}

// --- fakeProvider: in-memory Provider for Reconciler-level tests ---

type fakeProvider struct {
	records     []Record
	getErr      error
	appendErr   error
	deleteErr   error
	appendCalls int
	deleteCalls int
	nextID      int
}

func (f *fakeProvider) GetRecords(ctx context.Context, zone string) ([]Record, error) {
	if f.getErr != nil {
		return nil, f.getErr
	}
	out := make([]Record, len(f.records))
	copy(out, f.records)
	return out, nil
}

func (f *fakeProvider) AppendRecords(ctx context.Context, zone string, recs []Record) ([]Record, error) {
	f.appendCalls++
	if f.appendErr != nil {
		return nil, f.appendErr
	}
	var created []Record
	for _, r := range recs {
		f.nextID++
		r.ID = fmt.Sprintf("id-%d", f.nextID)
		f.records = append(f.records, r)
		created = append(created, r)
	}
	return created, nil
}

func (f *fakeProvider) DeleteRecords(ctx context.Context, zone string, recs []Record) ([]Record, error) {
	f.deleteCalls++
	if f.deleteErr != nil {
		return nil, f.deleteErr
	}
	var deleted []Record
	for _, r := range recs {
		for i, existing := range f.records {
			if existing.ID == r.ID {
				f.records = append(f.records[:i], f.records[i+1:]...)
				deleted = append(deleted, existing)
				break
			}
		}
	}
	return deleted, nil
}

// --- Reconciler end-to-end against an in-memory SQLite DB ---

func newTestDB(t *testing.T) *sql.DB {
	t.Helper()
	db, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	schema := []string{
		`CREATE TABLE caddy_nodes (
			id INTEGER PRIMARY KEY,
			public_ip TEXT,
			is_enabled INTEGER NOT NULL DEFAULT 1,
			health_status TEXT NOT NULL DEFAULT 'unknown'
		)`,
		`CREATE TABLE dns_providers (
			id INTEGER PRIMARY KEY,
			name TEXT,
			provider TEXT,
			api_token_enc TEXT
		)`,
		`CREATE TABLE routes (
			id INTEGER PRIMARY KEY,
			domain TEXT,
			caddy_node_id INTEGER,
			dns_steering_enabled INTEGER NOT NULL DEFAULT 0,
			dns_provider_id INTEGER,
			dns_steering_ttl INTEGER NOT NULL DEFAULT 60,
			status TEXT NOT NULL DEFAULT 'active'
		)`,
		`CREATE TABLE route_node_assignments (
			route_id INTEGER NOT NULL,
			node_id INTEGER NOT NULL,
			PRIMARY KEY (route_id, node_id)
		)`,
		`CREATE TABLE dns_steering_state (
			route_id INTEGER NOT NULL,
			node_id INTEGER NOT NULL,
			record_value TEXT NOT NULL,
			present INTEGER NOT NULL DEFAULT 0,
			last_synced_at TIMESTAMP NULL,
			last_error TEXT NULL,
			PRIMARY KEY (route_id, node_id)
		)`,
		`CREATE TABLE audit_log (
			id INTEGER PRIMARY KEY,
			user_id INTEGER,
			actor_type TEXT NOT NULL,
			action TEXT NOT NULL,
			entity TEXT NOT NULL,
			entity_id TEXT,
			ip TEXT,
			user_agent TEXT,
			meta TEXT,
			created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
		)`,
	}
	for _, stmt := range schema {
		if _, err := db.Exec(stmt); err != nil {
			t.Fatalf("schema %q: %v", stmt, err)
		}
	}
	return db
}

func setHealth(t *testing.T, db *sql.DB, nodeID int64, enabled bool, health string) {
	t.Helper()
	if _, err := db.Exec(`UPDATE caddy_nodes SET is_enabled=?, health_status=? WHERE id=?`, enabled, health, nodeID); err != nil {
		t.Fatal(err)
	}
}

type stateRow struct {
	present   bool
	lastError sql.NullString
}

func loadState(t *testing.T, db *sql.DB, routeID int64) map[int64]stateRow {
	t.Helper()
	rows, err := db.Query(`SELECT node_id, present, last_error FROM dns_steering_state WHERE route_id=?`, routeID)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	out := map[int64]stateRow{}
	for rows.Next() {
		var nodeID int64
		var sr stateRow
		if err := rows.Scan(&nodeID, &sr.present, &sr.lastError); err != nil {
			t.Fatal(err)
		}
		out[nodeID] = sr
	}
	return out
}

func auditCount(t *testing.T, db *sql.DB, action string) int {
	t.Helper()
	var n int
	if err := db.QueryRow(`SELECT COUNT(*) FROM audit_log WHERE action=?`, action).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

// TestReconcile_FullLifecycle drives one route through: initial steering,
// a node going unhealthy (removed), recovering (re-added), a full-outage
// scenario (fail-static keeps the last record), and a provider error (state
// records last_error, no panic).
func TestReconcile_FullLifecycle(t *testing.T) {
	db := newTestDB(t)
	exec := func(q string, args ...any) {
		t.Helper()
		if _, err := db.Exec(q, args...); err != nil {
			t.Fatalf("exec %q: %v", q, err)
		}
	}
	exec(`INSERT INTO caddy_nodes (id, public_ip, is_enabled, health_status) VALUES
		(1,'10.0.0.1',1,'healthy'), (2,'10.0.0.2',1,'healthy'), (3,'10.0.0.3',1,'healthy')`)
	exec(`INSERT INTO dns_providers (id, name, provider, api_token_enc) VALUES (1,'example.com','cloudflare','{"api_token":"tok"}')`)
	exec(`INSERT INTO routes (id, domain, caddy_node_id, dns_steering_enabled, dns_provider_id, dns_steering_ttl, status)
		VALUES (1,'app.example.com',1,1,1,60,'active')`)
	exec(`INSERT INTO route_node_assignments (route_id, node_id) VALUES (1,2),(1,3)`)

	fp := &fakeProvider{}
	rc := &Reconciler{
		DB:            func() *sql.DB { return db },
		Logger:        slog.Default(),
		DecryptSecret: func(s string) (string, error) { return s, nil },
		NewProvider:   func(slug string, fields map[string]string) (Provider, error) { return fp, nil },
	}
	ctx := context.Background()

	t.Run("initial steering adds all three healthy nodes", func(t *testing.T) {
		rc.Reconcile(ctx)
		if len(fp.records) != 3 {
			t.Fatalf("want 3 provider records, got %d: %+v", len(fp.records), fp.records)
		}
		state := loadState(t, db, 1)
		for _, id := range []int64{1, 2, 3} {
			if !state[id].present {
				t.Errorf("node %d expected present=1", id)
			}
		}
		if got := auditCount(t, db, "dns.steering.record_added"); got != 3 {
			t.Errorf("want 3 record_added audit rows, got %d", got)
		}
	})

	t.Run("node goes unhealthy: record removed", func(t *testing.T) {
		setHealth(t, db, 2, true, "down")
		rc.Reconcile(ctx)
		if len(fp.records) != 2 {
			t.Fatalf("want 2 provider records after removal, got %d: %+v", len(fp.records), fp.records)
		}
		state := loadState(t, db, 1)
		if state[2].present {
			t.Error("node 2 should be present=0 after going unhealthy")
		}
		if !state[1].present || !state[3].present {
			t.Error("nodes 1 and 3 should remain present")
		}
		if got := auditCount(t, db, "dns.steering.record_removed"); got != 1 {
			t.Errorf("want 1 record_removed audit row, got %d", got)
		}
	})

	t.Run("node recovers: record re-added", func(t *testing.T) {
		setHealth(t, db, 2, true, "healthy")
		rc.Reconcile(ctx)
		if len(fp.records) != 3 {
			t.Fatalf("want 3 provider records after recovery, got %d: %+v", len(fp.records), fp.records)
		}
		state := loadState(t, db, 1)
		if !state[2].present {
			t.Error("node 2 should be present=1 after recovering")
		}
		if got := auditCount(t, db, "dns.steering.record_added"); got != 4 {
			t.Errorf("want 4 cumulative record_added audit rows, got %d", got)
		}
	})

	t.Run("all nodes unhealthy: fail-static keeps the last record", func(t *testing.T) {
		setHealth(t, db, 1, true, "down")
		setHealth(t, db, 2, true, "down")
		setHealth(t, db, 3, true, "down")
		rc.Reconcile(ctx)
		if len(fp.records) != 1 {
			t.Fatalf("fail-static must keep exactly 1 record, got %d: %+v", len(fp.records), fp.records)
		}
		state := loadState(t, db, 1)
		if !state[1].present {
			t.Error("fail-static should keep node 1 (lowest ID) present")
		}
		if state[2].present || state[3].present {
			t.Error("nodes 2 and 3 should have been removed")
		}
	})

	t.Run("provider error: last_error persisted, no panic", func(t *testing.T) {
		setHealth(t, db, 1, true, "healthy")
		setHealth(t, db, 2, true, "healthy")
		setHealth(t, db, 3, true, "healthy")
		fp.getErr = errors.New("cloudflare: rate limited")
		defer func() {
			if r := recover(); r != nil {
				t.Fatalf("Reconcile panicked on provider error: %v", r)
			}
		}()
		rc.Reconcile(ctx)
		state := loadState(t, db, 1)
		for _, id := range []int64{1, 2, 3} {
			if !state[id].lastError.Valid || !strings.Contains(state[id].lastError.String, "rate limited") {
				t.Errorf("node %d expected last_error to mention the provider failure, got %+v", id, state[id])
			}
		}
	})
}
