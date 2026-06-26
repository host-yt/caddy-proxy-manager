package wafevents

import (
	"context"
	"database/sql"
	"fmt"
	"os"
	"testing"
	"time"

	_ "github.com/go-sql-driver/mysql"
)

// openTestDB opens a real DB via TEST_DB_DSN or skips the test.
func openTestDB(t *testing.T) *sql.DB {
	t.Helper()
	dsn := os.Getenv("TEST_DB_DSN")
	if dsn == "" {
		t.Skip("TEST_DB_DSN not set - skipping DB-backed test")
	}
	db, err := sql.Open("mysql", dsn)
	if err != nil {
		t.Fatalf("sql.Open: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := db.PingContext(ctx); err != nil {
		t.Skipf("DB not reachable: %v", err)
	}
	return db
}

// insertTestEvent inserts a minimal waf_event and returns its ID.
func insertTestEvent(t *testing.T, db *sql.DB, ctx context.Context, ruleID string, routeID int64) int64 {
	t.Helper()
	var rid sql.NullInt64
	if routeID > 0 {
		rid = sql.NullInt64{Int64: routeID, Valid: true}
	}
	res, err := db.ExecContext(ctx,
		`INSERT INTO waf_events (route_id, ts, severity, rule_id, action, remote_ip, host, uri, message)
		 VALUES (?, NOW(), 'low', ?, 'detected', '1.2.3.4', 'test.example.com', '/', 'test')`,
		rid, ruleID,
	)
	if err != nil {
		t.Fatalf("insertTestEvent: %v", err)
	}
	id, _ := res.LastInsertId()
	return id
}

// TestSuppressRuleAndFilteredMarking proves:
// - SuppressRule inserts a record
// - FilteredWithSuppressions marks matching events as Suppressed
// - DeleteSuppression removes it
func TestSuppressRuleAndFilteredMarking(t *testing.T) {
	db := openTestDB(t)
	defer db.Close()
	ctx := context.Background()

	ruleID := fmt.Sprintf("test-rule-%d", time.Now().UnixNano())
	store := New(func() *sql.DB { return db })

	// Insert an event for the rule.
	eventID := insertTestEvent(t, db, ctx, ruleID, 0)
	t.Cleanup(func() {
		_, _ = db.ExecContext(ctx, "DELETE FROM waf_events WHERE id = ?", eventID)
	})

	// No suppression yet: event should not be marked.
	events, _, err := store.FilteredWithSuppressions(ctx, Filter{RuleID: ruleID, Limit: 10})
	if err != nil {
		t.Fatalf("FilteredWithSuppressions: %v", err)
	}
	if len(events) == 0 {
		t.Fatal("expected at least one event")
	}
	for _, e := range events {
		if e.RuleID == ruleID && e.Suppressed {
			t.Error("event should not be suppressed before SuppressRule")
		}
	}

	// Create a global suppression.
	supID, err := store.SuppressRule(ctx, Suppression{
		RuleID:    ruleID,
		CreatedBy: 1,
		Reason:    "test suppression",
	})
	if err != nil {
		t.Fatalf("SuppressRule: %v", err)
	}
	t.Cleanup(func() {
		_, _ = db.ExecContext(ctx, "DELETE FROM waf_rule_suppressions WHERE id = ?", supID)
	})

	// Now events matching the rule must be marked suppressed.
	events, _, err = store.FilteredWithSuppressions(ctx, Filter{RuleID: ruleID, Limit: 10})
	if err != nil {
		t.Fatalf("FilteredWithSuppressions after suppress: %v", err)
	}
	found := false
	for _, e := range events {
		if e.RuleID == ruleID {
			found = true
			if !e.Suppressed {
				t.Errorf("event id=%d should be marked Suppressed", e.ID)
			}
		}
	}
	if !found {
		t.Fatal("expected to find the test event")
	}

	// ListSuppressions (global / super_admin view) should include our record.
	sups, err := store.ListSuppressions(ctx, nil)
	if err != nil {
		t.Fatalf("ListSuppressions: %v", err)
	}
	var found2 bool
	for _, s := range sups {
		if s.ID == supID {
			found2 = true
			break
		}
	}
	if !found2 {
		t.Error("suppression not returned by ListSuppressions")
	}

	// Delete suppression; event must stop being marked.
	if err := store.DeleteSuppression(ctx, supID, 0); err != nil {
		t.Fatalf("DeleteSuppression: %v", err)
	}
	events, _, err = store.FilteredWithSuppressions(ctx, Filter{RuleID: ruleID, Limit: 10})
	if err != nil {
		t.Fatalf("FilteredWithSuppressions after delete: %v", err)
	}
	for _, e := range events {
		if e.RuleID == ruleID && e.Suppressed {
			t.Error("event should no longer be suppressed after DeleteSuppression")
		}
	}
}

// TestAckEvent proves AckEvent sets acknowledged_at/by on the event.
func TestAckEvent(t *testing.T) {
	db := openTestDB(t)
	defer db.Close()
	ctx := context.Background()

	ruleID := fmt.Sprintf("ack-rule-%d", time.Now().UnixNano())
	store := New(func() *sql.DB { return db })

	eventID := insertTestEvent(t, db, ctx, ruleID, 0)
	t.Cleanup(func() {
		_, _ = db.ExecContext(ctx, "DELETE FROM waf_events WHERE id = ?", eventID)
	})

	const actorUserID = int64(42)
	if err := store.AckEvent(ctx, eventID, actorUserID); err != nil {
		t.Fatalf("AckEvent: %v", err)
	}

	var ackedAt sql.NullTime
	var ackedBy sql.NullInt64
	if err := db.QueryRowContext(ctx,
		"SELECT acknowledged_at, acknowledged_by FROM waf_events WHERE id = ?", eventID,
	).Scan(&ackedAt, &ackedBy); err != nil {
		t.Fatalf("scan ack columns: %v", err)
	}
	if !ackedAt.Valid {
		t.Error("acknowledged_at should be set")
	}
	if !ackedBy.Valid || ackedBy.Int64 != actorUserID {
		t.Errorf("acknowledged_by = %v, want %d", ackedBy, actorUserID)
	}

	// Second ack must be a no-op (WHERE acknowledged_at IS NULL).
	if err := store.AckEvent(ctx, eventID, 99); err != nil {
		t.Fatalf("second AckEvent: %v", err)
	}
	var ackedBy2 sql.NullInt64
	_ = db.QueryRowContext(ctx,
		"SELECT acknowledged_by FROM waf_events WHERE id = ?", eventID,
	).Scan(&ackedBy2)
	if ackedBy2.Int64 != actorUserID {
		t.Errorf("second ack should not overwrite: got %d", ackedBy2.Int64)
	}
}

// TestScopedSuppressBlocksGlobal proves DeleteSuppression with ownerRouteID
// does not delete a global (route_id IS NULL) suppression.
func TestScopedSuppressBlocksGlobal(t *testing.T) {
	db := openTestDB(t)
	defer db.Close()
	ctx := context.Background()

	ruleID := fmt.Sprintf("scope-rule-%d", time.Now().UnixNano())
	store := New(func() *sql.DB { return db })

	// Global suppression.
	supID, err := store.SuppressRule(ctx, Suppression{
		RuleID:    ruleID,
		CreatedBy: 1,
	})
	if err != nil {
		t.Fatalf("SuppressRule: %v", err)
	}
	t.Cleanup(func() {
		_, _ = db.ExecContext(ctx, "DELETE FROM waf_rule_suppressions WHERE id = ?", supID)
	})

	// Scoped delete with ownerRouteID=999 must not remove the global row.
	if err := store.DeleteSuppression(ctx, supID, 999); err != nil {
		t.Fatalf("DeleteSuppression scoped: %v", err)
	}
	var count int
	_ = db.QueryRowContext(ctx,
		"SELECT COUNT(*) FROM waf_rule_suppressions WHERE id = ?", supID,
	).Scan(&count)
	if count != 1 {
		t.Error("global suppression should survive a scoped delete with wrong route_id")
	}
}
