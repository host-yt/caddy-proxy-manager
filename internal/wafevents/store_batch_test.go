package wafevents

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"fmt"
	"testing"
	"time"
)

// TestInsertBatchIfNewDedup proves the one-tx batch insert stores new events
// and that a full replay (same keys) dedups every row without new inserts.
func TestInsertBatchIfNewDedup(t *testing.T) {
	db := openTestDB(t)
	defer db.Close()
	ctx := context.Background()

	st := New(func() *sql.DB { return db })
	tag := fmt.Sprintf("batch-%d", time.Now().UnixNano())

	events := make([]Event, 3)
	keys := make([]string, 3)
	for i := range events {
		events[i] = Event{
			TS:       time.Now().UTC().Truncate(time.Second),
			Severity: "low",
			RuleID:   fmt.Sprintf("%s-%d", tag, i),
			Action:   "detected",
			RemoteIP: "203.0.113.9",
			Host:     "batch.example",
			URI:      "/x",
			Message:  "batch test",
		}
		sum := sha256.Sum256([]byte(fmt.Sprintf("%s-key-%d", tag, i)))
		keys[i] = hex.EncodeToString(sum[:])
	}
	t.Cleanup(func() {
		_, _ = db.ExecContext(ctx, "DELETE FROM waf_events WHERE rule_id LIKE ?", tag+"%")
		for _, k := range keys {
			_, _ = db.ExecContext(ctx, "DELETE FROM waf_seen_events WHERE event_hash = ?", k)
		}
	})

	first, err := st.InsertBatchIfNew(ctx, events, keys)
	if err != nil {
		t.Fatalf("first batch: %v", err)
	}
	for i, ok := range first {
		if !ok {
			t.Errorf("first[%d] = false, want true (new event must insert)", i)
		}
	}

	// Full replay: every key already in the ledger, nothing may re-insert.
	second, err := st.InsertBatchIfNew(ctx, events, keys)
	if err != nil {
		t.Fatalf("second batch: %v", err)
	}
	for i, ok := range second {
		if ok {
			t.Errorf("second[%d] = true, want false (replay must dedup)", i)
		}
	}

	var n int
	if err := db.QueryRowContext(ctx,
		"SELECT COUNT(*) FROM waf_events WHERE rule_id LIKE ?", tag+"%").Scan(&n); err != nil {
		t.Fatalf("count rows: %v", err)
	}
	if n != len(events) {
		t.Errorf("waf_events rows = %d, want %d (replay inserted duplicates)", n, len(events))
	}
}
