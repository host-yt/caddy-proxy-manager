package leader

import (
	"context"
	"testing"
	"time"
)

// Without Redis the election degrades to single-process always-leader.
// This is the contract main.go relies on for local/dev/single-replica runs.
func TestNoRedisAlwaysLeader(t *testing.T) {
	e := New(nil)
	if e.IsLeader() {
		t.Fatal("should not be leader before any attempt")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	e.attempt(ctx)
	if !e.IsLeader() {
		t.Fatal("should be leader after first attempt when RDB is nil")
	}
}
