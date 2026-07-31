package auth

import (
	"context"
	"testing"
)

// TestIncompatibleGenerationPresent guards the future-upgrade fence: a
// heartbeat from any generation other than ours must be detected so Ready()
// can refuse traffic during a mixed-version rollout.
func TestIncompatibleGenerationPresent(t *testing.T) {
	f := newFakeRedis()
	f.vals[fleetKeyPrefix+"1:deadbeef"] = "1" // old generation still heartbeating
	m := testManager(f)

	found, err := m.IncompatibleGenerationPresent(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !found {
		t.Fatal("expected an old-generation heartbeat to be detected as incompatible")
	}
}

// TestIncompatibleGenerationAbsentWhenFleetMatches confirms no false
// positive when every heartbeat is our own generation.
func TestIncompatibleGenerationAbsentWhenFleetMatches(t *testing.T) {
	f := newFakeRedis()
	f.vals[fleetKeyPrefix+"2:aaaa"] = "1"
	f.vals[fleetKeyPrefix+"2:bbbb"] = "1"
	m := testManager(f)

	found, err := m.IncompatibleGenerationPresent(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if found {
		t.Fatal("expected no incompatible generation when the whole fleet matches")
	}
}

// TestStartGenerationHeartbeatWritesOwnGeneration checks the heartbeat key
// this replica writes is tagged with ClusterGeneration, not a stale value.
func TestStartGenerationHeartbeatWritesOwnGeneration(t *testing.T) {
	f := newFakeRedis()
	m := testManager(f)

	// beat() runs synchronously before the ticker goroutine starts, so
	// cancelling right away still leaves the key written and avoids a
	// leaked goroutine in the test process.
	ctx, cancel := context.WithCancel(context.Background())
	m.StartGenerationHeartbeat(ctx, nil)
	cancel()

	found, err := m.IncompatibleGenerationPresent(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if found {
		t.Fatal("a lone replica's own heartbeat must never be flagged as incompatible")
	}
	if len(f.vals) != 1 {
		t.Fatalf("expected exactly one fleet key written, got %d", len(f.vals))
	}
}
