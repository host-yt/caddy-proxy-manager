package auth

import (
	"context"
	"errors"
	"testing"
	"time"
)

// startedManager brings up a replica on gen with its heartbeat already
// published; the context is cancelled so the ticker goroutine cannot race the
// non-locking fakeRedis map.
func startedManager(t *testing.T, f *fakeRedis, gen int) *Manager {
	t.Helper()
	m := testManager(f)
	ctx, cancel := context.WithCancel(context.Background())
	m.startFleetBeacon(ctx, nil, gen)
	cancel()
	return m
}

// TestFleetGenerationReadyLoneReplica: a single replica seeing only its own
// heartbeat serves.
func TestFleetGenerationReadyLoneReplica(t *testing.T) {
	f := newFakeRedis()
	m := startedManager(t, f, ClusterGeneration)

	if err := m.FleetGenerationReady(context.Background()); err != nil {
		t.Fatalf("lone replica must be ready, got %v", err)
	}
	if len(f.vals) != 1 {
		t.Fatalf("expected exactly one fleet key written, got %d", len(f.vals))
	}
}

// TestFleetGenerationOlderPeerDoesNotBlockUs is the asymmetry: an old
// generation still heartbeating must not stop the newer replica serving,
// otherwise a rolling upgrade deadlocks.
func TestFleetGenerationOlderPeerDoesNotBlockUs(t *testing.T) {
	f := newFakeRedis()
	f.vals[fleetKeyPrefix+"1:deadbeef"] = "1"
	m := startedManager(t, f, ClusterGeneration)

	if err := m.FleetGenerationReady(context.Background()); err != nil {
		t.Fatalf("newer generation must serve while an older peer drains, got %v", err)
	}
}

// TestFleetGenerationYieldsToNewer: the older replica steps aside so the
// stricter binary owns the traffic.
func TestFleetGenerationYieldsToNewer(t *testing.T) {
	f := newFakeRedis()
	f.vals[fleetKeyPrefix+"99:cafe"] = "1"
	m := startedManager(t, f, ClusterGeneration)

	err := m.FleetGenerationReady(context.Background())
	if !errors.Is(err, ErrFleetNewerGeneration) {
		t.Fatalf("want ErrFleetNewerGeneration, got %v", err)
	}
}

// TestFleetGenerationNotReadyBeforeHeartbeatStarts keeps the fence
// fail-closed when the beacon was never started.
func TestFleetGenerationNotReadyBeforeHeartbeatStarts(t *testing.T) {
	m := testManager(newFakeRedis())

	if err := m.FleetGenerationReady(context.Background()); !errors.Is(err, ErrFleetNotPublished) {
		t.Fatalf("want ErrFleetNotPublished, got %v", err)
	}
}

// TestFleetGenerationRedisDownAtStartThenRecovers: a boot with Redis
// unavailable must stay unready until a publish actually succeeds - the old
// code only logged the failed SET and let /readyz pass.
func TestFleetGenerationRedisDownAtStartThenRecovers(t *testing.T) {
	f := newFakeRedis()
	f.setErr = errors.New("connection refused")
	m := startedManager(t, f, ClusterGeneration)

	if err := m.FleetGenerationReady(context.Background()); !errors.Is(err, ErrFleetNotPublished) {
		t.Fatalf("unpublished replica must not be ready, got %v", err)
	}

	f.setErr = nil
	m.publishFleetBeat(context.Background(), nil)
	if err := m.FleetGenerationReady(context.Background()); err != nil {
		t.Fatalf("ready expected once the heartbeat lands, got %v", err)
	}
}

// TestFleetGenerationReadOnlyRedis covers a Redis that answers PING/SCAN but
// rejects writes: the key ages out of the grace window and we go unready.
func TestFleetGenerationReadOnlyRedis(t *testing.T) {
	f := newFakeRedis()
	m := startedManager(t, f, ClusterGeneration)
	if err := m.FleetGenerationReady(context.Background()); err != nil {
		t.Fatalf("precondition: replica should start ready, got %v", err)
	}

	f.setErr = errors.New("READONLY You can't write against a read only replica")
	b := m.fleet.Load()
	b.markPublished(time.Now().Add(-fleetPublishGrace - time.Second))
	m.publishFleetBeat(context.Background(), nil) // fails, must not refresh lastOK

	if err := m.FleetGenerationReady(context.Background()); !errors.Is(err, ErrFleetNotPublished) {
		t.Fatalf("stale heartbeat must fail readiness, got %v", err)
	}
}

// TestFleetGenerationSelfKeyMissing: a wiped or swapped Redis means peers are
// not reading the state we fenced against.
func TestFleetGenerationSelfKeyMissing(t *testing.T) {
	f := newFakeRedis()
	m := startedManager(t, f, ClusterGeneration)
	f.vals = map[string]string{}

	if err := m.FleetGenerationReady(context.Background()); !errors.Is(err, ErrFleetNotPublished) {
		t.Fatalf("want ErrFleetNotPublished after a fleet-state wipe, got %v", err)
	}
}

// TestFleetGenerationScanError keeps an unreadable fleet state from reading
// as "clear".
func TestFleetGenerationScanError(t *testing.T) {
	f := newFakeRedis()
	m := startedManager(t, f, ClusterGeneration)
	f.scanErr = errors.New("scan failed")

	if err := m.FleetGenerationReady(context.Background()); err == nil {
		t.Fatal("a scan failure must not be reported as ready")
	}
}

// TestRollingControllerTwoGenerations simulates a controller that keeps the
// old replica alive until the new one is ready. The symmetric design
// deadlocked here (both sides unready forever); with generation ordering at
// least one replica is ready at every step and the rollout converges.
func TestRollingControllerTwoGenerations(t *testing.T) {
	f := newFakeRedis()
	ctx := context.Background()

	oldA := startedManager(t, f, ClusterGeneration)
	oldB := startedManager(t, f, ClusterGeneration)
	assertReady := func(step string, m *Manager, want bool) {
		t.Helper()
		err := m.FleetGenerationReady(ctx)
		if want && err != nil {
			t.Fatalf("%s: expected ready, got %v", step, err)
		}
		if !want && err == nil {
			t.Fatalf("%s: expected not ready", step)
		}
	}

	assertReady("steady old fleet: A", oldA, true)
	assertReady("steady old fleet: B", oldB, true)

	// Controller surges in a new-generation replica; old ones keep running.
	newA := startedManager(t, f, ClusterGeneration+1)
	assertReady("surge: new replica", newA, true) // deadlocked under symmetric checks
	assertReady("surge: old A yields", oldA, false)
	assertReady("surge: old B yields", oldB, false)

	// New replica reported ready, so the controller retires old A; its key
	// expires (TTL) and the fleet keeps serving throughout.
	delete(f.vals, oldA.fleet.Load().key)
	assertReady("drain A: new replica", newA, true)

	// Second new replica joins, last old replica retires.
	newB := startedManager(t, f, ClusterGeneration+1)
	delete(f.vals, oldB.fleet.Load().key)
	assertReady("converged: new A", newA, true)
	assertReady("converged: new B", newB, true)
	if len(f.vals) != 2 {
		t.Fatalf("expected only the two new-generation keys left, got %d", len(f.vals))
	}
}
