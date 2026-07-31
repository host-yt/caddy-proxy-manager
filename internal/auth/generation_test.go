package auth

import (
	"context"
	"errors"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/redis/go-redis/v9"

	"github.com/host-yt/caddy-proxy-manager/internal/obs"
)

// startedManager brings up a replica on gen with its heartbeat already
// published. The context is cancelled only at cleanup, so the ticker goroutine
// cannot race the non-locking fakeRedis map during the test.
func startedManager(t *testing.T, f *fakeRedis, gen int) *Manager {
	t.Helper()
	return startedManagerReady(t, f, gen, nil)
}

func startedManagerReady(t *testing.T, r sessionRedis, gen int, localReady func(context.Context) error) *Manager {
	t.Helper()
	m := NewSessionManager(nil, "hpg_session", false, "lax", time.Hour)
	m.rdb = r
	ctx, cancel := context.WithCancel(context.Background())
	m.startFleetBeacon(ctx, nil, gen, localReady)
	// Wait for the beacon goroutine to finish withdrawing, so its Redis writes
	// cannot race a peer's cleanup on the same fake.
	t.Cleanup(func() {
		cancel()
		<-m.fleet.Load().stopped
	})
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

// ttlRedis is a sessionRedis with real key expiry on a manual clock, so a
// surge/drain rollout can be replayed without sleeping 20 real seconds.
type ttlRedis struct {
	mu   sync.Mutex
	now  time.Time
	vals map[string]ttlVal
}

type ttlVal struct {
	v   string
	exp time.Time
}

func newTTLRedis() *ttlRedis {
	return &ttlRedis{now: time.Unix(1_700_000_000, 0), vals: map[string]ttlVal{}}
}

func (r *ttlRedis) advance(d time.Duration) {
	r.mu.Lock()
	r.now = r.now.Add(d)
	r.mu.Unlock()
}

func (r *ttlRedis) live() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	var keys []string
	for k, v := range r.vals {
		if v.exp.After(r.now) {
			keys = append(keys, k)
		}
	}
	return keys
}

func (r *ttlRedis) Get(_ context.Context, key string) *redis.StringCmd {
	r.mu.Lock()
	defer r.mu.Unlock()
	v, ok := r.vals[key]
	if !ok || !v.exp.After(r.now) {
		return redis.NewStringResult("", redis.Nil)
	}
	return redis.NewStringResult(v.v, nil)
}

func (r *ttlRedis) Set(_ context.Context, key string, value any, ttl time.Duration) *redis.StatusCmd {
	r.mu.Lock()
	defer r.mu.Unlock()
	s, _ := value.(string)
	r.vals[key] = ttlVal{v: s, exp: r.now.Add(ttl)}
	return redis.NewStatusResult("OK", nil)
}

func (r *ttlRedis) Del(_ context.Context, keys ...string) *redis.IntCmd {
	r.mu.Lock()
	defer r.mu.Unlock()
	var n int64
	for _, k := range keys {
		if _, ok := r.vals[k]; ok {
			delete(r.vals, k)
			n++
		}
	}
	return redis.NewIntResult(n, nil)
}

func (r *ttlRedis) Scan(_ context.Context, _ uint64, match string, _ int64) *redis.ScanCmd {
	prefix := strings.TrimSuffix(match, "*")
	var keys []string
	for _, k := range r.live() {
		if strings.HasPrefix(k, prefix) {
			keys = append(keys, k)
		}
	}
	return redis.NewScanCmdResult(keys, 0, nil)
}

// TestUnhealthyNewerReplicaDoesNotWedgeFleet is the surge-then-drain case: a
// newer replica whose DB never comes up must not advertise its generation,
// or every healthy older replica yields to it and the fleet has zero ready
// instances for as long as the broken process keeps refreshing its key.
func TestUnhealthyNewerReplicaDoesNotWedgeFleet(t *testing.T) {
	r := newTTLRedis()
	ctx := context.Background()
	broken := errors.New("db: connection refused")
	newReady := func(context.Context) error { return broken }

	oldA := startedManagerReady(t, r, ClusterGeneration, nil)
	oldB := startedManagerReady(t, r, ClusterGeneration, nil)
	newC := startedManagerReady(t, r, ClusterGeneration+1, func(c context.Context) error { return newReady(c) })

	mustReady := func(step string, m *Manager) {
		t.Helper()
		if err := m.FleetGenerationReady(ctx); err != nil {
			t.Fatalf("%s: expected ready, got %v", step, err)
		}
	}

	mustReady("surge with broken new replica: old A", oldA)
	mustReady("surge with broken new replica: old B", oldB)
	if err := newC.FleetGenerationReady(ctx); !errors.Is(err, ErrFleetNotPublished) {
		t.Fatalf("unhealthy replica must not be ready, got %v", err)
	}
	if len(r.live()) != 2 {
		t.Fatalf("broken replica must not advertise; live keys = %v", r.live())
	}

	// Past the 20s TTL the old replicas keep beating and stay ready - the
	// broken one never converts its unreadiness into a fleet-wide outage.
	for i := 0; i < 3; i++ {
		r.advance(fleetHeartbeatEvery)
		oldA.refreshFleetBeat(ctx, nil)
		oldB.refreshFleetBeat(ctx, nil)
		newC.refreshFleetBeat(ctx, nil)
	}
	mustReady("after TTL window: old A", oldA)
	mustReady("after TTL window: old B", oldB)

	// The new replica recovers, advertises, and only then do the old ones yield.
	newReady = func(context.Context) error { return nil }
	newC.refreshFleetBeat(ctx, nil)
	mustReady("recovered new replica", newC)
	if err := oldA.FleetGenerationReady(ctx); !errors.Is(err, ErrFleetNewerGeneration) {
		t.Fatalf("old replica must yield once a healthy newer one advertises, got %v", err)
	}
}

// TestPortConflictNewReplicaKeepsOlderFleetServing: the new binary loses the
// bind (port already taken). Its serving gate never opens, so it never
// advertises the newer generation and the healthy older replicas keep serving
// instead of latching the fence and self-shutting-down.
func TestPortConflictNewReplicaKeepsOlderFleetServing(t *testing.T) {
	r := newTTLRedis()
	ctx := context.Background()

	held, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer held.Close()

	gate := obs.NewServingGate(0)
	if _, err := net.Listen("tcp", held.Addr().String()); err != nil {
		gate.MarkStopped(err)
	} else {
		t.Fatal("precondition: second bind on the same port must fail")
	}

	oldA := startedManagerReady(t, r, ClusterGeneration, nil)
	oldB := startedManagerReady(t, r, ClusterGeneration, nil)
	newC := startedManagerReady(t, r, ClusterGeneration+1, gate.Check)

	for i := 0; i < 3; i++ {
		r.advance(fleetHeartbeatEvery)
		oldA.refreshFleetBeat(ctx, nil)
		oldB.refreshFleetBeat(ctx, nil)
		newC.refreshFleetBeat(ctx, nil)
	}

	if err := oldA.FleetGenerationReady(ctx); err != nil {
		t.Fatalf("old A must keep serving through a failed rollout, got %v", err)
	}
	if err := oldB.FleetGenerationReady(ctx); err != nil {
		t.Fatalf("old B must keep serving through a failed rollout, got %v", err)
	}
	if oldA.FleetFenceActive() || oldB.FleetFenceActive() {
		t.Fatal("fence must not latch for a replica that never bound its listener")
	}
	if err := newC.FleetGenerationReady(ctx); !errors.Is(err, ErrFleetNotPublished) {
		t.Fatalf("the replica that lost the bind must not be ready, got %v", err)
	}
	if len(r.live()) != 2 {
		t.Fatalf("only the two old replicas may advertise; live keys = %v", r.live())
	}

	// It recovers only once the listener is genuinely up.
	gate.MarkServing()
	newC.refreshFleetBeat(ctx, nil)
	if err := newC.FleetGenerationReady(ctx); err != nil {
		t.Fatalf("bound replica must advertise and serve, got %v", err)
	}
	if err := oldA.FleetGenerationReady(ctx); !errors.Is(err, ErrFleetNewerGeneration) {
		t.Fatalf("old replica yields only now, got %v", err)
	}
}

// TestFleetBeaconWithdrawsWhenReadinessLost: losing local readiness must pull
// the advertisement out of Redis, not just stop refreshing it.
func TestFleetBeaconWithdrawsWhenReadinessLost(t *testing.T) {
	r := newTTLRedis()
	ctx := context.Background()
	var healthy atomic.Bool
	healthy.Store(true)
	m := startedManagerReady(t, r, ClusterGeneration, func(context.Context) error {
		if healthy.Load() {
			return nil
		}
		return errors.New("db down")
	})
	if err := m.FleetGenerationReady(ctx); err != nil {
		t.Fatalf("precondition: healthy replica should be ready, got %v", err)
	}

	healthy.Store(false)
	m.refreshFleetBeat(ctx, nil)
	if len(r.live()) != 0 {
		t.Fatalf("advertisement must be withdrawn, live keys = %v", r.live())
	}
	if err := m.FleetGenerationReady(ctx); !errors.Is(err, ErrFleetNotPublished) {
		t.Fatalf("want ErrFleetNotPublished after withdrawal, got %v", err)
	}
}

// TestFleetFenceLatchesForRequestPath: the request-path fence is cached (no
// Redis per request), trips a drain signal, and never un-latches - a replica
// that once saw a newer generation must not resume serving.
func TestFleetFenceLatchesForRequestPath(t *testing.T) {
	f := newFakeRedis()
	m := startedManager(t, f, ClusterGeneration)
	if m.FleetFenceActive() {
		t.Fatal("fence must be inactive on a clean fleet")
	}

	f.vals[fleetKeyPrefix+"99:cafe"] = "1"
	m.refreshFleetBeat(context.Background(), nil)
	if !m.FleetFenceActive() {
		t.Fatal("fence must trip once a newer generation is live")
	}
	select {
	case <-m.FleetFenceTripped():
	default:
		t.Fatal("drain signal must fire when the fence trips")
	}

	delete(f.vals, fleetKeyPrefix+"99:cafe")
	m.refreshFleetBeat(context.Background(), nil)
	if !m.FleetFenceActive() {
		t.Fatal("fence must stay latched after the newer peer disappears")
	}
	if err := m.FleetGenerationReady(context.Background()); !errors.Is(err, ErrFleetNewerGeneration) {
		t.Fatalf("readiness must stay fenced, got %v", err)
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
