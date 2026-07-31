package auth

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"strconv"
	"strings"
	"sync"
	"time"
)

// ClusterGeneration ties the fleet fence to the session schema: a replica on
// a different generation treats Restricted/Epoch differently and must not
// share traffic with this one.
const ClusterGeneration = sessionSchemaVer

const (
	fleetKeyPrefix      = "hpg:fleet:"
	fleetHeartbeatTTL   = 20 * time.Second
	fleetHeartbeatEvery = 8 * time.Second
	// One missed beat is tolerated; past this the fleet is about to lose our
	// key (TTL 20s) and we must stop admitting traffic before it does.
	fleetPublishGrace = 16 * time.Second
	// Withdrawal must still land after the serving context is cancelled.
	fleetWithdrawTimeout = 2 * time.Second
	// A hung DB must not stall the beacon loop; a timeout counts as unready.
	fleetReadyTimeout = 3 * time.Second
)

var (
	// ErrFleetNotPublished means this replica is not visible to the fleet, so
	// peers cannot fence against us and we must not serve.
	ErrFleetNotPublished = errors.New("fleet generation heartbeat not published")
	// ErrFleetNewerGeneration means a strictly newer generation is live; the
	// older side yields so the newer, stricter binary owns the traffic.
	ErrFleetNewerGeneration = errors.New("a newer session generation is live in the fleet")
)

// fleetBeacon tracks this replica's own heartbeat key and the last time a
// publish actually succeeded. gen is a field, not the constant, so a
// two-generation rollout is testable in one process.
type fleetBeacon struct {
	key string
	gen int
	// localReady gates advertising: we must not claim a generation we cannot
	// actually serve, or every older peer yields to a replica that never works.
	localReady func(context.Context) error
	mu         sync.Mutex
	lastOK     time.Time
	// everOK stays true after the first successful publish, so a replica that
	// boots unready does not log a withdrawal it never made.
	everOK bool
	// fenced latches once a newer generation is seen; the request path reads it
	// without touching Redis, and it never un-latches (no flapping mid-drain).
	fenced    bool
	fencedCh  chan struct{}
	fenceOnce sync.Once
	// stopped closes once the beacon loop has withdrawn and exited.
	stopped chan struct{}
}

func (b *fleetBeacon) markPublished(now time.Time) {
	b.mu.Lock()
	b.lastOK = now
	b.everOK = true
	b.mu.Unlock()
}

func (b *fleetBeacon) published() bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.everOK
}

// markWithdrawn drops our advertisement so peers stop fencing against us.
func (b *fleetBeacon) markWithdrawn() {
	b.mu.Lock()
	b.lastOK = time.Time{}
	b.mu.Unlock()
}

func (b *fleetBeacon) fresh(now time.Time) bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	return !b.lastOK.IsZero() && now.Sub(b.lastOK) <= fleetPublishGrace
}

func (b *fleetBeacon) trip() {
	b.mu.Lock()
	b.fenced = true
	b.mu.Unlock()
	b.fenceOnce.Do(func() { close(b.fencedCh) })
}

func (b *fleetBeacon) isFenced() bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.fenced
}

// StartGenerationHeartbeat announces this replica's generation in shared
// state (TTL key, self-expiring on crash) so FleetGenerationReady can order
// the fleet - the fence future rolling upgrades need but this release's old
// binary predates. localReady must report this process's own serving
// prerequisites (DB, Redis, install state and a self-probed HTTP listener);
// nil means "always ready".
func (m *Manager) StartGenerationHeartbeat(ctx context.Context, logger *slog.Logger, localReady func(context.Context) error) {
	m.startFleetBeacon(ctx, logger, ClusterGeneration, localReady)
}

func (m *Manager) startFleetBeacon(ctx context.Context, logger *slog.Logger, gen int, localReady func(context.Context) error) {
	if m == nil || m.rdb == nil {
		return
	}
	idBytes := make([]byte, 8)
	_, _ = rand.Read(idBytes)
	b := &fleetBeacon{
		key:        fmt.Sprintf("%s%d:%s", fleetKeyPrefix, gen, hex.EncodeToString(idBytes)),
		gen:        gen,
		localReady: localReady,
		fencedCh:   make(chan struct{}),
		stopped:    make(chan struct{}),
	}
	m.fleet.Store(b)
	m.refreshFleetBeat(ctx, logger)
	go func() {
		defer close(b.stopped)
		t := time.NewTicker(fleetHeartbeatEvery)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				// Tie the advertisement to the serving lifecycle: on shutdown
				// peers must see us leave immediately, not after the TTL.
				m.withdrawFleetBeat(logger, "shutdown")
				return
			case <-t.C:
				m.refreshFleetBeat(ctx, logger)
			}
		}
	}()
}

// refreshFleetBeat publishes (or withdraws) our advertisement and refreshes
// the cached fence state the request path reads.
func (m *Manager) refreshFleetBeat(ctx context.Context, logger *slog.Logger) {
	b := m.fleet.Load()
	if b == nil {
		return
	}
	if b.localReady != nil {
		rctx, cancel := context.WithTimeout(ctx, fleetReadyTimeout)
		err := b.localReady(rctx)
		cancel()
		if err != nil {
			m.withdrawFleetBeat(logger, err.Error())
			m.refreshFleetFence(ctx, b)
			return
		}
	}
	m.publishFleetBeat(ctx, logger)
	m.refreshFleetFence(ctx, b)
}

// refreshFleetFence caches whether a strictly newer generation is live so
// per-request enforcement costs no Redis round-trip.
func (m *Manager) refreshFleetFence(ctx context.Context, b *fleetBeacon) {
	if _, newest, err := m.scanFleet(ctx, b.key, b.gen); err == nil && newest > b.gen {
		b.trip()
	}
}

// publishFleetBeat refreshes our heartbeat key. On failure lastOK is left
// stale on purpose: an unpublished replica must go unready, not just log.
func (m *Manager) publishFleetBeat(ctx context.Context, logger *slog.Logger) {
	b := m.fleet.Load()
	if b == nil {
		return
	}
	now := time.Now()
	if err := m.rdb.Set(ctx, b.key, strconv.FormatInt(now.Unix(), 10), fleetHeartbeatTTL).Err(); err != nil {
		if logger != nil {
			logger.Warn("fleet generation heartbeat failed", "err", err)
		}
		return
	}
	b.markPublished(now)
}

// withdrawFleetBeat retracts our generation claim. Used when this replica
// cannot serve locally: holding the newest generation while broken would keep
// every healthy older replica unready forever.
func (m *Manager) withdrawFleetBeat(logger *slog.Logger, reason string) {
	b := m.fleet.Load()
	if b == nil {
		return
	}
	if !b.published() {
		// Never advertised (e.g. still binding at boot) - nothing to retract.
		return
	}
	b.markWithdrawn()
	ctx, cancel := context.WithTimeout(context.Background(), fleetWithdrawTimeout)
	defer cancel()
	if err := m.rdb.Del(ctx, b.key).Err(); err != nil && logger != nil {
		logger.Warn("fleet generation withdrawal failed", "reason", reason, "err", err)
		return
	}
	if logger != nil {
		logger.Warn("withdrew fleet generation advertisement", "reason", reason)
	}
}

// FleetGenerationReady reports whether this replica may admit traffic.
//
// The fence is asymmetric and ordered by generation number: a replica serves
// only while it is publishing its own heartbeat AND no strictly newer
// generation is live. Only a locally healthy replica advertises at all, so the
// highest advertised generation is always one that can actually serve.
// Symmetric mutual exclusion would deadlock a rolling upgrade; with ordering
// the newest healthy generation present always serves and the fleet converges.
func (m *Manager) FleetGenerationReady(ctx context.Context) error {
	if m == nil || m.rdb == nil {
		return nil
	}
	b := m.fleet.Load()
	if b == nil {
		return ErrFleetNotPublished
	}
	if b.isFenced() {
		return ErrFleetNewerGeneration
	}
	if !b.fresh(time.Now()) {
		return ErrFleetNotPublished
	}
	selfSeen, newest, err := m.scanFleet(ctx, b.key, b.gen)
	if err != nil {
		return err
	}
	// Our key must be readable back: a wiped or swapped Redis means the fleet
	// state we just fenced against is not the one peers are reading.
	if !selfSeen {
		return ErrFleetNotPublished
	}
	if newest > b.gen {
		b.trip()
		return fmt.Errorf("%w: generation %d", ErrFleetNewerGeneration, newest)
	}
	return nil
}

// FleetFenceActive is the cached, allocation-free fence read for the request
// path: true once a newer generation owns the fleet and this binary's more
// permissive session handling must stop serving.
func (m *Manager) FleetFenceActive() bool {
	if m == nil {
		return false
	}
	b := m.fleet.Load()
	return b != nil && b.isFenced()
}

// FleetFenceTripped closes when a newer generation appears, so the server can
// start draining instead of waiting for an external controller to notice.
func (m *Manager) FleetFenceTripped() <-chan struct{} {
	if m == nil {
		return nil
	}
	b := m.fleet.Load()
	if b == nil {
		return nil
	}
	return b.fencedCh
}

// scanFleet returns whether selfKey is present and the highest generation
// currently heartbeating. A scan failure is an error, not a clear read.
func (m *Manager) scanFleet(ctx context.Context, selfKey string, ownGen int) (bool, int, error) {
	var (
		cursor   uint64
		selfSeen bool
		newest   = ownGen
	)
	for {
		keys, next, err := m.rdb.Scan(ctx, cursor, fleetKeyPrefix+"*", 200).Result()
		if err != nil {
			return false, 0, err
		}
		for _, k := range keys {
			if k == selfKey {
				selfSeen = true
			}
			rest := strings.TrimPrefix(k, fleetKeyPrefix)
			genStr, _, ok := strings.Cut(rest, ":")
			if !ok {
				continue
			}
			gen, err := strconv.Atoi(genStr)
			if err != nil {
				continue
			}
			if gen > newest {
				newest = gen
			}
		}
		cursor = next
		if cursor == 0 {
			return selfSeen, newest, nil
		}
	}
}
