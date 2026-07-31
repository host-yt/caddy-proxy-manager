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
	key    string
	gen    int
	mu     sync.Mutex
	lastOK time.Time
}

func (b *fleetBeacon) markPublished(now time.Time) {
	b.mu.Lock()
	b.lastOK = now
	b.mu.Unlock()
}

func (b *fleetBeacon) fresh(now time.Time) bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	return !b.lastOK.IsZero() && now.Sub(b.lastOK) <= fleetPublishGrace
}

// StartGenerationHeartbeat announces this replica's generation in shared
// state (TTL key, self-expiring on crash) so FleetGenerationReady can order
// the fleet - the fence future rolling upgrades need but this release's old
// binary predates.
func (m *Manager) StartGenerationHeartbeat(ctx context.Context, logger *slog.Logger) {
	m.startFleetBeacon(ctx, logger, ClusterGeneration)
}

func (m *Manager) startFleetBeacon(ctx context.Context, logger *slog.Logger, gen int) {
	if m == nil || m.rdb == nil {
		return
	}
	idBytes := make([]byte, 8)
	_, _ = rand.Read(idBytes)
	b := &fleetBeacon{
		key: fmt.Sprintf("%s%d:%s", fleetKeyPrefix, gen, hex.EncodeToString(idBytes)),
		gen: gen,
	}
	m.fleet.Store(b)
	m.publishFleetBeat(ctx, logger)
	go func() {
		t := time.NewTicker(fleetHeartbeatEvery)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				m.publishFleetBeat(ctx, logger)
			}
		}
	}()
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

// FleetGenerationReady reports whether this replica may admit traffic.
//
// The fence is asymmetric and ordered by generation number: a replica serves
// only while it is publishing its own heartbeat AND no strictly newer
// generation is live. Symmetric mutual exclusion would deadlock a rolling
// upgrade (neither side could ever become ready); with ordering the newest
// generation present is always allowed to serve, so the fleet converges:
// new replicas go ready immediately, old ones drain, and their keys expire.
func (m *Manager) FleetGenerationReady(ctx context.Context) error {
	if m == nil || m.rdb == nil {
		return nil
	}
	b := m.fleet.Load()
	if b == nil {
		return ErrFleetNotPublished
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
		return fmt.Errorf("%w: generation %d", ErrFleetNewerGeneration, newest)
	}
	return nil
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
