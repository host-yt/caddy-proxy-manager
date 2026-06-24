// Package leader provides a simple Redis-backed singleton lock so background
// workers (health probe, metrics poller, route reconciler, drift probe,
// backup scheduler) only run on one replica when the panel is deployed
// hot-standby.
//
// Algorithm:
//   - Each replica generates a random tokenID at start.
//   - Every interval, replica tries `SET hpg:leader <tokenID> NX PX <ttl>`.
//     On success it holds leadership until ttl elapses.
//   - Every interval/2 the holder refreshes via Lua `if get==me then pexpire`.
//   - Replicas that aren't holder treat IsLeader() as false.
//
// In a single-replica deploy the same replica is always the leader; the lock
// is a no-op overhead (~1 ms per interval).
package leader

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"sync/atomic"
	"time"

	"github.com/redis/go-redis/v9"
)

const (
	defaultKey      = "hpg:leader"
	defaultTTL      = 15 * time.Second
	defaultInterval = 5 * time.Second
)

// Election holds a leadership state for one replica.
type Election struct {
	RDB      *redis.Client
	Key      string
	TTL      time.Duration
	Interval time.Duration

	id     string
	leader atomic.Bool
}

// New returns an Election with sane defaults.
func New(rdb *redis.Client) *Election {
	idBytes := make([]byte, 8)
	_, _ = rand.Read(idBytes)
	return &Election{
		RDB:      rdb,
		Key:      defaultKey,
		TTL:      defaultTTL,
		Interval: defaultInterval,
		id:       hex.EncodeToString(idBytes),
	}
}

// IsLeader returns true when this replica currently holds the lock.
// Cheap — checks an atomic flag, no Redis call.
func (e *Election) IsLeader() bool { return e.leader.Load() }

// Run blocks until ctx done, repeatedly attempting acquisition + refresh.
// Spawn from main as a goroutine.
func (e *Election) Run(ctx context.Context) {
	t := time.NewTicker(e.Interval)
	defer t.Stop()
	e.attempt(ctx)
	for {
		select {
		case <-ctx.Done():
			e.release(context.Background())
			return
		case <-t.C:
			e.attempt(ctx)
		}
	}
}

// luaRefresh extends TTL only when our id still holds the key. Prevents a
// stale holder (one that lost its lease) from accidentally refreshing.
const luaRefresh = `
if redis.call("GET", KEYS[1]) == ARGV[1] then
  return redis.call("PEXPIRE", KEYS[1], ARGV[2])
else
  return 0
end`

const luaRelease = `
if redis.call("GET", KEYS[1]) == ARGV[1] then
  return redis.call("DEL", KEYS[1])
else
  return 0
end`

func (e *Election) attempt(ctx context.Context) {
	if e.RDB == nil {
		// No Redis → always leader (single-process fallback).
		e.leader.Store(true)
		return
	}
	ttlMs := int(e.TTL / time.Millisecond)
	if e.leader.Load() {
		// Try to renew first.
		got, err := e.RDB.Eval(ctx, luaRefresh, []string{e.Key}, e.id, ttlMs).Int()
		if err == nil && got == 1 {
			return
		}
		// Lost lease; fall through to re-acquire.
		e.leader.Store(false)
	}
	ok, err := e.RDB.SetNX(ctx, e.Key, e.id, e.TTL).Result()
	if err != nil {
		// Stay non-leader on Redis errors.
		e.leader.Store(false)
		return
	}
	e.leader.Store(ok)
}

func (e *Election) release(ctx context.Context) {
	if e.RDB == nil || !e.leader.Load() {
		return
	}
	_, _ = e.RDB.Eval(ctx, luaRelease, []string{e.Key}, e.id).Result()
	e.leader.Store(false)
}
