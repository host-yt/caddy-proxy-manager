package auth

import (
	"context"
	"errors"
	"sync"
	"time"
)

// ErrAPIKeyThrottled means the expensive verification path was refused, not
// that the credential was wrong. Callers answer 429, never 401.
var ErrAPIKeyThrottled = errors.New("api key verification throttled")

// Budget for the Argon2 compat path. One Argon2id verify is ~150 ms and 64 MiB
// and cannot be cancelled once started, so an unauthenticated caller who knows
// a key prefix must not be able to queue up an unbounded number of them.
// Genuine use is one verify per legacy key ever (the row is upgraded to HMAC
// right after), so the budget is deliberately small.
const (
	legacyKDFConcurrency = 2
	legacyKDFPerPrefix   = 5               // per minute, per key prefix
	legacyKDFPerMinute   = 60              // per minute, process-wide
	legacyKDFWait        = 2 * time.Second // how long a verify waits for a slot
)

type kdfBudget struct {
	sem chan struct{}

	mu       sync.Mutex
	winStart time.Time
	total    int
	perKey   map[string]int
}

// legacyKDF is the process-wide budget for pre-auth Argon2 work.
var legacyKDF = newKDFBudget(legacyKDFConcurrency)

func newKDFBudget(concurrency int) *kdfBudget {
	return &kdfBudget{sem: make(chan struct{}, concurrency), perKey: map[string]int{}}
}

// reserve counts one verification against the current minute window.
func (b *kdfBudget) reserve(key string) bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	now := time.Now()
	if now.Sub(b.winStart) >= time.Minute {
		b.winStart = now
		b.total = 0
		b.perKey = make(map[string]int, legacyKDFPerMinute)
	}
	// The global cap also bounds perKey: at most legacyKDFPerMinute entries.
	if b.total >= legacyKDFPerMinute || b.perKey[key] >= legacyKDFPerPrefix {
		return false
	}
	b.total++
	b.perKey[key]++
	return true
}

// acquire takes a rate slot and a concurrency slot. The returned release must
// be called once the KDF is done. Refuses rather than queueing: a request that
// waits here still pins a connection and the work it waits for is unstoppable.
func (b *kdfBudget) acquire(ctx context.Context, key string) (func(), error) {
	if !b.reserve(key) {
		return nil, ErrAPIKeyThrottled
	}
	t := time.NewTimer(legacyKDFWait)
	defer t.Stop()
	select {
	case b.sem <- struct{}{}:
		return func() { <-b.sem }, nil
	case <-ctx.Done():
		return nil, ErrAPIKeyThrottled
	case <-t.C:
		return nil, ErrAPIKeyThrottled
	}
}
