package auth

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/redis/go-redis/v9"
)

// legacyWatchInterval is how often we look for an old replica still minting.
const legacyWatchInterval = 2 * time.Minute

// LegacyMintingDetected reports whether a session appeared in the pre-version
// namespace AFTER `since`. Only a running old replica can create one, and that
// replica ignores Restricted/Epoch entirely - it will happily serve a confined
// admin as a platform admin. Leftover keys from before the upgrade are older
// than `since` and do not trigger.
func (m *Manager) LegacyMintingDetected(ctx context.Context, since time.Time) (bool, error) {
	if m == nil || m.rdb == nil {
		return false, nil
	}
	var cursor uint64
	var decodeErrs int
	for {
		keys, next, err := m.rdb.Scan(ctx, cursor, legacySessionKeyPrefix+"*", 200).Result()
		if err != nil {
			// Never report "all clear" from a failed look: a broken Redis is
			// exactly what accompanies a botched rolling upgrade.
			return false, err
		}
		for _, k := range keys {
			b, gerr := m.rdb.Get(ctx, k).Bytes()
			if gerr != nil {
				if errors.Is(gerr, redis.Nil) {
					continue // expired between SCAN and GET, not a decode failure
				}
				return false, gerr
			}
			var s Session
			if json.Unmarshal(b, &s) != nil {
				// A corrupt session record is itself an anomaly; don't let it
				// masquerade as "no legacy sessions found".
				decodeErrs++
				continue
			}
			if s.CreatedAt.After(since) {
				return true, nil
			}
		}
		cursor = next
		if cursor == 0 {
			break
		}
	}
	if decodeErrs > 0 {
		return false, fmt.Errorf("legacy-session watch: %d key(s) failed to decode", decodeErrs)
	}
	return false, nil
}

// StartLegacyWatch warns for as long as a mixed-version fleet is serving.
// The old code cannot be stopped from here; an operator being told loudly is
// the most this side can do.
func (m *Manager) StartLegacyWatch(ctx context.Context, logger *slog.Logger) {
	if m == nil || m.rdb == nil || logger == nil {
		return
	}
	since := time.Now().UTC()
	go func() {
		t := time.NewTicker(legacyWatchInterval)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				found, err := m.LegacyMintingDetected(ctx, since)
				if err != nil {
					logger.Warn("legacy-session watch failed; cannot confirm no old replica is serving", "err", err)
					continue
				}
				if found {
					logger.Error("mixed-version fleet: an old replica is still minting sessions in the pre-upgrade namespace; it ignores restricted-admin confinement and auth epochs - drain it now")
				}
			}
		}
	}()
}
