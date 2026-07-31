package auth

import (
	"context"
	"encoding/json"
	"log/slog"
	"time"
)

// legacyWatchInterval is how often we look for an old replica still minting.
const legacyWatchInterval = 2 * time.Minute

// LegacyMintingDetected reports whether a session appeared in the pre-version
// namespace AFTER `since`. Only a running old replica can create one, and that
// replica ignores Restricted/Epoch entirely - it will happily serve a confined
// admin as a platform admin. Leftover keys from before the upgrade are older
// than `since` and do not trigger.
func (m *Manager) LegacyMintingDetected(ctx context.Context, since time.Time) bool {
	if m == nil || m.rdb == nil {
		return false
	}
	var cursor uint64
	for {
		keys, next, err := m.rdb.Scan(ctx, cursor, legacySessionKeyPrefix+"*", 200).Result()
		if err != nil {
			return false
		}
		for _, k := range keys {
			b, gerr := m.rdb.Get(ctx, k).Bytes()
			if gerr != nil {
				continue
			}
			var s Session
			if json.Unmarshal(b, &s) != nil {
				continue
			}
			if s.CreatedAt.After(since) {
				return true
			}
		}
		cursor = next
		if cursor == 0 {
			return false
		}
	}
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
				if m.LegacyMintingDetected(ctx, since) {
					logger.Error("mixed-version fleet: an old replica is still minting sessions in the pre-upgrade namespace; it ignores restricted-admin confinement and auth epochs - drain it now")
				}
			}
		}
	}()
}
