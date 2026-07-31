package auth

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"log/slog"
	"strconv"
	"strings"
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
)

// StartGenerationHeartbeat announces this replica's generation in shared
// state (TTL key, self-expiring on crash) so Ready() can refuse traffic while
// an incompatible peer is still in the fleet - the fence future rolling
// upgrades need but this release's old binary predates.
func (m *Manager) StartGenerationHeartbeat(ctx context.Context, logger *slog.Logger) {
	if m == nil || m.rdb == nil {
		return
	}
	idBytes := make([]byte, 8)
	_, _ = rand.Read(idBytes)
	key := fmt.Sprintf("%s%d:%s", fleetKeyPrefix, ClusterGeneration, hex.EncodeToString(idBytes))
	beat := func() {
		if err := m.rdb.Set(ctx, key, "1", fleetHeartbeatTTL).Err(); err != nil && logger != nil {
			logger.Warn("fleet generation heartbeat failed", "err", err)
		}
	}
	beat()
	go func() {
		t := time.NewTicker(fleetHeartbeatEvery)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				beat()
			}
		}
	}()
}

// IncompatibleGenerationPresent scans fleet heartbeats for a replica running
// a generation other than ours. A scan failure is returned as an error, not
// folded into "false" - an unreadable fleet state must not read as "clear".
func (m *Manager) IncompatibleGenerationPresent(ctx context.Context) (bool, error) {
	if m == nil || m.rdb == nil {
		return false, nil
	}
	var cursor uint64
	for {
		keys, next, err := m.rdb.Scan(ctx, cursor, fleetKeyPrefix+"*", 200).Result()
		if err != nil {
			return false, err
		}
		for _, k := range keys {
			rest := strings.TrimPrefix(k, fleetKeyPrefix)
			genStr, _, ok := strings.Cut(rest, ":")
			if !ok {
				continue
			}
			gen, err := strconv.Atoi(genStr)
			if err != nil {
				continue
			}
			if gen != ClusterGeneration {
				return true, nil
			}
		}
		cursor = next
		if cursor == 0 {
			return false, nil
		}
	}
}
