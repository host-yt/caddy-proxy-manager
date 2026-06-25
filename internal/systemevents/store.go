// Package systemevents records infrastructure events (node up/down, cert renewal, etc.)
// into the system_events table. Emit is always soft-fail: errors are logged, never returned.
package systemevents

import (
	"context"
	"database/sql"
	"encoding/json"
	"log/slog"
)

// Store persists system events.
type Store struct {
	DB     *sql.DB
	Logger *slog.Logger
}

// Emit inserts one event record. nodeID and routeID may be nil.
// Always returns nil so callers are never disrupted by event failures.
func (s *Store) Emit(ctx context.Context, nodeID, routeID *int64, eventType, severity, message string, meta map[string]any) error {
	if s.DB == nil {
		return nil
	}

	var nid sql.NullInt64
	if nodeID != nil {
		nid = sql.NullInt64{Int64: *nodeID, Valid: true}
	}

	var rid sql.NullInt64
	if routeID != nil {
		rid = sql.NullInt64{Int64: *routeID, Valid: true}
	}

	var metaJSON []byte
	if meta != nil {
		b, err := json.Marshal(meta)
		if err != nil {
			s.Logger.ErrorContext(ctx, "systemevents: marshal meta", "err", err)
			return nil
		}
		metaJSON = b
	}

	_, err := s.DB.ExecContext(ctx,
		`INSERT INTO system_events (node_id, route_id, event_type, severity, message, meta)
		 VALUES (?, ?, ?, ?, ?, ?)`,
		nid, rid, eventType, severity, message, metaJSON,
	)
	if err != nil {
		s.Logger.ErrorContext(ctx, "systemevents: insert", "err", err)
	}
	return nil
}
