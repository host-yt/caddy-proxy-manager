package alert

import (
	"context"
	"database/sql"
	"fmt"

	"github.com/host-yt/caddy-proxy-manager/internal/audit"
)

// tryAutoFailover moves active routes from a dead node to a healthy failover
// sibling, then resyncs the sibling. No-op when feature is disabled or wiring
// is missing.
func (e *Evaluator) tryAutoFailover(ctx context.Context, db *sql.DB, nodeID int64) {
	if !e.Cfg.AutoFailoverEnabled {
		return
	}
	if e.RouteSvc == nil {
		return
	}

	// Find a healthy enabled sibling in the same failover node_group.
	var siblingID int64
	err := db.QueryRowContext(ctx, `
		SELECT n2.id
		  FROM caddy_nodes n1
		  JOIN caddy_nodes n2
		    ON n2.node_group_id = n1.node_group_id AND n2.id <> n1.id
		  JOIN node_groups ng ON ng.id = n1.node_group_id
		 WHERE n1.id = ?
		   AND n2.health_status = 'healthy'
		   AND n2.is_enabled = 1
		   AND ng.mode = 'failover'
		 LIMIT 1`, nodeID).Scan(&siblingID)
	if err == sql.ErrNoRows {
		if e.Logger != nil {
			e.Logger.Warn("auto_failover: no healthy sibling", "node_id", nodeID)
		}
		return
	}
	if err != nil {
		if e.Logger != nil {
			e.Logger.Warn("auto_failover: sibling query failed", "node_id", nodeID, "err", err)
		}
		return
	}

	// Collect active routes on the dead node.
	rows, err := db.QueryContext(ctx,
		`SELECT id FROM routes WHERE caddy_node_id = ? AND status = 'active'`, nodeID)
	if err != nil {
		if e.Logger != nil {
			e.Logger.Warn("auto_failover: route query failed", "node_id", nodeID, "err", err)
		}
		return
	}
	defer rows.Close()

	var routeIDs []int64
	for rows.Next() {
		var id int64
		if err := rows.Scan(&id); err == nil {
			routeIDs = append(routeIDs, id)
		}
	}
	_ = rows.Close()

	if len(routeIDs) == 0 {
		return
	}

	// Move each route and write an audit trail.
	for _, rid := range routeIDs {
		if _, err := db.ExecContext(ctx,
			`UPDATE routes SET caddy_node_id = ? WHERE id = ?`, siblingID, rid); err != nil {
			if e.Logger != nil {
				e.Logger.Warn("auto_failover: route update failed", "route_id", rid, "err", err)
			}
			continue
		}
		audit.Write(ctx, db, e.Logger, nil, audit.Entry{
			ActorType: audit.ActorSystem,
			Action:    "node.failover.route_moved",
			Entity:    "route",
			EntityID:  fmt.Sprintf("%d", rid),
			Meta: map[string]any{
				"from_node": nodeID,
				"to_node":   siblingID,
			},
		})
	}

	// Rebuild Caddy config on the sibling to pick up the new routes.
	if err := e.RouteSvc.Resync(ctx, siblingID); err != nil && e.Logger != nil {
		e.Logger.Warn("auto_failover: resync failed", "sibling_id", siblingID, "err", err)
	}
}
