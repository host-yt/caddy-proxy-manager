package routes

import (
	"context"
	"database/sql"
	"fmt"
)

// nodePlacement returns the set of node IDs a route should be deployed to,
// given the service's node_group.mode:
//
//	single        → the lowest-usage enabled+approved node in the group.
//	active_active → every enabled+approved node in the group with capacity.
//	failover      → primary (highest priority enabled+approved+healthy);
//	                warm-secondary (next-highest) tracked for future
//	                promotion. We deploy to both so the cert exists when
//	                we need it (caddy-tlsredis shares cert storage).
//
// Capacity check uses current_routes < max_routes per node.
func nodePlacement(ctx context.Context, db *sql.DB, groupID int64) (primary int64, all []int64, mode string, err error) {
	if err := db.QueryRowContext(ctx,
		"SELECT mode FROM node_groups WHERE id = ?", groupID,
	).Scan(&mode); err != nil {
		return 0, nil, "", err
	}

	switch mode {
	case "active_active":
		var rows *sql.Rows
		rows, err = db.QueryContext(ctx,
			`SELECT id FROM caddy_nodes
			 WHERE node_group_id = ? AND is_enabled = 1 AND approved_at IS NOT NULL
			   AND current_routes < max_routes
			 ORDER BY id ASC`, groupID)
		if err != nil {
			return 0, nil, mode, err
		}
		defer rows.Close()
		for rows.Next() {
			var id int64
			if scanErr := rows.Scan(&id); scanErr == nil {
				all = append(all, id)
			}
		}
		if len(all) == 0 {
			return 0, nil, mode, fmt.Errorf("active_active: no nodes with capacity")
		}
		primary = all[0]
		return

	case "failover":
		var rows *sql.Rows
		rows, err = db.QueryContext(ctx,
			`SELECT id FROM caddy_nodes
			 WHERE node_group_id = ? AND is_enabled = 1 AND approved_at IS NOT NULL
			   AND current_routes < max_routes
			 ORDER BY priority DESC, (current_routes / GREATEST(max_routes,1)) ASC, id ASC
			 LIMIT 2`, groupID)
		if err != nil {
			return 0, nil, mode, err
		}
		defer rows.Close()
		for rows.Next() {
			var id int64
			if scanErr := rows.Scan(&id); scanErr == nil {
				all = append(all, id)
			}
		}
		if len(all) == 0 {
			return 0, nil, mode, fmt.Errorf("failover: no nodes with capacity")
		}
		primary = all[0]
		return

	default: // single
		err = db.QueryRowContext(ctx,
			`SELECT id FROM caddy_nodes
			 WHERE node_group_id = ? AND is_enabled = 1 AND approved_at IS NOT NULL
			   AND current_routes < max_routes
			 ORDER BY (current_routes / GREATEST(max_routes,1)) ASC, priority DESC, id ASC
			 LIMIT 1`, groupID).Scan(&primary)
		if err != nil {
			return 0, nil, mode, err
		}
		return primary, []int64{primary}, mode, nil
	}
}

// claimNodeWithCapacity atomically takes one route slot on some enabled,
// approved node in groupID other than skipID, and returns that node.
//
// The conditional UPDATE is the claim: reading current_routes < max_routes and
// then incrementing in two steps lets concurrent creates hand out the same last
// slot, which is how a node ends up above its max_routes. Candidates are read
// first only to get the preference order; a candidate that lost its slot in the
// meantime simply fails its claim and the next one is tried.
func claimNodeWithCapacity(ctx context.Context, tx *sql.Tx, groupID, skipID int64) (int64, bool) {
	rows, err := tx.QueryContext(ctx,
		`SELECT id FROM caddy_nodes
		  WHERE node_group_id = ? AND id <> ? AND is_enabled = 1 AND approved_at IS NOT NULL
		    AND current_routes < max_routes
		  ORDER BY (current_routes / GREATEST(max_routes,1)) ASC, priority DESC, id ASC
		  LIMIT 8`, groupID, skipID)
	if err != nil {
		return 0, false
	}
	var candidates []int64
	for rows.Next() {
		var id int64
		if rows.Scan(&id) == nil {
			candidates = append(candidates, id)
		}
	}
	rows.Close()
	for _, id := range candidates {
		res, err := tx.ExecContext(ctx,
			"UPDATE caddy_nodes SET current_routes = current_routes + 1 WHERE id = ? AND current_routes < max_routes",
			id)
		if err != nil {
			return 0, false
		}
		if n, _ := res.RowsAffected(); n == 1 {
			return id, true
		}
	}
	return 0, false
}
