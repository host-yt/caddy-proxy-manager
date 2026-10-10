package handlers

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
)

// nodeAlloc is one destination's share of a node migration.
type nodeAlloc struct {
	dest     int64
	routeIDs []int64
}

// migrateNodeRoutes moves a node's routes onto same-group peers, spreading
// them by free capacity, and pushes every destination. Any reservation or
// push failure puts the routes back on the source, which was never touched.
// drain=true picks only healthy peers and leaves WG-tunneled routes behind.
func (h *AdminHandlers) migrateNodeRoutes(ctx context.Context, db *sql.DB, src, group int64, drain bool) (int, []int64, error) {
	q := "SELECT id FROM routes WHERE caddy_node_id = ?"
	if drain {
		q += " AND via_wg_peer_id IS NULL"
	}
	ids, err := queryInt64s(ctx, db, q+" ORDER BY id", src)
	if err != nil {
		return 0, nil, fmt.Errorf("list routes: %w", err)
	}
	if len(ids) == 0 {
		return 0, nil, nil
	}

	cq := `SELECT id, max_routes - current_routes FROM caddy_nodes
		 WHERE node_group_id = ? AND id <> ? AND is_enabled = 1 AND approved_at IS NOT NULL
		   AND current_routes < max_routes`
	if drain {
		cq += " AND health_status = 'healthy'"
	}
	rows, err := db.QueryContext(ctx, cq+" ORDER BY (current_routes / GREATEST(max_routes,1)) ASC, priority DESC, id ASC", group, src)
	if err != nil {
		return 0, nil, fmt.Errorf("list peers: %w", err)
	}
	var allocs []nodeAlloc
	rest := ids
	for rows.Next() && len(rest) > 0 {
		var dest int64
		var free int
		if err := rows.Scan(&dest, &free); err != nil {
			rows.Close()
			return 0, nil, err
		}
		n := min(free, len(rest))
		allocs = append(allocs, nodeAlloc{dest: dest, routeIDs: rest[:n]})
		rest = rest[n:]
	}
	rows.Close()
	if len(rest) > 0 {
		return 0, nil, fmt.Errorf("peers in the same group have room for %d of %d route(s) - add capacity first",
			len(ids)-len(rest), len(ids))
	}

	if err := applyNodeAllocs(ctx, db, src, allocs, false); err != nil {
		return 0, nil, err
	}
	dests := make([]int64, 0, len(allocs))
	for _, a := range allocs {
		dests = append(dests, a.dest)
	}
	if h.ResyncNode == nil {
		return len(ids), dests, nil
	}
	for i, d := range dests {
		if perr := h.ResyncNode(ctx, d); perr != nil {
			if rerr := applyNodeAllocs(ctx, db, src, allocs, true); rerr != nil {
				return 0, nil, fmt.Errorf("push to node %d failed (%v) and rollback failed: %w", d, perr, rerr)
			}
			// Destinations already pushed still carry the moved routes; re-push them.
			for _, done := range dests[:i] {
				_ = h.ResyncNode(ctx, done)
			}
			return 0, nil, fmt.Errorf("push to node %d failed, migration rolled back: %w", d, perr)
		}
	}
	return len(ids), dests, nil
}

// applyNodeAllocs moves (or with revert, returns) routes and their counters
// in one transaction. The capacity guard makes each reservation atomic.
func applyNodeAllocs(ctx context.Context, db *sql.DB, src int64, allocs []nodeAlloc, revert bool) error {
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback() //nolint:errcheck
	total := 0
	for _, a := range allocs {
		n := len(a.routeIDs)
		total += n
		from, to := src, a.dest
		counter, cargs := "UPDATE caddy_nodes SET current_routes = current_routes + ? WHERE id = ? AND current_routes + ? <= max_routes", []any{n, a.dest, n}
		if revert {
			from, to = a.dest, src
			counter, cargs = "UPDATE caddy_nodes SET current_routes = GREATEST(0, current_routes - ?) WHERE id = ?", []any{n, a.dest}
		}
		res, err := tx.ExecContext(ctx, counter, cargs...)
		if err != nil {
			return err
		}
		if c, _ := res.RowsAffected(); c != 1 && !revert {
			return fmt.Errorf("node %d ran out of capacity, retry", a.dest)
		}
		args := []any{to, from}
		for _, id := range a.routeIDs {
			args = append(args, id)
		}
		res, err = tx.ExecContext(ctx, "UPDATE routes SET caddy_node_id = ? WHERE caddy_node_id = ? AND id IN (?"+
			strings.Repeat(",?", n-1)+")", args...)
		if err != nil {
			return err
		}
		if c, _ := res.RowsAffected(); c != int64(n) && !revert {
			return errors.New("routes changed during migration, retry")
		}
	}
	srcSQL := "UPDATE caddy_nodes SET current_routes = GREATEST(0, current_routes - ?) WHERE id = ?"
	if revert {
		srcSQL = "UPDATE caddy_nodes SET current_routes = current_routes + ? WHERE id = ?"
	}
	if _, err := tx.ExecContext(ctx, srcSQL, total, src); err != nil {
		return err
	}
	return tx.Commit()
}

func queryInt64s(ctx context.Context, db *sql.DB, q string, args ...any) ([]int64, error) {
	rows, err := db.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []int64
	for rows.Next() {
		var v int64
		if err := rows.Scan(&v); err != nil {
			return nil, err
		}
		out = append(out, v)
	}
	return out, rows.Err()
}
