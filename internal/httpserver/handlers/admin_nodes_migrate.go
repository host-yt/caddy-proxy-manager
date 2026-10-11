package handlers

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/host-yt/caddy-proxy-manager/internal/store"
)

// nodeMove is one route membership leaving the source for dest.
type nodeMove struct {
	route, dest int64
	anchor      bool // source is the route's caddy_node_id
	srcRow      bool // source has a route_node_assignments row to carry over
	shared      bool // dest already serves the route: no new slot, source row dropped
}

// migrateNodeRoutes moves a node's route memberships (anchor and fan-out
// assignments) onto same-group peers that do not already serve the route,
// spreading them by free capacity, and pushes every destination. Any
// reservation or push failure puts everything back on the source.
// drain=true picks only healthy peers, leaves WG-tunneled routes behind and
// re-syncs the source so it stops serving what moved.
func (h *AdminHandlers) migrateNodeRoutes(ctx context.Context, db *sql.DB, src, group int64, drain bool) (int, []int64, error) {
	where := ` WHERE (r.caddy_node_id = ? OR EXISTS (SELECT 1 FROM route_node_assignments s
		        WHERE s.route_id = r.id AND s.node_id = ?))`
	if drain {
		where += " AND r.via_wg_peer_id IS NULL"
	}
	type routeRow struct{ id, anchor int64 }
	var rts []routeRow
	members := map[int64]map[int64]bool{} // route -> assigned nodes
	rows, err := db.QueryContext(ctx, "SELECT r.id, COALESCE(r.caddy_node_id, 0) FROM routes r"+where+" ORDER BY r.id", src, src)
	if err != nil {
		return 0, nil, fmt.Errorf("list routes: %w", err)
	}
	for rows.Next() {
		var r routeRow
		if err := rows.Scan(&r.id, &r.anchor); err != nil {
			rows.Close()
			return 0, nil, err
		}
		rts = append(rts, r)
		members[r.id] = map[int64]bool{}
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return 0, nil, fmt.Errorf("list routes: %w", err)
	}
	if len(rts) == 0 {
		return 0, nil, nil
	}
	rows, err = db.QueryContext(ctx,
		"SELECT a.route_id, a.node_id FROM route_node_assignments a JOIN routes r ON r.id = a.route_id"+where, src, src)
	if err != nil {
		return 0, nil, fmt.Errorf("list assignments: %w", err)
	}
	for rows.Next() {
		var rid, nid int64
		if err := rows.Scan(&rid, &nid); err != nil {
			rows.Close()
			return 0, nil, err
		}
		if m := members[rid]; m != nil {
			m[nid] = true
		}
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return 0, nil, fmt.Errorf("list assignments: %w", err)
	}

	// Full peers stay listed: an anchor may fall back to a peer already serving the route.
	cq := `SELECT id, max_routes - current_routes FROM caddy_nodes
		 WHERE node_group_id = ? AND id <> ? AND is_enabled = 1 AND approved_at IS NOT NULL`
	if drain {
		cq += " AND health_status = 'healthy'"
	}
	rows, err = db.QueryContext(ctx, cq+" ORDER BY (current_routes / GREATEST(max_routes,1)) ASC, priority DESC, id ASC", group, src)
	if err != nil {
		return 0, nil, fmt.Errorf("list peers: %w", err)
	}
	type peer struct {
		id   int64
		free int
	}
	var peers []*peer
	for rows.Next() {
		p := &peer{}
		if err := rows.Scan(&p.id, &p.free); err != nil {
			rows.Close()
			return 0, nil, err
		}
		peers = append(peers, p)
	}
	rows.Close()

	var moves []nodeMove
	var dests []int64
	seen := map[int64]bool{}
	for _, r := range rts {
		m := nodeMove{route: r.id, anchor: r.anchor == src, srcRow: members[r.id][src]}
		for _, p := range peers {
			if p.free > 0 && p.id != r.anchor && !members[r.id][p.id] {
				m.dest = p.id
				p.free--
				break
			}
		}
		// No free slot: hand off to a peer that already serves the route. A
		// replica-only source then just drops its assignment (no capacity needed).
		if m.dest == 0 {
			for _, p := range peers {
				if members[r.id][p.id] || (!m.anchor && p.id == r.anchor) {
					m.dest, m.shared = p.id, true
					break
				}
			}
		}
		if m.dest == 0 {
			continue
		}
		moves = append(moves, m)
		if !seen[m.dest] {
			seen[m.dest] = true
			dests = append(dests, m.dest)
		}
	}
	if len(moves) < len(rts) {
		return 0, nil, fmt.Errorf("peers in the same group have room for %d of %d route(s) - add capacity first",
			len(moves), len(rts))
	}

	if err := applyNodeMoves(ctx, db, src, moves, false); err != nil {
		return 0, nil, err
	}
	if h.ResyncNode == nil {
		return len(moves), dests, nil
	}
	targets := dests
	if drain {
		// Decommission clears the source itself, with a force path for dead nodes.
		targets = append(append([]int64(nil), dests...), src)
	}
	for i, d := range targets {
		if perr := h.ResyncNode(ctx, d); perr != nil {
			if rerr := applyNodeMoves(ctx, db, src, moves, true); rerr != nil {
				return 0, nil, fmt.Errorf("push to node %d failed (%v) and rollback failed: %w", d, perr, rerr)
			}
			// Re-push every attempted node, d included: its /load may have
			// applied even though the call errored (e.g. response timeout).
			cctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 2*time.Minute)
			var cerrs []error
			for _, done := range targets[:i+1] {
				if err := h.ResyncNode(cctx, done); err != nil {
					cerrs = append(cerrs, fmt.Errorf("node %d: %w", done, err))
				}
			}
			cancel()
			if len(cerrs) > 0 {
				return 0, nil, fmt.Errorf("push to node %d failed (%v), migration rolled back, but re-sync failed (drift reconcile will retry): %w",
					d, perr, errors.Join(cerrs...))
			}
			return 0, nil, fmt.Errorf("push to node %d failed, migration rolled back: %w", d, perr)
		}
	}
	return len(moves), dests, nil
}

// applyNodeMoves moves (or with revert, returns) route memberships and their
// counters in one transaction. The capacity guard makes each reservation atomic.
func applyNodeMoves(ctx context.Context, db *sql.DB, src int64, moves []nodeMove, revert bool) error {
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback() //nolint:errcheck
	// Forward moves must hit exactly one row; revert is best-effort.
	exec := func(msg, q string, args ...any) error {
		res, err := tx.ExecContext(ctx, q, args...)
		if err != nil {
			return err
		}
		if c, _ := res.RowsAffected(); c != 1 && !revert {
			return errors.New(msg)
		}
		return nil
	}
	const changed = "routes changed during migration, retry"
	for _, m := range moves {
		from, to := src, m.dest
		if revert {
			from, to = m.dest, src
		}
		if !m.shared {
			q := "UPDATE caddy_nodes SET current_routes = current_routes + 1 WHERE id = ? AND current_routes + 1 <= max_routes"
			if revert {
				q = "UPDATE caddy_nodes SET current_routes = GREATEST(0, current_routes - 1) WHERE id = ?"
			}
			if err := exec(fmt.Sprintf("node %d ran out of capacity, retry", m.dest), q, m.dest); err != nil {
				return err
			}
		}
		if m.anchor {
			if err := exec(changed, "UPDATE routes SET caddy_node_id = ? WHERE id = ? AND caddy_node_id = ?", to, m.route, from); err != nil {
				return err
			}
		}
		if !m.srcRow {
			continue
		}
		q, args := "UPDATE route_node_assignments SET node_id = ? WHERE route_id = ? AND node_id = ?", []any{to, m.route, from}
		switch {
		case m.shared && revert:
			q, args = store.InsertOrIgnore()+" INTO route_node_assignments (route_id, node_id) VALUES (?, ?)", []any{m.route, src}
		case m.shared:
			q, args = "DELETE FROM route_node_assignments WHERE route_id = ? AND node_id = ?", []any{m.route, src}
		}
		if err := exec(changed, q, args...); err != nil {
			return err
		}
	}
	srcSQL := "UPDATE caddy_nodes SET current_routes = GREATEST(0, current_routes - ?) WHERE id = ?"
	if revert {
		srcSQL = "UPDATE caddy_nodes SET current_routes = current_routes + ? WHERE id = ?"
	}
	if _, err := tx.ExecContext(ctx, srcSQL, len(moves), src); err != nil {
		return err
	}
	return tx.Commit()
}
