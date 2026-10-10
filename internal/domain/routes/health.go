// Node health probing and automatic failover.
package routes

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"sync"
	"time"

	"golang.org/x/sync/errgroup"

	"github.com/host-yt/caddy-proxy-manager/internal/store"
)

// HealthProbe sweeps every enabled node in parallel, GETs its /config/
// endpoint, and updates health_status + last_seen_at. Errors are logged,
// not returned. Bounded concurrency keeps slow nodes from delaying the
// rest. Designed to be called every ~30s from a background ticker.
const healthProbeWorkers = 8

func (s *Service) HealthProbe(ctx context.Context) {
	if s.DB == nil {
		return
	}
	rows, err := s.DB.QueryContext(ctx,
		"SELECT id, api_url FROM caddy_nodes WHERE is_enabled = 1")
	if err != nil {
		s.Logger.Warn("health: list nodes", "err", err)
		return
	}
	type nodeProbe struct {
		id     int64
		apiURL string
	}
	var probes []nodeProbe
	for rows.Next() {
		var p nodeProbe
		if err := rows.Scan(&p.id, &p.apiURL); err == nil {
			probes = append(probes, p)
		}
	}
	rows.Close()

	sem := make(chan struct{}, healthProbeWorkers)
	var wg sync.WaitGroup
	for _, p := range probes {
		p := p
		sem <- struct{}{}
		wg.Add(1)
		go func() {
			defer recoverBg(s.Logger, "healthProbe")
			defer wg.Done()
			defer func() { <-sem }()
			status := "down"
			client := s.NodeClient(ctx, p.id, p.apiURL)
			probeCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
			probeStart := time.Now()
			_, probeErr := client.GetRaw(probeCtx, "/config/")
			rttMs := int(time.Since(probeStart).Milliseconds())
			if probeErr == nil {
				status = "healthy"
			}
			cancel()
			_, _ = s.DB.ExecContext(ctx,
				"UPDATE caddy_nodes SET health_status = ?, last_seen_at = NOW() WHERE id = ?",
				status, p.id)
			// Only a successful probe reflects real RTT - a failed/timed-out
			// probe measures the timeout, not the network.
			if probeErr == nil {
				s.recordRTT(ctx, p.id, rttMs, probeStart)
			}

			// Auto-resync: node came back online (was down/unknown, now healthy).
			// Caddy may have lost its config on restart, so re-push from DB.
			if status == "healthy" && s.markHealthAndChanged(p.id, status) {
				go func(id int64) {
					defer recoverBg(s.Logger, "autoResync")
					pushCtx, c := context.WithTimeout(s.BackgroundCtx(), 30*time.Second)
					defer c()
					if err := s.pushNodeConfig(pushCtx, id); err != nil {
						s.Logger.Warn("auto-resync on recovery failed", "node_id", id, "err", err)
					} else {
						s.Logger.Info("auto-resync on recovery ok", "node_id", id)
					}
				}(p.id)
			} else {
				s.markHealth(p.id, status)
			}
		}()
	}
	wg.Wait()
	s.pruneRTTSamples(ctx)
}

// markHealthAndChanged records new status and returns true iff this is a
// recovery transition (previous status was "down" or absent and new is healthy).
// First-observation healthy returns false (handled by boot-time PushAll).
func (s *Service) markHealthAndChanged(id int64, status string) bool {
	s.healthMu.Lock()
	defer s.healthMu.Unlock()
	if s.lastHealth == nil {
		s.lastHealth = map[int64]string{}
	}
	prev, seen := s.lastHealth[id]
	s.lastHealth[id] = status
	return seen && prev == "down" && status == "healthy"
}

func (s *Service) markHealth(id int64, status string) {
	s.healthMu.Lock()
	defer s.healthMu.Unlock()
	if s.lastHealth == nil {
		s.lastHealth = map[int64]string{}
	}
	s.lastHealth[id] = status
}

// AutoFailover migrates routes off Caddy nodes that have been "down"
// for more than the grace window onto the lowest-loaded healthy peer
// in the same node_group. Routes bound to a WG tunnel (via_wg_peer_id)
// are SKIPPED - their wg-tun0 only exists on the failed node, so
// moving them silently would yield 502s with no clear cause. Those
// routes need explicit operator intervention (HA tunnel mode or
// re-issue tunnel on a new node).
//
// Called by a leader-only ticker on a 2-min cadence; designed to be
// idempotent (no-op when no node is down or no peer has capacity).
const failoverGraceMinutes = 5

func (s *Service) AutoFailover(ctx context.Context) {
	if s.DB == nil {
		return
	}
	rows, err := s.DB.QueryContext(ctx,
		`SELECT r.id, r.domain, r.caddy_node_id, n.node_group_id, r.via_wg_peer_id, sv.client_id
		 FROM routes r
		 JOIN caddy_nodes n ON n.id = r.caddy_node_id
		 JOIN services sv ON sv.id = r.service_id
		 WHERE n.is_enabled = 1
		   AND n.health_status = 'down'
		   AND n.last_seen_at < `+store.DateSubParam("MINUTE")+`
		   AND r.status IN ('active','dns_ok','pending_ssl')
		 ORDER BY r.id ASC LIMIT 500`, failoverGraceMinutes)
	if err != nil {
		s.Logger.Warn("autofailover: list candidates", "err", err)
		return
	}
	type candidate struct {
		id         int64
		domain     string
		fromNodeID int64
		groupID    int64
		viaPeerID  sql.NullInt64
		clientID   int64
	}
	var cands []candidate
	for rows.Next() {
		var c candidate
		if err := rows.Scan(&c.id, &c.domain, &c.fromNodeID, &c.groupID, &c.viaPeerID, &c.clientID); err == nil {
			cands = append(cands, c)
		}
	}
	rows.Close()
	if len(cands) == 0 {
		return
	}

	movedByDest := map[int64]int{}
	for _, c := range cands {
		select {
		case <-ctx.Done():
			return
		default:
		}
		if c.viaPeerID.Valid {
			// Tunneled routes can't follow - their wg-tun0 is on the
			// dead node. Surface via webhook so the operator can act.
			s.Logger.Warn("autofailover: route bound to tunnel, skipping",
				"route_id", c.id, "domain", c.domain, "from_node", c.fromNodeID)
			if s.Webhooks != nil {
				s.Webhooks.Emit(ctx, "route.failover.skipped", map[string]any{
					"route_id": c.id, "domain": c.domain, "node_id": c.fromNodeID,
					"reason": "bound to WG tunnel which lives on the failed node",
				})
			}
			if s.Notifier != nil {
				s.Notifier.Notify(ctx, c.clientID,
					"[Hostyt] "+c.domain+" cannot auto-failover",
					"Your route "+c.domain+" lives on a node that went down, and is bound to a WG tunnel "+
						"only available on that node. Manual action required: either re-create the tunnel on "+
						"a different node, or enable HA tunnel mode. The site will stay offline until then.")
			}
			continue
		}

		dest, err := s.failoverRoute(ctx, c.id, c.fromNodeID, c.groupID)
		if err != nil {
			s.Logger.Warn("autofailover: route not moved", "route_id", c.id, "group_id", c.groupID, "err", err)
			continue
		}
		movedByDest[dest]++
		s.Logger.Info("autofailover moved route", "route_id", c.id, "domain", c.domain,
			"from_node", c.fromNodeID, "to_node", dest)
		if s.Webhooks != nil {
			s.Webhooks.Emit(ctx, "route.failover", map[string]any{
				"route_id": c.id, "domain": c.domain,
				"from_node": c.fromNodeID, "to_node": dest,
			})
		}
		if s.Notifier != nil {
			s.Notifier.Notify(ctx, c.clientID,
				"[Hostyt] "+c.domain+" moved to a backup node",
				"The Caddy node serving your route "+c.domain+" went down. We automatically "+
					"moved your route to a healthy peer in the same group. Your site should be "+
					"reachable again within a minute. No action required.")
		}
	}

	// One push per destination node, not per route - saves N-1 /load calls.
	// Only nodes with committed moves are pushed; counters were settled in
	// each move's transaction. Bounded concurrency so a slow dest node
	// doesn't stall the others.
	gf, gfctx := errgroup.WithContext(ctx)
	gf.SetLimit(reconcileWorkers)
	for destID := range movedByDest {
		destID := destID
		gf.Go(func() error {
			if err := s.pushNodeConfig(gfctx, destID); err != nil {
				s.Logger.Warn("autofailover: push to new home failed", "node_id", destID, "err", err)
			}
			return nil
		})
	}
	_ = gf.Wait()
}

var errNoFailoverPeer = errors.New("no healthy peer with capacity in group")

// failoverRoute moves one route off fromNode in a single transaction and
// returns its new node. The destination slot is claimed with a conditional
// UPDATE per route: picking a node once and pouring every route onto it is how
// a peer with one free slot used to receive hundreds. The source counter only
// drops once the route row actually moved, so a failed move leaves both
// counters as they were.
func (s *Service) failoverRoute(ctx context.Context, routeID, fromNode, groupID int64) (int64, error) {
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return 0, err
	}
	defer tx.Rollback() //nolint:errcheck

	// A fan-out route may already have a copy on a healthy peer (the warm
	// standby); that node holds its slot already, so it takes over without a
	// new claim.
	var dest int64
	claimed := false
	err = tx.QueryRowContext(ctx,
		`SELECT a.node_id FROM route_node_assignments a
		   JOIN caddy_nodes n ON n.id = a.node_id
		  WHERE a.route_id = ? AND a.node_id <> ?
		    AND n.is_enabled = 1 AND n.approved_at IS NOT NULL AND n.health_status = 'healthy'
		  ORDER BY n.priority DESC, n.id ASC LIMIT 1`, routeID, fromNode).Scan(&dest)
	switch {
	case errors.Is(err, sql.ErrNoRows):
		var ok bool
		if dest, ok = claimNodeWithCapacity(ctx, tx, groupID, fromNode, true); !ok {
			return 0, errNoFailoverPeer
		}
		claimed = true
	case err != nil:
		return 0, fmt.Errorf("standby lookup: %w", err)
	}

	// Conditional on the old node: a concurrent edit or drain that already
	// moved the route must not be overwritten (rollback releases the claim).
	res, err := tx.ExecContext(ctx,
		`UPDATE routes SET caddy_node_id = ?, updated_at = NOW() WHERE id = ? AND caddy_node_id = ?`,
		dest, routeID, fromNode)
	if err != nil {
		return 0, fmt.Errorf("route update: %w", err)
	}
	if n, _ := res.RowsAffected(); n != 1 {
		return 0, errors.New("route already moved")
	}
	// Keep fan-out assignments in step: the dead node's copy goes, the new
	// home gets one (a no-op for single-mode routes, which have no rows).
	del, err := tx.ExecContext(ctx,
		`DELETE FROM route_node_assignments WHERE route_id = ? AND node_id = ?`, routeID, fromNode)
	if err != nil {
		return 0, fmt.Errorf("drop assignment: %w", err)
	}
	if n, _ := del.RowsAffected(); n == 1 && claimed {
		if _, err := tx.ExecContext(ctx,
			store.InsertOrIgnore()+" INTO route_node_assignments (route_id, node_id) VALUES (?, ?)",
			routeID, dest); err != nil {
			return 0, fmt.Errorf("add assignment: %w", err)
		}
	}
	if _, err := tx.ExecContext(ctx,
		`UPDATE caddy_nodes SET current_routes = GREATEST(0, current_routes - 1) WHERE id = ?`, fromNode); err != nil {
		return 0, fmt.Errorf("source counter: %w", err)
	}
	if err := s.markPushPending(ctx, tx, dest); err != nil {
		return 0, fmt.Errorf("push marker: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return 0, err
	}
	return dest, nil
}
