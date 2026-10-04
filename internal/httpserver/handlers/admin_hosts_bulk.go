package handlers

import (
	"context"
	"database/sql"
	"errors"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/host-yt/caddy-proxy-manager/internal/audit"
	"github.com/host-yt/caddy-proxy-manager/internal/auth"
	"github.com/host-yt/caddy-proxy-manager/internal/httpserver/middleware"
)

// HostsBulk applies one action (enable / disable / delete) to many
// routes at once. Failures are aggregated into the flash so the
// operator sees a partial-success summary instead of bailing on the
// first error.
func (h *AdminHandlers) HostsBulk(w http.ResponseWriter, r *http.Request) {
	if h.Routes == nil || h.DB() == nil {
		http.Error(w, "not ready", http.StatusServiceUnavailable)
		return
	}
	sess := middleware.SessionFromContext(r.Context())
	_ = r.ParseForm()
	action := r.FormValue("action")
	ids := r.Form["ids"]
	destNodeID, _ := strconv.ParseInt(strings.TrimSpace(r.FormValue("node_id")), 10, 64)
	if action == "" || len(ids) == 0 {
		redirectWithFlash(w, r, "/admin/hosts", "", "select rows and an action")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()

	ok, fail := 0, 0
	touchedNodes := map[int64]struct{}{}
	for _, s := range ids {
		id, err := strconv.ParseInt(s, 10, 64)
		if err != nil || id == 0 {
			fail++
			continue
		}
		// IDOR guard: a scoped admin may only bulk-act on its own tenants' routes.
		if !h.scopeCheckRoute(ctx, sess, id) {
			fail++
			continue
		}
		var nodeID int64
		_ = h.DB().QueryRowContext(ctx,
			"SELECT caddy_node_id FROM routes WHERE id = ?", id).Scan(&nodeID)
		switch action {
		case "delete":
			if derr := h.Routes.Delete(ctx, 0, id); derr != nil {
				fail++
				continue
			}
		case "disable":
			if _, derr := h.DB().ExecContext(ctx,
				"UPDATE routes SET status='disabled', updated_at=NOW() WHERE id=?", id); derr != nil {
				fail++
				continue
			}
			touchedNodes[nodeID] = struct{}{}
		case "enable":
			if werr := h.revalidateStoredWAF(ctx, sess, id); werr != nil {
				h.Logger.Warn("admin host bulk: enable rejected", "route_id", id, "err", werr)
				fail++
				continue
			}
			if _, derr := h.DB().ExecContext(ctx,
				"UPDATE routes SET status='pending_dns', last_error=NULL, updated_at=NOW() WHERE id=?", id); derr != nil {
				fail++
				continue
			}
			touchedNodes[nodeID] = struct{}{}
		case "set_tag":
			tag := strings.TrimSpace(r.FormValue("tag"))
			if len(tag) > 64 {
				tag = tag[:64]
			}
			if tag == "" {
				fail++
				continue
			}
			if _, derr := h.DB().ExecContext(ctx,
				"UPDATE routes SET tag=?, updated_at=NOW() WHERE id=?", tag, id); derr != nil {
				fail++
				continue
			}
		case "clear_tag":
			if _, derr := h.DB().ExecContext(ctx,
				"UPDATE routes SET tag=NULL, updated_at=NOW() WHERE id=?", id); derr != nil {
				fail++
				continue
			}
		case "move_node":
			if destNodeID <= 0 {
				fail++
				continue
			}
			oldNodeID, merr := h.moveRouteToNode(ctx, sess, id, destNodeID)
			if merr != nil {
				h.Logger.Warn("admin host bulk: move rejected", "route_id", id, "node_id", destNodeID, "err", merr)
				fail++
				continue
			}
			touchedNodes[oldNodeID] = struct{}{}
			touchedNodes[destNodeID] = struct{}{}
		case "maintenance_on":
			if _, derr := h.DB().ExecContext(ctx,
				"UPDATE routes SET maintenance_mode=1, updated_at=NOW() WHERE id=?", id); derr != nil {
				fail++
				continue
			}
			touchedNodes[nodeID] = struct{}{}
		case "maintenance_off":
			if _, derr := h.DB().ExecContext(ctx,
				"UPDATE routes SET maintenance_mode=0, updated_at=NOW() WHERE id=?", id); derr != nil {
				fail++
				continue
			}
			touchedNodes[nodeID] = struct{}{}
		case "retry_ssl":
			// Only resets routes with ssl_enabled to trigger cert re-issue.
			// domain_verified=1 is required: pending_ssl is a serving status, so
			// without it a scoped admin could repoint a route at an unowned
			// hostname and bulk-retry it straight back into the host matcher.
			var retryable int
			_ = h.DB().QueryRowContext(ctx,
				"SELECT COUNT(*) FROM routes WHERE id=? AND ssl_enabled=1 AND domain_verified=1", id).Scan(&retryable)
			if retryable == 0 {
				fail++
				continue
			}
			if _, derr := h.DB().ExecContext(ctx,
				"UPDATE routes SET status=?, last_error=NULL, updated_at=NOW() WHERE id=? AND ssl_enabled=1 AND domain_verified=1",
				"pending_ssl", id); derr != nil {
				fail++
				continue
			}
			touchedNodes[nodeID] = struct{}{}
		case "resync":
			// Queue node for immediate resync without changing route status.
			touchedNodes[nodeID] = struct{}{}
		default:
			fail++
			continue
		}
		ok++
	}
	// Single resync per affected node, not per row.
	for nodeID := range touchedNodes {
		nid := nodeID
		go func() {
			defer recoverBg(h.Logger, "resync")
			ctx, cancel := context.WithTimeout(h.Routes.BackgroundCtx(), 30*time.Second)
			defer cancel()
			_ = h.Routes.Resync(ctx, nid)
		}()
	}
	audit.Write(ctx, h.DB(), h.Logger, r, audit.Entry{
		UserID: actorUserID(sess), Action: "admin.host.bulk", Entity: "route",
		Meta: map[string]any{"action": action, "ok": ok, "fail": fail, "count": len(ids)},
	})
	msg := strconv.Itoa(ok) + " host(s) " + action + "d"
	if fail > 0 {
		msg += "; " + strconv.Itoa(fail) + " failed"
	}
	redirectWithFlash(w, r, "/admin/hosts", msg, "")
}

// moveRouteToNode repoints a route at destNodeID and returns the previous node.
// Destination is resolved and authorized INSIDE the tx: it must exist, be
// approved and enabled, and - for anyone who is not a full platform admin -
// live in the same node group the route's service is placed in. Owning the
// route is not owning the fleet; a cross-group move lands a tenant's config on
// another tenant's (or a platform) node.
func (h *AdminHandlers) moveRouteToNode(ctx context.Context, sess *auth.Session, routeID, destNodeID int64) (oldNodeID int64, err error) {
	tenantScoped, provOK := h.selfProvisionScope(ctx, sess)
	platform := provOK && !tenantScoped

	tx, err := h.DB().BeginTx(ctx, nil)
	if err != nil {
		return 0, err
	}
	defer func() { _ = tx.Rollback() }() // no-op once committed

	var srcGroupID sql.NullInt64
	if err = tx.QueryRowContext(ctx,
		`SELECT r.caddy_node_id, s.node_group_id
		   FROM routes r JOIN services s ON s.id = r.service_id
		  WHERE r.id = ?`, routeID).Scan(&oldNodeID, &srcGroupID); err != nil {
		return 0, err
	}
	var destGroupID sql.NullInt64
	if err = tx.QueryRowContext(ctx,
		`SELECT node_group_id FROM caddy_nodes
		  WHERE id = ? AND approved_at IS NOT NULL AND is_enabled = 1`,
		destNodeID).Scan(&destGroupID); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return 0, errors.New("destination node not found, not approved or disabled")
		}
		return 0, err
	}
	if !platform && (!srcGroupID.Valid || !destGroupID.Valid || srcGroupID.Int64 != destGroupID.Int64) {
		return 0, errors.New("destination node is outside the route's placement group")
	}
	if _, err = tx.ExecContext(ctx,
		"UPDATE routes SET caddy_node_id=?, updated_at=NOW() WHERE id=?", destNodeID, routeID); err != nil {
		return 0, err
	}
	if err = tx.Commit(); err != nil {
		return 0, err
	}
	return oldNodeID, nil
}

// ensureAdminClient returns the clients.id for the admin user, creating
// it on first call. Each user has at most one clients row (uq_clients_user).
// ensureAdminClient returns the self-client for an admin, creating it on first
// use. resellerID is the caller's Session.ResellerID: for a reseller-admin the
// self-client must carry that reseller_id so hosts/streams they self-provision
// stay inside their reseller scope (scope is derived from clients.reseller_id).
// A pre-existing self-client with a mismatched/NULL reseller_id is repaired.
func ensureAdminClient(ctx context.Context, db *sql.DB, userID, resellerID int64) (int64, error) {
	var id int64
	var curReseller sql.NullInt64
	err := db.QueryRowContext(ctx, "SELECT id, reseller_id FROM clients WHERE user_id = ?", userID).Scan(&id, &curReseller)
	if err == nil {
		if resellerID > 0 && (!curReseller.Valid || curReseller.Int64 != resellerID) {
			if _, uerr := db.ExecContext(ctx, "UPDATE clients SET reseller_id = ? WHERE id = ?", resellerID, id); uerr != nil {
				return 0, uerr
			}
		}
		return id, nil
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return 0, err
	}
	var resellerCol any
	if resellerID > 0 {
		resellerCol = resellerID
	}
	res, err := db.ExecContext(ctx,
		"INSERT INTO clients (user_id, display_name, reseller_id) VALUES (?, ?, ?)",
		userID, "admin (self)", resellerCol)
	if err != nil {
		return 0, err
	}
	id, _ = res.LastInsertId()
	return id, nil
}

// ensureAdminPlan returns the id of the "_admin-self" plan, creating it
// in the supplied node_group on first call. The plan is kind=npm with
// no caps so admin hosts never trip plan limits.
func ensureAdminPlan(ctx context.Context, db *sql.DB, nodeGroupID int64) (int64, error) {
	// Plans are keyed by (name, node_group_id). Without the group filter,
	// the first call wins and subsequent groups silently inherit the wrong
	// node_group - services then get placed against routes the wrong
	// caddy node owns and the resync loop fights itself.
	var id int64
	err := db.QueryRowContext(ctx,
		"SELECT id FROM plans WHERE name = ? AND node_group_id = ? LIMIT 1",
		internalAdminPlanName, nodeGroupID).Scan(&id)
	if err == nil {
		return id, nil
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return 0, err
	}
	res, err := db.ExecContext(ctx,
		`INSERT INTO plans (name, kind, max_domains, max_ports, ssl_enabled,
		   path_routing_enabled, wildcard_enabled, websocket_enabled, node_group_id)
		 VALUES (?, 'npm', 1000000, 1000000, 1, 1, 1, 1, ?)`,
		internalAdminPlanName, nodeGroupID)
	if err != nil {
		return 0, err
	}
	id, _ = res.LastInsertId()
	return id, nil
}

// ensureAdminService finds or creates a services row keyed on
// (client_id, backend_ip). The port range is the full 1..65535 so a
// single service can carry many admin-added routes. New backends get
// new services on demand; deleting the last route does not GC the
// service (cheap, lets the admin reuse it later).
func ensureAdminService(ctx context.Context, db *sql.DB, clientID int64, backendIP string, planID, nodeGroupID int64) (int64, error) {
	var id int64
	err := db.QueryRowContext(ctx,
		`SELECT id FROM services WHERE client_id = ? AND backend_ip = ? LIMIT 1`,
		clientID, backendIP).Scan(&id)
	if err == nil {
		return id, nil
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return 0, err
	}
	res, err := db.ExecContext(ctx,
		`INSERT INTO services (client_id, name, backend_ip, allowed_port_start, allowed_port_end,
		   plan_id, node_group_id, status)
		 VALUES (?, ?, ?, 1, 65535, ?, ?, 'active')`,
		clientID, "admin "+backendIP, backendIP, planID, nodeGroupID)
	if err != nil {
		return 0, err
	}
	id, _ = res.LastInsertId()
	return id, nil
}
