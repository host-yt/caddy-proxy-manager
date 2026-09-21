// Route update: one command that validates the FULL new state of a route
// against the owning service's allocation and its plan, shared by create and by
// every update transport (HPG-008). Owning a row is not permission to move it
// into any state.
package routes

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"

	"github.com/host-yt/caddy-proxy-manager/internal/caddyapi"
)

var (
	// ErrRouteNotFound: no routes row with that id.
	ErrRouteNotFound = errors.New("route not found")
	// ErrPathNotInPlan / ErrSSLNotInPlan / ErrWebSocketNotInPlan: the requested
	// state needs a plan capability this service's plan does not have.
	ErrPathNotInPlan      = errors.New("plan does not permit path routing")
	ErrSSLNotInPlan       = errors.New("plan does not permit SSL")
	ErrWebSocketNotInPlan = errors.New("plan does not permit websockets")
	// ErrUnsafePlaceholder: a tenant string Caddy would expand as a placeholder
	// reading the node's env/filesystem (HPG-001).
	ErrUnsafePlaceholder = errors.New("value contains a placeholder that is not permitted")
)

// RouteState is the post-write shape of a route that the plan and the service's
// port allocation constrain. Create and the update paths validate the same
// struct so the rules exist once.
type RouteState struct {
	Kind         string // "" / "proxy" / "redirect"
	External     bool
	UpstreamPort int
	PathPrefix   string
	SSL          bool
	WebSocket    bool
	RedirectURL  string
}

// routePlan is the subset of services+plans the state check needs.
type routePlan struct {
	portStart, portEnd int
	ssl, ws, path      bool
}

// ValidateRouteState checks a route's full new state against the owning
// service's plan. routeID is the row being written (0 on create) so the port
// collision check can ignore the row itself.
func (s *Service) ValidateRouteState(ctx context.Context, serviceID, routeID int64, st RouteState) error {
	p, err := s.loadRoutePlan(ctx, serviceID)
	if err != nil {
		return err
	}
	return s.checkRouteState(ctx, serviceID, routeID, st, p)
}

func (s *Service) loadRoutePlan(ctx context.Context, serviceID int64) (routePlan, error) {
	var p routePlan
	err := s.DB.QueryRowContext(ctx,
		`SELECT s.allowed_port_start, s.allowed_port_end, pl.ssl_enabled, pl.websocket_enabled,
		        pl.path_routing_enabled
		   FROM services s JOIN plans pl ON pl.id = s.plan_id WHERE s.id = ? LIMIT 1`,
		serviceID).Scan(&p.portStart, &p.portEnd, &p.ssl, &p.ws, &p.path)
	if errors.Is(err, sql.ErrNoRows) {
		return p, ErrServiceNotFound
	}
	if err != nil {
		return p, fmt.Errorf("plan lookup: %w", err)
	}
	return p, nil
}

// checkRouteState is the rule set itself. Redirect routes never dial, external
// routes target the origin's own port, so neither is bound by the customer port
// allocation.
func (s *Service) checkRouteState(ctx context.Context, serviceID, routeID int64, st RouteState, p routePlan) error {
	dials := st.Kind != "redirect" && !st.External
	if dials {
		if st.UpstreamPort < p.portStart || st.UpstreamPort > p.portEnd {
			return ErrPortOutOfRange
		}
		var used int
		if err := s.DB.QueryRowContext(ctx,
			"SELECT COUNT(*) FROM routes WHERE service_id = ? AND upstream_port = ? AND id <> ?",
			serviceID, st.UpstreamPort, routeID).Scan(&used); err == nil && used > 0 {
			return ErrPortInUse
		}
	}
	if strings.TrimSpace(st.PathPrefix) != "" && !p.path {
		return ErrPathNotInPlan
	}
	// External routes always serve their own cert, so the plan SSL flag cannot
	// switch them off (mirrors Create).
	if st.SSL && !p.ssl && !st.External {
		return ErrSSLNotInPlan
	}
	if st.WebSocket && !p.ws {
		return ErrWebSocketNotInPlan
	}
	if st.RedirectURL != "" {
		if err := ScreenTenantString(st.RedirectURL); err != nil {
			return err
		}
	}
	return nil
}

// ScreenTenantString rejects a tenant-supplied string Caddy would expand as a
// placeholder reading the node's environment or filesystem. It is the write-time
// half of the screening the emission path already does; fail closed.
func ScreenTenantString(v string) error {
	if err := caddyapi.ScreenTenantTemplate(v); err != nil {
		return fmt.Errorf("%w: %v", ErrUnsafePlaceholder, err)
	}
	return nil
}

// ScreenTenantText is the looser check for free-text and HTML values, where a
// stray brace is legitimate (CSS). Emission neutralizes what survives this, so
// the write-time job is only to tell the operator early about the obvious ones.
func ScreenTenantText(v string) error {
	if err := caddyapi.ScreenReplacerValue(v); err != nil {
		return fmt.Errorf("%w: %v", ErrUnsafePlaceholder, err)
	}
	return nil
}

// UpdateInput is a partial route change: a nil field is left as it is.
type UpdateInput struct {
	UpstreamPort *int
	PathPrefix   *string
	SSL          *bool
	WebSocket    *bool
	ForceHTTPS   *bool
}

// UpdateRoute applies a partial change after validating the resulting FULL
// state against the current plan. Returns changed=false when the request writes
// nothing new to an existing, authorized route - a no-op is a success, not a
// 404 (HPG-019). clientID 0 means an admin/API context (no ownership check).
func (s *Service) UpdateRoute(ctx context.Context, clientID, routeID int64, in UpdateInput) (bool, error) {
	if s == nil || s.DB == nil {
		return false, errors.New("route service not ready")
	}
	var (
		ownerClient, serviceID, nodeID int64
		kind                           string
		external, enforced             int
		curPort                        int
		curPath                        string
		curSSL, curWS, curForce        int
	)
	switch err := s.DB.QueryRowContext(ctx,
		`SELECT sv.client_id, r.service_id, COALESCE(r.caddy_node_id,0), r.kind,
		        COALESCE(r.upstream_external,0), COALESCE(r.require_client_cert,0),
		        r.upstream_port, COALESCE(r.path_prefix,''), COALESCE(r.ssl_enabled,0),
		        COALESCE(r.websocket,0), COALESCE(r.force_https,0)
		   FROM routes r JOIN services sv ON sv.id = r.service_id WHERE r.id = ?`,
		routeID,
	).Scan(&ownerClient, &serviceID, &nodeID, &kind, &external, &enforced,
		&curPort, &curPath, &curSSL, &curWS, &curForce); {
	case errors.Is(err, sql.ErrNoRows):
		return false, ErrRouteNotFound
	case err != nil:
		return false, fmt.Errorf("route lookup: %w", err)
	}
	if clientID != 0 && ownerClient != clientID {
		return false, ErrServiceNotYours
	}

	next := RouteState{
		Kind: kind, External: external == 1, UpstreamPort: curPort, PathPrefix: curPath,
		SSL: curSSL == 1, WebSocket: curWS == 1,
	}
	if in.UpstreamPort != nil {
		next.UpstreamPort = *in.UpstreamPort
	}
	if in.PathPrefix != nil {
		p := strings.TrimSpace(*in.PathPrefix)
		if p != "" {
			if !strings.HasPrefix(p, "/") {
				p = "/" + p
			}
			if strings.Contains(p, "..") {
				return false, ErrInvalidDomain
			}
		}
		next.PathPrefix = p
	}
	if in.SSL != nil {
		next.SSL = *in.SSL
	}
	if in.WebSocket != nil {
		next.WebSocket = *in.WebSocket
	}
	// mTLS rides on the route's TLS connection policy: an enforced host without
	// TLS serves either wide open or 503. Rejected here and again atomically in
	// the UPDATE's WHERE, which is what keeps a concurrent "enable mTLS" honest.
	if enforced == 1 && !next.SSL {
		return false, ErrMTLSNeedsTLS
	}
	nextForce := curForce == 1
	if in.ForceHTTPS != nil {
		nextForce = *in.ForceHTTPS
	}
	nextForce = nextForce || enforced == 1

	if err := s.ValidateRouteState(ctx, serviceID, routeID, next); err != nil {
		return false, err
	}

	// Nothing new to write: an authorized no-op is a success. Checked before the
	// UPDATE because MySQL reports 0 affected rows for a write that changes
	// nothing (no clientFoundRows), which is not "row missing".
	if next.UpstreamPort == curPort && next.PathPrefix == curPath &&
		next.SSL == (curSSL == 1) && next.WebSocket == (curWS == 1) && nextForce == (curForce == 1) {
		return false, nil
	}

	where := "id=?"
	if !next.SSL {
		where += " AND COALESCE(require_client_cert, 0) = 0"
	}
	res, err := s.DB.ExecContext(ctx,
		`UPDATE routes SET upstream_port=?, path_prefix=?, ssl_enabled=?, websocket=?,
		        force_https=(? OR COALESCE(require_client_cert,0)), updated_at=NOW()
		  WHERE `+where,
		next.UpstreamPort, next.PathPrefix, next.SSL, next.WebSocket, nextForce, routeID)
	if err != nil {
		return false, fmt.Errorf("route update: %w", err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		// Either the row went away or the mTLS guard held the write back; a
		// re-read that fails still rejects.
		var live int
		switch err := s.DB.QueryRowContext(ctx,
			"SELECT COALESCE(require_client_cert,0) FROM routes WHERE id = ?", routeID).Scan(&live); {
		case errors.Is(err, sql.ErrNoRows):
			return false, ErrRouteNotFound
		case err != nil:
			return false, fmt.Errorf("route update: %w", err)
		case live == 1 && !next.SSL:
			return false, ErrMTLSNeedsTLS
		}
		// Row exists, guard did not fire: another writer already stored this
		// exact state. Still a no-op success.
		return false, nil
	}
	if nodeID != 0 {
		s.SchedulePush(nodeID)
	}
	return true, nil
}
