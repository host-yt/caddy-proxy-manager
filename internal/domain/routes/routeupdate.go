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
	"time"

	"github.com/host-yt/caddy-proxy-manager/internal/caddyapi"
	"github.com/host-yt/caddy-proxy-manager/internal/store"
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

// RoutesOutsidePorts counts the service's dialing routes (same rule as
// checkRouteState) whose port falls outside [start,end]. A range change must
// not leave them live on ports the service no longer owns. Run it on the tx that
// holds LockServicePortRange so no route write slips in before the range UPDATE.
func RoutesOutsidePorts(ctx context.Context, tx *sql.Tx, serviceID int64, start, end int) (int, error) {
	var n int
	err := tx.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM routes WHERE service_id = ? AND kind <> 'redirect'
		    AND COALESCE(upstream_external,0) = 0 AND (upstream_port < ? OR upstream_port > ?)`,
		serviceID, start, end).Scan(&n)
	return n, err
}

// LockServicePortRange row-locks the service and returns its port range. Route
// writes and range changes both take it, so neither commits against a stale range.
func LockServicePortRange(ctx context.Context, tx *sql.Tx, serviceID int64) (start, end int, err error) {
	err = tx.QueryRowContext(ctx,
		"SELECT allowed_port_start, allowed_port_end FROM services WHERE id = ?"+store.ForUpdate(),
		serviceID).Scan(&start, &end)
	if errors.Is(err, sql.ErrNoRows) {
		err = ErrServiceNotFound
	}
	return start, end, err
}

// CheckLockedPort re-validates a dialing route's port under the service lock,
// inside the tx that writes the route.
func CheckLockedPort(ctx context.Context, tx *sql.Tx, serviceID int64, st RouteState) error {
	if st.Kind == "redirect" || st.External {
		return nil
	}
	start, end, err := LockServicePortRange(ctx, tx, serviceID)
	if err != nil {
		return err
	}
	if st.UpstreamPort < start || st.UpstreamPort > end {
		return ErrPortOutOfRange
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
	// Upstream scheme and per-route policy (nil = unchanged).
	UpstreamScheme *string
	WAFEnabled     *bool
	WAFBlocking    *bool
	RateEnabled    *bool
	RateWindow     *string
	RateMaxEvents  *int
	RateKey        *string
	// SkipTLSVerify disables upstream cert verification; callers gate it.
	SkipTLSVerify *bool
}

// routePolicy is the scheme/WAF/rate-limit slice of a route row.
type routePolicy struct {
	Scheme              string
	WAF, WAFBlock, Rate bool
	RateWindow, RateKey string
	RateMaxEvents       int
	SkipTLS             bool
}

// apply overlays in onto p and validates it with the same rules as the UI
// save, including the node-module gate for newly enabled features.
func (s *Service) applyPolicy(ctx context.Context, nodeID int64, external bool, p routePolicy, in UpdateInput) (routePolicy, error) {
	if in.UpstreamScheme != nil {
		sc := strings.ToLower(strings.TrimSpace(*in.UpstreamScheme))
		if sc != "http" && sc != "https" {
			return p, fmt.Errorf("%w: upstream_scheme must be http or https", ErrInvalidRouteField)
		}
		if external && sc != "https" {
			return p, fmt.Errorf("%w: external routes are always https", ErrInvalidRouteField)
		}
		p.Scheme = sc
	}
	if in.SkipTLSVerify != nil {
		p.SkipTLS = *in.SkipTLSVerify
	}
	if in.WAFEnabled != nil {
		p.WAF = *in.WAFEnabled
	}
	if in.WAFBlocking != nil {
		p.WAFBlock = *in.WAFBlocking
	}
	if in.RateEnabled != nil {
		p.Rate = *in.RateEnabled
	}
	if in.RateWindow != nil {
		p.RateWindow = strings.TrimSpace(*in.RateWindow)
	}
	if in.RateMaxEvents != nil {
		p.RateMaxEvents = *in.RateMaxEvents
	}
	if in.RateKey != nil {
		p.RateKey = strings.TrimSpace(*in.RateKey)
	}
	if p.RateWindow == "" {
		p.RateWindow = "1m"
	}
	if p.RateMaxEvents <= 0 {
		p.RateMaxEvents = 100
	}
	if p.RateKey == "" {
		p.RateKey = "{http.request.remote.host}"
	}
	if p.RateMaxEvents > 1000000 {
		return p, fmt.Errorf("%w: rate_max_events must be 1-1000000", ErrInvalidRouteField)
	}
	if _, err := time.ParseDuration(p.RateWindow); err != nil {
		return p, fmt.Errorf("%w: invalid rate_window (e.g. 1m, 30s)", ErrInvalidRouteField)
	}
	if err := caddyapi.ScreenTenantRateKey(p.RateKey); err != nil {
		return p, fmt.Errorf("%w: rate_key: %v", ErrInvalidRouteField, err)
	}
	// Never enable a feature the node's Caddy build lacks (probe wins over env flag).
	if (in.WAFEnabled != nil && p.WAF) || (in.RateEnabled != nil && p.Rate) {
		var pWAF, pRate sql.NullBool
		_ = s.DB.QueryRowContext(ctx,
			`SELECT CASE WHEN modules_probed_at IS NOT NULL THEN has_waf END,
			        CASE WHEN modules_probed_at IS NOT NULL THEN has_rate_limit END
			   FROM caddy_nodes WHERE id = ?`, nodeID).Scan(&pWAF, &pRate)
		effWAF, effRate := s.WAFModuleAvailable, s.RateLimitModuleAvailable
		if pWAF.Valid {
			effWAF = pWAF.Bool
		}
		if pRate.Valid {
			effRate = pRate.Bool
		}
		if in.WAFEnabled != nil && p.WAF && !effWAF {
			return p, fmt.Errorf("%w: WAF needs the coraza-caddy module on the node", ErrInvalidRouteField)
		}
		if in.RateEnabled != nil && p.Rate && !effRate {
			return p, fmt.Errorf("%w: rate limiting needs the caddy-ratelimit module on the node", ErrInvalidRouteField)
		}
	}
	return p, nil
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
		cur                            routePolicy
	)
	switch err := s.DB.QueryRowContext(ctx,
		`SELECT sv.client_id, r.service_id, COALESCE(r.caddy_node_id,0), r.kind,
		        COALESCE(r.upstream_external,0), COALESCE(r.require_client_cert,0),
		        r.upstream_port, COALESCE(r.path_prefix,''), COALESCE(r.ssl_enabled,0),
		        COALESCE(r.websocket,0), COALESCE(r.force_https,0),
		        r.upstream_scheme, COALESCE(r.waf_enabled,0), COALESCE(r.waf_blocking,0),
		        COALESCE(r.rate_enabled,0), COALESCE(r.rate_window,''), COALESCE(r.rate_max_events,0), COALESCE(r.rate_key,''),
		        COALESCE(r.upstream_skip_tls_verify,0)
		   FROM routes r JOIN services sv ON sv.id = r.service_id WHERE r.id = ?`,
		routeID,
	).Scan(&ownerClient, &serviceID, &nodeID, &kind, &external, &enforced,
		&curPort, &curPath, &curSSL, &curWS, &curForce,
		&cur.Scheme, &cur.WAF, &cur.WAFBlock, &cur.Rate, &cur.RateWindow, &cur.RateMaxEvents, &cur.RateKey, &cur.SkipTLS); {
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
	pol, err := s.applyPolicy(ctx, nodeID, external == 1, cur, in)
	if err != nil {
		return false, err
	}
	// Compare against stored values, not the defaulted ones, so an untouched
	// route with empty rate columns stays a no-op.
	polChanged := pol.Scheme != cur.Scheme || pol.WAF != cur.WAF || pol.WAFBlock != cur.WAFBlock || pol.Rate != cur.Rate || pol.SkipTLS != cur.SkipTLS ||
		(in.RateWindow != nil && pol.RateWindow != cur.RateWindow) ||
		(in.RateMaxEvents != nil && pol.RateMaxEvents != cur.RateMaxEvents) ||
		(in.RateKey != nil && pol.RateKey != cur.RateKey)
	if !polChanged {
		pol.RateWindow, pol.RateMaxEvents, pol.RateKey = cur.RateWindow, cur.RateMaxEvents, cur.RateKey
	}

	// Nothing new to write: an authorized no-op is a success. Checked before the
	// UPDATE because MySQL reports 0 affected rows for a write that changes
	// nothing (no clientFoundRows), which is not "row missing".
	if next.UpstreamPort == curPort && next.PathPrefix == curPath &&
		next.SSL == (curSSL == 1) && next.WebSocket == (curWS == 1) && nextForce == (curForce == 1) && !polChanged {
		return false, nil
	}

	where := "id=?"
	if !next.SSL {
		where += " AND COALESCE(require_client_cert, 0) = 0"
	}
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return false, err
	}
	defer tx.Rollback() //nolint:errcheck
	if err := CheckLockedPort(ctx, tx, serviceID, next); err != nil {
		return false, err
	}
	res, err := tx.ExecContext(ctx,
		`UPDATE routes SET upstream_port=?, path_prefix=?, ssl_enabled=?, websocket=?,
		        force_https=(? OR COALESCE(require_client_cert,0)), upstream_scheme=?,
		        waf_enabled=?, waf_blocking=?, rate_enabled=?, rate_window=?, rate_max_events=?, rate_key=?, upstream_skip_tls_verify=?, updated_at=NOW()
		  WHERE `+where,
		next.UpstreamPort, next.PathPrefix, next.SSL, next.WebSocket, nextForce, pol.Scheme,
		pol.WAF, pol.WAFBlock, pol.Rate, pol.RateWindow, pol.RateMaxEvents, pol.RateKey, pol.SkipTLS, routeID)
	if err != nil {
		return false, fmt.Errorf("route update: %w", err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		// Either the row went away or the mTLS guard held the write back; a
		// re-read that fails still rejects.
		var live int
		switch err := tx.QueryRowContext(ctx,
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
	if err := tx.Commit(); err != nil {
		return false, fmt.Errorf("route update: %w", err)
	}
	s.SchedulePushForRoute(ctx, routeID)
	return true, nil
}
