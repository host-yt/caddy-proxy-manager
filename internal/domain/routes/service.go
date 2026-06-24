// Package routes owns the route lifecycle: validation, node placement,
// DNS pre-check, Caddy push.
package routes

import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"runtime/debug"
	"sort"
	"strings"
	"sync"
	"time"

	"golang.org/x/sync/errgroup"

	"github.com/hostyt/proxy-gateway/internal/caddyapi"
	"github.com/hostyt/proxy-gateway/internal/dns"
)

// recoverBg logs and swallows a panic in a fire-and-forget goroutine.
// Background goroutines have no Recoverer middleware, so one nil-deref would
// otherwise crash the whole control plane. Use as `defer recoverBg(log, name)`.
func recoverBg(logger *slog.Logger, name string) {
	if r := recover(); r != nil && logger != nil {
		logger.Error("background goroutine panicked", "task", name, "panic", r, "stack", string(debug.Stack()))
	}
}

// Service drives the route lifecycle.
type Service struct {
	DB          *sql.DB
	Logger      *slog.Logger
	AskURL      string
	ACMEEmail   string
	ACMEStaging bool

	// BgCtx is a background context derived from the app root context,
	// cancelled after HTTP shutdown so fire-and-forget pushes drain cleanly
	// instead of outliving the process. Nil-safe via BackgroundCtx().
	BgCtx context.Context

	// CacheModuleAvailable mirrors caddyapi.NodeSettings.CacheModuleAvailable.
	// Sourced from env CACHE_HANDLER_AVAILABLE so operators upgrading their
	// Caddy nodes (deploy/caddy/Dockerfile xcaddy build) flip it once
	// fleet-wide, before turning on `cache_enabled` on any route.
	CacheModuleAvailable bool

	// Layer4ModuleAvailable mirrors caddyapi.NodeSettings.Layer4ModuleAvailable.
	// Env: LAYER4_AVAILABLE=1.
	Layer4ModuleAvailable bool

	// WeightedLBAvailable gates weighted_round_robin LB emission. Env:
	// WEIGHTED_LB_AVAILABLE=1. When off the builder downgrades to round_robin.
	WeightedLBAvailable bool

	// RateLimitModuleAvailable / WAFModuleAvailable / DNS01ModuleAvailable gate
	// non-stock per-route handlers + wildcard automation. Default off; flipping
	// on before the fleet runs the custom image takes nodes offline on /load.
	RateLimitModuleAvailable bool
	WAFModuleAvailable       bool
	DNS01ModuleAvailable     bool

	// PanelPublicHost / PanelInternalHost / PanelInternalPort drive the
	// self-bootstrap route prepended to every node's Caddy config. When
	// PanelPublicHost is empty the bootstrap route is skipped (e.g. APP_URL
	// not configured yet, or operator opted out).
	PanelPublicHost   string
	PanelInternalHost string
	PanelInternalPort int

	// Metrics is optional. When set, push/drift counters tick into Prometheus.
	Metrics PushMetrics

	// Webhooks is optional. When set, route lifecycle events (active, failed,
	// cert.issued) get emitted to configured endpoints.
	Webhooks WebhookEmitter

	// Notifier is optional. When set, lifecycle transitions that affect
	// a customer's reachability (auto-failover, failover-skipped) trigger
	// an email + SMS to the route's owning client.
	Notifier CustomerNotifier

	// EncryptSecret / DecryptSecret wrap installstate AES-GCM (APP_SECRET) so
	// this package can store/read the External-route inbound bearer at rest
	// without importing installstate. Nil disables external secret handling.
	EncryptSecret func(string) (string, error)
	DecryptSecret func(string) (string, error)

	// ExternalUpstreamAllowlist is the set of FQDNs an External proxy route
	// may target (exact host, case-insensitive). Empty = no external route is
	// permitted. Enforced at Create AND again at build time (defense in depth).
	ExternalUpstreamAllowlist []string

	// IncrementalPush enables per-route Caddy @id mutations (PATCH/POST/DELETE)
	// for single-route changes instead of a full /load. Kill switch: env
	// INCREMENTAL_PATCH=0 reverts to full /load with no code change. Every
	// incremental op already falls back to /load on any error.
	IncrementalPush bool

	nodeMu sync.Mutex
	locks  map[int64]*sync.Mutex // per-node serialization for Caddy /load

	// healthMu guards lastHealth.
	healthMu   sync.Mutex
	lastHealth map[int64]string // last observed health_status per node

	// extAllowMu guards the cached DB allowlist (external_upstream_allowlist).
	// Cached with a short TTL so the build hot path does not hit the DB on
	// every route; UI edits take effect within extAllowTTL.
	extAllowMu      sync.Mutex
	extAllowCache   map[string]struct{}
	extAllowFetched time.Time
}

// extAllowTTL bounds how stale the cached DB allowlist may be. Short so
// UI add/remove propagates to the build path within seconds.
const extAllowTTL = 15 * time.Second

// panelRoute returns the self-bootstrap Caddy route for the panel domain
// or nil if PanelPublicHost is unset (operator hasn't completed wizard or
// disabled it).
func (s *Service) panelRoute() *caddyapi.Route {
	if s.PanelPublicHost == "" || s.PanelInternalHost == "" || s.PanelInternalPort == 0 {
		return nil
	}
	return &caddyapi.Route{
		ID:           "panel_self",
		Hosts:        []string{s.PanelPublicHost},
		UpstreamIP:   s.PanelInternalHost,
		UpstreamPort: s.PanelInternalPort,
		WebSocket:    true,
		ForceHTTPS:   true,
		HTTP2:        true,
	}
}

// PushMetrics is implemented by *obs.Metrics; defined as an interface so the
// routes package does not depend on the obs package directly (avoids cycle).
type PushMetrics interface {
	CaddyPushOK()
	CaddyPushFail()
	CaddyDriftResync()
}

// WebhookEmitter is implemented by *webhook.Service. Defined as an
// interface to keep the routes package import-cycle free.
type WebhookEmitter interface {
	Emit(ctx context.Context, eventType string, payload map[string]any)
}

// CustomerNotifier delivers an out-of-band notification to the client
// owning a route. Wired by main from mail.Mailer + sms.Sender via a
// tiny adapter; nil-safe so tests/dev can skip it.
type CustomerNotifier interface {
	Notify(ctx context.Context, clientID int64, subject, body string)
}

func (s *Service) nodeLock(id int64) *sync.Mutex {
	s.nodeMu.Lock()
	defer s.nodeMu.Unlock()
	if s.locks == nil {
		s.locks = map[int64]*sync.Mutex{}
	}
	m, ok := s.locks[id]
	if !ok {
		m = &sync.Mutex{}
		s.locks[id] = m
	}
	return m
}

// BackgroundCtx returns the app background context (cancelled after shutdown),
// or context.Background() when unset (tests/dev). Exported so handlers in other
// packages can scope their fire-and-forget pushes to the app lifecycle.
func (s *Service) BackgroundCtx() context.Context {
	if s.BgCtx != nil {
		return s.BgCtx
	}
	return context.Background()
}

// CreateInput is the user-supplied form for a new mapping.
type CreateInput struct {
	ServiceID      int64
	UpstreamPort   int
	UpstreamScheme string // http (default) or https
	Domain         string
	PathPrefix     string
	SSL            bool
	WebSocket      bool
	ForceHTTPS     bool
	// Kind "" or "proxy" → reverse_proxy; "redirect" → static_response.
	// When Kind=="redirect", UpstreamPort is ignored (stored as 0) and
	// RedirectURL/RedirectCode are required.
	Kind         string
	RedirectURL  string
	RedirectCode int
	Tag          string

	// External marks an external-HTTPS-upstream route (admin-only): proxy to
	// an allowlisted public FQDN over TLS from the node's egress IP. When set,
	// Create forces scheme=https / kind=proxy, skips the customer port-range
	// check, stores ExternalHost in backend_ip_override, and encrypts
	// ProxySecretPlain (the freshly generated inbound bearer) at rest.
	External           bool
	ExternalHost       string
	UpstreamHostHeader string
	ProxySecretPlain   string

	// WildcardEnabled marks this route's domain as served by a *.WildcardZone
	// cert obtained via ACME DNS-01. Requires an enabled dns_providers row for
	// the zone and the domain to be the zone or a subdomain of it. Admin-only.
	WildcardEnabled bool
	WildcardZone    string
}

// Validation errors exposed to handlers.
var (
	ErrPortOutOfRange  = errors.New("port not in allowed range for this service")
	ErrInvalidDomain   = errors.New("invalid domain")
	ErrDomainTaken     = errors.New("domain (+ path) already mapped")
	ErrNoNodeFound     = errors.New("no Caddy node available for this plan")
	ErrServiceNotYours = errors.New("service does not belong to caller")
	ErrMaxDomains      = errors.New("plan limit reached: max domains")
	// ErrExternalHostNotAllowed: the external upstream FQDN is not in the
	// operator's EXTERNAL_UPSTREAM_ALLOWLIST. Primary open-relay defense.
	ErrExternalHostNotAllowed = errors.New("external upstream host not in allowlist")
	// ErrExternalNotInPlan: the owning plan does not have external_proxy_enabled.
	ErrExternalNotInPlan = errors.New("plan does not permit external HTTPS upstream routes")
	// ErrWildcardNoProvider: no enabled dns_providers row exists for the
	// requested wildcard_zone, so the DNS-01 cert could never be issued.
	ErrWildcardNoProvider = errors.New("no DNS provider configured for wildcard zone")
	// ErrWildcardZoneMismatch: the route domain is neither the zone nor a
	// subdomain of it, so a *.zone cert would not cover it.
	ErrWildcardZoneMismatch = errors.New("domain is not covered by the wildcard zone")
)

// ExternalHostAllowed is the exported wrapper so handlers can validate an
// external upstream FQDN against the allowlist (single source of truth).
func (s *Service) ExternalHostAllowed(host string) bool { return s.externalHostAllowed(host) }

// externalHostAllowed reports whether host is an exact (case-insensitive)
// member of the external-upstream allowlist: the union of the env CSV
// (ExternalUpstreamAllowlist, backward compat) and the DB-managed table
// (external_upstream_allowlist). Empty union denies all.
func (s *Service) externalHostAllowed(host string) bool {
	host = strings.ToLower(strings.TrimSpace(host))
	if host == "" {
		return false
	}
	for _, a := range s.ExternalUpstreamAllowlist {
		if strings.ToLower(strings.TrimSpace(a)) == host {
			return true
		}
	}
	_, ok := s.dbAllowlist()[host]
	return ok
}

// dbAllowlist returns the cached set of DB-managed allowlist hosts (lowercased),
// refreshing from external_upstream_allowlist when the cache is older than
// extAllowTTL. On query error it returns the last good cache (fail-closed to
// what was previously known, never widening the allowlist).
func (s *Service) dbAllowlist() map[string]struct{} {
	s.extAllowMu.Lock()
	defer s.extAllowMu.Unlock()
	if s.extAllowCache != nil && time.Since(s.extAllowFetched) < extAllowTTL {
		return s.extAllowCache
	}
	if s.DB == nil {
		if s.extAllowCache == nil {
			s.extAllowCache = map[string]struct{}{}
		}
		return s.extAllowCache
	}
	ctx, cancel := context.WithTimeout(s.BackgroundCtx(), 2*time.Second)
	defer cancel()
	rows, err := s.DB.QueryContext(ctx, "SELECT host FROM external_upstream_allowlist")
	if err != nil {
		if s.extAllowCache == nil {
			s.extAllowCache = map[string]struct{}{}
		}
		return s.extAllowCache
	}
	defer rows.Close()
	next := map[string]struct{}{}
	for rows.Next() {
		var h string
		if rows.Scan(&h) == nil {
			next[strings.ToLower(strings.TrimSpace(h))] = struct{}{}
		}
	}
	s.extAllowCache = next
	s.extAllowFetched = time.Now()
	return next
}

// ExternalAllowlistAll returns the full union (env CSV + DB table), sorted and
// deduped, for UI display (host datalist / management list refresh).
func (s *Service) ExternalAllowlistAll() []string {
	set := map[string]struct{}{}
	for _, a := range s.ExternalUpstreamAllowlist {
		if a = strings.ToLower(strings.TrimSpace(a)); a != "" {
			set[a] = struct{}{}
		}
	}
	for h := range s.dbAllowlist() {
		set[h] = struct{}{}
	}
	out := make([]string, 0, len(set))
	for h := range set {
		out = append(out, h)
	}
	sort.Strings(out)
	return out
}

// Create inserts a route, picks a node, runs DNS pre-check synchronously
// (best-effort), and pushes the node config to Caddy. Returns the new
// route id.
func (s *Service) Create(ctx context.Context, clientID int64, in CreateInput) (int64, error) {
	domain := strings.ToLower(strings.TrimSpace(in.Domain))
	pathPrefix := strings.TrimSpace(in.PathPrefix)
	if domain == "" || !validDomain(domain) {
		return 0, ErrInvalidDomain
	}
	if pathPrefix != "" {
		if !strings.HasPrefix(pathPrefix, "/") {
			pathPrefix = "/" + pathPrefix
		}
		if strings.Contains(pathPrefix, "..") {
			return 0, ErrInvalidDomain
		}
	}

	// Verify service ownership + read port range + node_group + plan.
	var (
		backendIP    string
		portStart    int
		portEnd      int
		ownerClient  int64
		nodeGroupID  int64
		planSSL      bool
		planWS       bool
		planPath     bool
		planMaxDom   int
		planWild     bool
		planExtProxy bool
	)
	err := s.DB.QueryRowContext(ctx,
		`SELECT s.client_id, s.backend_ip, s.allowed_port_start, s.allowed_port_end, s.node_group_id,
		        p.ssl_enabled, p.websocket_enabled, p.path_routing_enabled, p.max_domains, p.wildcard_enabled,
		        p.external_proxy_enabled
		 FROM services s JOIN plans p ON p.id = s.plan_id
		 WHERE s.id = ? LIMIT 1`,
		in.ServiceID,
	).Scan(&ownerClient, &backendIP, &portStart, &portEnd, &nodeGroupID, &planSSL, &planWS, &planPath, &planMaxDom, &planWild, &planExtProxy)
	if errors.Is(err, sql.ErrNoRows) {
		return 0, ErrServiceNotYours
	}
	if err != nil {
		return 0, fmt.Errorf("service lookup: %w", err)
	}
	// 0 clientID means "called from admin/API context" - allow.
	if clientID != 0 && ownerClient != clientID {
		return 0, ErrServiceNotYours
	}
	// External-HTTPS-upstream setup (admin-only). Validate the FQDN against
	// the allowlist (primary open-relay defense) and force the route shape:
	// https proxy to the origin's :443, its own cert via On-Demand TLS.
	var externalHost, encSecret string
	if in.External {
		// Per-plan gate. Admin/API context (clientID==0) still requires the
		// plan flag; the admin-self plan is kind='npm' which the migration
		// sets external_proxy_enabled=1, so super_admin works out of the box.
		if !planExtProxy {
			return 0, ErrExternalNotInPlan
		}
		externalHost = strings.ToLower(strings.TrimSpace(in.ExternalHost))
		if !s.externalHostAllowed(externalHost) {
			return 0, ErrExternalHostNotAllowed
		}
		in.Kind = "proxy"
		in.UpstreamScheme = "https"
		in.SSL = true
		if in.UpstreamPort == 0 {
			in.UpstreamPort = 443
		}
		if in.ProxySecretPlain != "" {
			if s.EncryptSecret == nil {
				return 0, fmt.Errorf("external route secret encryption not configured")
			}
			encSecret, err = s.EncryptSecret(in.ProxySecretPlain)
			if err != nil {
				return 0, fmt.Errorf("encrypt proxy secret: %w", err)
			}
		}
	}

	// Redirect routes have no upstream; skip the port-range check and
	// store port=0 so the column (NOT NULL) stays valid. External routes
	// target the origin's port (443), not the customer range, so skip too.
	if in.Kind == "redirect" {
		in.UpstreamPort = 0
		if in.RedirectURL == "" {
			return 0, fmt.Errorf("redirect_url is required for redirect routes")
		}
		switch in.RedirectCode {
		case 0:
			in.RedirectCode = 308
		case 301, 302, 307, 308:
		default:
			return 0, fmt.Errorf("redirect_code must be 301/302/307/308")
		}
	} else if !in.External && (in.UpstreamPort < portStart || in.UpstreamPort > portEnd) {
		return 0, ErrPortOutOfRange
	}
	if pathPrefix != "" && !planPath {
		return 0, fmt.Errorf("plan does not permit path routing")
	}
	// Plan limit: max_domains counted across this service.
	if planMaxDom > 0 {
		var currentCount int
		if err := s.DB.QueryRowContext(ctx,
			"SELECT COUNT(*) FROM routes WHERE service_id = ?", in.ServiceID,
		).Scan(&currentCount); err == nil && currentCount >= planMaxDom {
			return 0, ErrMaxDomains
		}
	}

	// Plan flags constrain customer choice. External routes always need their
	// own cert (the node domain), so the plan SSL flag can't disable them.
	if !planSSL && !in.External {
		in.SSL = false
	}
	if !planWS {
		in.WebSocket = false
	}

	// Wildcard DNS-01: plan-gated for customers (admin clientID==0 bypasses,
	// like External). Require an enabled dns_providers row for the zone (else
	// the cert can never issue) and that the domain is the zone or a subdomain
	// of it (else *.zone would not cover it). DNS A/AAAA is still required for
	// the host data-plane and is checked later in advanceRoute.
	var wildcardZone string
	if in.WildcardEnabled {
		if clientID != 0 && !planWild {
			return 0, fmt.Errorf("plan does not permit wildcard certificates")
		}
		wildcardZone = strings.ToLower(strings.TrimSpace(in.WildcardZone))
		if wildcardZone == "" || !validDomain(wildcardZone) {
			return 0, ErrWildcardZoneMismatch
		}
		if domain != wildcardZone && !strings.HasSuffix(domain, "."+wildcardZone) {
			return 0, ErrWildcardZoneMismatch
		}
		var n int
		if err := s.DB.QueryRowContext(ctx,
			"SELECT COUNT(*) FROM dns_providers WHERE name = ?", wildcardZone).Scan(&n); err != nil || n == 0 {
			return 0, ErrWildcardNoProvider
		}
	}

	// Pick node(s) based on group mode: single / active_active / failover.
	// Primary slot lands in routes.caddy_node_id; for fan-out modes the
	// other nodes get rows in route_node_assignments after insert.
	var (
		primaryNode int64
		allNodes    []int64
		groupMode   string
	)
	primaryNode, allNodes, groupMode, err = nodePlacement(ctx, s.DB, nodeGroupID)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return 0, ErrNoNodeFound
		}
		return 0, fmt.Errorf("node placement: %w", err)
	}
	nodeID := primaryNode

	// Insert + increment counter in a transaction.
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return 0, err
	}
	defer tx.Rollback() //nolint:errcheck

	kind := in.Kind
	if kind != "redirect" {
		kind = "proxy"
	}
	var redirURL sql.NullString
	if in.RedirectURL != "" {
		redirURL = sql.NullString{String: in.RedirectURL, Valid: true}
	}
	var redirCode sql.NullInt32
	if in.RedirectCode != 0 {
		redirCode = sql.NullInt32{Int32: int32(in.RedirectCode), Valid: true}
	}
	var tagVal sql.NullString
	if t := strings.TrimSpace(in.Tag); t != "" {
		if len(t) > 64 {
			t = t[:64]
		}
		tagVal = sql.NullString{String: t, Valid: true}
	}
	scheme := in.UpstreamScheme
	if scheme != "https" {
		scheme = "http"
	}
	// External-route columns (NULL/0 for normal routes).
	var backendOverride, hostHeader, secretEnc sql.NullString
	extFlag := 0
	if in.External {
		extFlag = 1
		backendOverride = sql.NullString{String: externalHost, Valid: true}
		hh := strings.TrimSpace(in.UpstreamHostHeader)
		if hh == "" {
			hh = externalHost
		}
		hostHeader = sql.NullString{String: hh, Valid: true}
		if encSecret != "" {
			secretEnc = sql.NullString{String: encSecret, Valid: true}
		}
	}
	// Wildcard columns (0/NULL for normal routes).
	var wildFlag int
	var wildZone sql.NullString
	if in.WildcardEnabled {
		wildFlag = 1
		wildZone = sql.NullString{String: wildcardZone, Valid: true}
	}
	res, err := tx.ExecContext(ctx,
		`INSERT INTO routes (service_id, caddy_node_id, domain, path_prefix, upstream_port, upstream_scheme,
		   ssl_enabled, websocket, force_https, http2_enabled, http3_enabled, status,
		   kind, redirect_url, redirect_code, tag,
		   backend_ip_override, upstream_external, upstream_host_header, proxy_secret_enc,
		   wildcard_enabled, wildcard_zone)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 1, 0, 'pending_dns', ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		in.ServiceID, nodeID, domain, pathPrefix, in.UpstreamPort, scheme,
		in.SSL, in.WebSocket, in.ForceHTTPS,
		kind, redirURL, redirCode, tagVal,
		backendOverride, extFlag, hostHeader, secretEnc,
		wildFlag, wildZone)
	if err != nil {
		if strings.Contains(err.Error(), "Duplicate entry") {
			return 0, ErrDomainTaken
		}
		return 0, fmt.Errorf("route insert: %w", err)
	}
	routeID, _ := res.LastInsertId()
	if _, err := tx.ExecContext(ctx,
		"UPDATE caddy_nodes SET current_routes = current_routes + 1 WHERE id = ?", nodeID); err != nil {
		return 0, fmt.Errorf("node counter bump: %w", err)
	}
	// Fan-out modes: record every target node in the assignments join table.
	// active_active deploys to all peers; failover deploys to primary + one
	// warm standby so the standby has the route ready when it's promoted.
	if groupMode != "single" && len(allNodes) > 1 {
		for _, n := range allNodes {
			if _, err := tx.ExecContext(ctx,
				"INSERT IGNORE INTO route_node_assignments (route_id, node_id) VALUES (?, ?)",
				routeID, n); err != nil {
				return 0, fmt.Errorf("fan-out assign: %w", err)
			}
			if n != nodeID {
				if _, err := tx.ExecContext(ctx,
					"UPDATE caddy_nodes SET current_routes = current_routes + 1 WHERE id = ?", n); err != nil {
					return 0, fmt.Errorf("peer counter bump: %w", err)
				}
			}
		}
	}
	if err := tx.Commit(); err != nil {
		return 0, err
	}

	// Best-effort lifecycle. Failures are recorded in the row, not returned.
	// Bound it: advanceRoute does a DNS lookup + Caddy push and must not pile
	// up holding a DB connection unbounded under burst route creation.
	go func() {
		defer recoverBg(s.Logger, "advanceRoute")
		ctx, cancel := context.WithTimeout(s.BackgroundCtx(), 45*time.Second)
		defer cancel()
		s.advanceRoute(ctx, routeID)
	}()
	if groupMode != "single" {
		for _, n := range allNodes {
			if n == nodeID {
				continue
			}
			n := n
			go func() {
				defer recoverBg(s.Logger, "pushNodeConfig")
				ctx2, cancel := context.WithTimeout(s.BackgroundCtx(), 30*time.Second)
				defer cancel()
				_ = s.pushNodeConfig(ctx2, n)
			}()
		}
	}
	return routeID, nil
}

// VerifyDNS re-runs the DNS check for an existing route and re-pushes
// to Caddy if it transitions to dns_ok.
func (s *Service) VerifyDNS(ctx context.Context, clientID, routeID int64) error {
	var ownerClient int64
	if err := s.DB.QueryRowContext(ctx,
		`SELECT sv.client_id FROM routes r JOIN services sv ON sv.id = r.service_id WHERE r.id = ?`,
		routeID,
	).Scan(&ownerClient); err != nil {
		return err
	}
	if clientID != 0 && ownerClient != clientID {
		return ErrServiceNotYours
	}
	s.advanceRoute(ctx, routeID)
	return nil
}

// Delete removes the route, decrements the node counter, and rebuilds the
// node config so Caddy stops serving the domain.
func (s *Service) Delete(ctx context.Context, clientID, routeID int64) error {
	var ownerClient, nodeID int64
	if err := s.DB.QueryRowContext(ctx,
		`SELECT sv.client_id, r.caddy_node_id FROM routes r
		 JOIN services sv ON sv.id = r.service_id WHERE r.id = ?`,
		routeID,
	).Scan(&ownerClient, &nodeID); err != nil {
		return err
	}
	if clientID != 0 && ownerClient != clientID {
		return ErrServiceNotYours
	}

	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback() //nolint:errcheck
	if _, err := tx.ExecContext(ctx, "DELETE FROM routes WHERE id = ?", routeID); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx,
		"UPDATE caddy_nodes SET current_routes = GREATEST(current_routes - 1, 0) WHERE id = ?", nodeID); err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return err
	}
	go func() {
		defer recoverBg(s.Logger, "pushRouteIncremental.remove")
		ctx, cancel := context.WithTimeout(s.BackgroundCtx(), 30*time.Second)
		defer cancel()
		// Row is already deleted: remove the route from the node by @id.
		_ = s.pushRouteIncremental(ctx, nodeID, routeID, routeRemove)
	}()
	return nil
}

// advanceRoute: DNS check → status update → push if eligible.
func (s *Service) advanceRoute(ctx context.Context, routeID int64) {
	var (
		nodeID       int64
		domain       string
		nodeHostname sql.NullString
		nodeIP       sql.NullString
	)
	if err := s.DB.QueryRowContext(ctx,
		`SELECT r.caddy_node_id, r.domain, n.public_hostname, n.public_ip
		 FROM routes r JOIN caddy_nodes n ON n.id = r.caddy_node_id WHERE r.id = ?`,
		routeID,
	).Scan(&nodeID, &domain, &nodeHostname, &nodeIP); err != nil {
		s.Logger.Error("advance: route lookup", "id", routeID, "err", err)
		return
	}

	if err := dns.Check(ctx, domain, nodeHostname.String, nodeIP.String); err != nil {
		_, _ = s.DB.ExecContext(ctx,
			"UPDATE routes SET status='pending_dns', last_error=?, dns_checked_at=NOW(), updated_at=NOW() WHERE id=?",
			truncErr(err), routeID)
		s.Logger.Info("route: dns pending", "id", routeID, "domain", domain, "err", err)
		// Push anyway: Caddy serves HTTP-01 challenge on :80 once DNS catches up.
		// For initial MVP we wait for DNS to be correct before pushing.
		return
	}
	_, _ = s.DB.ExecContext(ctx,
		"UPDATE routes SET status='dns_ok', last_error=NULL, dns_checked_at=NOW(), updated_at=NOW() WHERE id=?", routeID)

	// Incremental single-route push (covers Create-primary, VerifyDNS, Reconcile,
	// which all funnel through advanceRoute); falls back to full /load on error.
	if err := s.pushRouteIncremental(ctx, nodeID, routeID, routeUpsert); err != nil {
		_, _ = s.DB.ExecContext(ctx,
			"UPDATE routes SET status='failed', last_error=? WHERE id=?", truncErr(err), routeID)
		if s.Webhooks != nil {
			s.Webhooks.Emit(ctx, "route.failed", map[string]any{
				"route_id": routeID, "domain": domain, "node_id": nodeID,
				"error": truncErr(err),
			})
		}
		return
	}
	// On first activation set ssl_issued_at; on subsequent activations
	// (renewal) refresh it so the certs page shows recent activity.
	_, _ = s.DB.ExecContext(ctx,
		`UPDATE routes
		   SET status='active', last_error=NULL,
		       ssl_issued_at = CASE WHEN ssl_enabled = 1 THEN NOW() ELSE ssl_issued_at END
		 WHERE id=?`, routeID)
	if s.Webhooks != nil {
		s.Webhooks.Emit(ctx, "route.active", map[string]any{
			"route_id": routeID, "domain": domain, "node_id": nodeID,
		})
	}
}

// HealthProbe sweeps every enabled node in parallel, GETs its /config/
// endpoint, and updates health_status + last_seen_at. Errors are logged,
// not returned. Bounded concurrency keeps slow nodes from delaying the
// rest. Designed to be called every ~30s from a background ticker.
const healthProbeWorkers = 8

// pushWorkers bounds concurrent full /load pushes during fleet-wide sweeps
// (boot push, drift resync). Without this a single slow node serialized the
// whole sweep at N x clientTimeout; now one slow node only ties up one worker.
const pushWorkers = 4

// reconcileWorkers bounds concurrent per-route/per-node work in the reconcile
// sweeps so one slow node can't stall the whole sweep (it previously ran serial).
const reconcileWorkers = 4

// pushNodesConcurrent fans out pushNodeConfig across ids with bounded
// concurrency and a per-node timeout, so one slow/half-open node cannot stall
// the entire sweep. Errors are logged, not returned. Respects ctx cancel.
func (s *Service) pushNodesConcurrent(ctx context.Context, ids []int64, label string) {
	sem := make(chan struct{}, pushWorkers)
	var wg sync.WaitGroup
	for _, id := range ids {
		select {
		case <-ctx.Done():
			wg.Wait()
			return
		case sem <- struct{}{}:
		}
		wg.Add(1)
		go func(id int64) {
			defer recoverBg(s.Logger, "pushAll")
			defer wg.Done()
			defer func() { <-sem }()
			pushCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
			defer cancel()
			if err := s.pushNodeConfig(pushCtx, id); err != nil {
				s.Logger.Warn(label+" failed", "node_id", id, "err", err)
			} else {
				s.Logger.Info(label+" ok", "node_id", id)
			}
		}(id)
	}
	wg.Wait()
}

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
			client := caddyapi.New(p.apiURL)
			probeCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
			if _, err := client.GetRaw(probeCtx, "/config/"); err == nil {
				status = "healthy"
			}
			cancel()
			_, _ = s.DB.ExecContext(ctx,
				"UPDATE caddy_nodes SET health_status = ?, last_seen_at = NOW() WHERE id = ?",
				status, p.id)

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

// PushAll pushes the current DB-derived config to every enabled node.
// Used on panel boot so a cold-started Caddy (lost autosave, fresh container)
// gets repopulated immediately instead of waiting up to 5min for ReconcileDrift.
func (s *Service) PushAll(ctx context.Context) {
	if s.DB == nil {
		return
	}
	rows, err := s.DB.QueryContext(ctx,
		"SELECT id FROM caddy_nodes WHERE is_enabled = 1")
	if err != nil {
		s.Logger.Warn("boot push: list nodes", "err", err)
		return
	}
	var ids []int64
	for rows.Next() {
		var id int64
		if err := rows.Scan(&id); err == nil {
			ids = append(ids, id)
		}
	}
	rows.Close()
	s.pushNodesConcurrent(ctx, ids, "boot push")
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
		   AND n.last_seen_at < (NOW() - INTERVAL ? MINUTE)
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

	// Group-level dest cache so we don't re-pick the same dest for every
	// route. Also avoids the worst-case N picks across the same group.
	destByGroup := map[int64]int64{}
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

		dest, ok := destByGroup[c.groupID]
		if !ok {
			var d sql.NullInt64
			err := s.DB.QueryRowContext(ctx,
				`SELECT id FROM caddy_nodes
				 WHERE node_group_id = ? AND id <> ?
				   AND is_enabled = 1 AND approved_at IS NOT NULL
				   AND health_status = 'healthy'
				   AND current_routes < max_routes
				 ORDER BY (current_routes / GREATEST(max_routes,1)) ASC, priority DESC, id ASC
				 LIMIT 1`, c.groupID, c.fromNodeID).Scan(&d)
			if err != nil || !d.Valid {
				s.Logger.Warn("autofailover: no healthy peer in group", "group_id", c.groupID, "route_id", c.id)
				continue
			}
			dest = d.Int64
			destByGroup[c.groupID] = dest
		}

		_, err := s.DB.ExecContext(ctx,
			`UPDATE routes SET caddy_node_id = ?, updated_at = NOW() WHERE id = ?`,
			dest, c.id)
		if err != nil {
			s.Logger.Warn("autofailover: route update", "route_id", c.id, "err", err)
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
	// Bounded concurrency so a slow dest node doesn't stall the others.
	gf, gfctx := errgroup.WithContext(ctx)
	gf.SetLimit(reconcileWorkers)
	for destID, n := range movedByDest {
		destID, n := destID, n
		gf.Go(func() error {
			_, _ = s.DB.ExecContext(gfctx,
				`UPDATE caddy_nodes SET current_routes = current_routes + ? WHERE id = ?`, n, destID)
			if err := s.pushNodeConfig(gfctx, destID); err != nil {
				s.Logger.Warn("autofailover: push to new home failed", "node_id", destID, "err", err)
			}
			return nil
		})
	}
	_ = gf.Wait()
	// Best-effort: also bump down-node counters to reflect moves.
	for _, c := range cands {
		if c.viaPeerID.Valid {
			continue
		}
		_, _ = s.DB.ExecContext(ctx,
			`UPDATE caddy_nodes SET current_routes = GREATEST(0, current_routes - 1) WHERE id = ?`, c.fromNodeID)
	}
}

// Reconcile picks up routes stuck in non-terminal states beyond a grace
// window and re-runs advanceRoute on them. Idempotent - if the route is
// already healthy it's a no-op. Called on a slow ticker (60s).
func (s *Service) Reconcile(ctx context.Context) {
	if s.DB == nil {
		return
	}
	rows, err := s.DB.QueryContext(ctx,
		`SELECT id FROM routes
		 WHERE status IN ('pending_dns','dns_ok','pending_ssl','failed')
		   AND updated_at < (NOW() - INTERVAL 1 MINUTE)
		 ORDER BY updated_at ASC LIMIT 100`)
	if err != nil {
		s.Logger.Warn("reconcile: list stuck routes", "err", err)
		return
	}
	var ids []int64
	for rows.Next() {
		var id int64
		if err := rows.Scan(&id); err == nil {
			ids = append(ids, id)
		}
	}
	rows.Close()
	if len(ids) == 0 {
		return
	}
	s.Logger.Info("reconcile: retry stuck routes", "n", len(ids))
	// Bounded concurrency: advanceRoute does a DNS check + push per route;
	// running 4 at once is safe because pushRouteIncremental/pushNodeConfig take
	// the per-node lock (same-node ops serialize, cross-node parallelize).
	g, gctx := errgroup.WithContext(ctx)
	g.SetLimit(reconcileWorkers)
	for _, id := range ids {
		id := id
		g.Go(func() error {
			if gctx.Err() != nil {
				return nil
			}
			s.advanceRoute(gctx, id)
			return nil
		})
	}
	_ = g.Wait()
}

// ReconcileDrift walks every enabled node, fetches its current Caddy
// route list, computes a fingerprint, and compares to the DB-derived
// expected fingerprint. Mismatch → trigger a full Resync. Cheap when
// routes are stable.
func (s *Service) ReconcileDrift(ctx context.Context) {
	if s.DB == nil {
		return
	}
	rows, err := s.DB.QueryContext(ctx,
		"SELECT id, api_url FROM caddy_nodes WHERE is_enabled = 1")
	if err != nil {
		return
	}
	type node struct {
		id     int64
		apiURL string
	}
	var nodes []node
	for rows.Next() {
		var n node
		if err := rows.Scan(&n.id, &n.apiURL); err == nil {
			nodes = append(nodes, n)
		}
	}
	rows.Close()
	// Probe + resync each node concurrently: the 5s GET plus a possible full
	// /load is otherwise serial, so one slow node delayed the whole sweep.
	sem := make(chan struct{}, pushWorkers)
	var wg sync.WaitGroup
	for _, n := range nodes {
		select {
		case <-ctx.Done():
			wg.Wait()
			return
		case sem <- struct{}{}:
		}
		wg.Add(1)
		go func(n node) {
			defer recoverBg(s.Logger, "reconcileDrift")
			defer wg.Done()
			defer func() { <-sem }()
			expected, err := s.expectedNodeHash(ctx, n.id)
			if err != nil {
				return
			}
			client := caddyapi.New(n.apiURL)
			probeCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
			actualRaw, err := client.GetRaw(probeCtx, "/config/apps/http/servers/srv0/routes")
			cancel()
			if err != nil {
				return
			}
			// Canonicalise before hashing: Caddy may reformat the GET response
			// (map key order, whitespace) so a raw hash flaps even when the
			// route set is identical, triggering an infinite resync loop.
			// Unmarshal+re-marshal gives stable byte output on both sides.
			// Drop infra routes (panel_self, hpg_wstunnel_*) the expected hash
			// never carries - else a panel/WSS node drifts every cycle forever.
			actual := canonHashBytes(filterVirtualRoutes(actualRaw))
			if actual == expected {
				return
			}
			s.Logger.Warn("drift detected, re-pushing", "node_id", n.id, "expected", expected[:12], "actual", actual[:12])
			if s.Metrics != nil {
				s.Metrics.CaddyDriftResync()
			}
			pushCtx, c := context.WithTimeout(ctx, 30*time.Second)
			defer c()
			if err := s.pushNodeConfig(pushCtx, n.id); err != nil {
				s.Logger.Warn("drift resync failed", "node_id", n.id, "err", err)
			}
		}(n)
	}
	wg.Wait()
}

// Resync rebuilds the node's Caddy config from DB and POSTs /load.
// Public wrapper around pushNodeConfig for admin use.
func (s *Service) Resync(ctx context.Context, nodeID int64) error {
	return s.pushNodeConfig(ctx, nodeID)
}

// nodePush is the built, ready-to-Load config for one node plus the data
// loadNodeConfig needs for fingerprinting.
type nodePush struct {
	cfg      map[string]any
	built    []caddyapi.Route
	routeIDs []int64
	apiURL   string
}

// validTunnelHostname accepts only DNS-hostname / IPv4 characters. Rejects
// schemes, IPv6 brackets/colons, and any junk so a bad tunnel_endpoint never
// reaches Caddy JSON (which would fail /load for the whole node).
func validTunnelHostname(h string) bool {
	if h == "" || len(h) > 253 {
		return false
	}
	for _, r := range h {
		if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '.' || r == '-') {
			return false
		}
	}
	return true
}

// buildNodePush renders the full Caddy config for a node from DB. Read-only;
// holds no lock.
func (s *Service) buildNodePush(ctx context.Context, nodeID int64) (*nodePush, error) {
	built, routeIDs, err := s.buildRoutesForNode(ctx, nodeID)
	if err != nil {
		return nil, err
	}
	var (
		apiURL         string
		transport      sql.NullString
		wstunnelPort   sql.NullInt64
		tunnelEndpoint sql.NullString
		tunnelEnabled  bool
		wstHealthy     sql.NullBool
		wstFresh       sql.NullBool
	)
	if err := s.DB.QueryRowContext(ctx,
		`SELECT api_url, tunnel_transport, tunnel_wstunnel_port, tunnel_endpoint, tunnel_enabled,
		        tunnel_wstunnel_healthy,
		        tunnel_wstunnel_reported_at > NOW() - INTERVAL 3 MINUTE
		   FROM caddy_nodes WHERE id = ?`,
		nodeID).Scan(&apiURL, &transport, &wstunnelPort, &tunnelEndpoint, &tunnelEnabled, &wstHealthy, &wstFresh); err != nil {
		return nil, err
	}
	streams := s.buildStreamsForNode(ctx, nodeID)
	branding := s.loadErrorBranding(ctx)
	for i := range built {
		built[i].ErrorBranding = branding
	}

	// Build wstunnel Caddy route when transport is not pure UDP. Fail-closed:
	// a malformed endpoint host (scheme, IPv6, junk) must NOT be emitted into
	// Caddy JSON - that would fail the node's /load and break ALL routes.
	// Also gate on node health: emit only when the node reported a healthy
	// wstunnel recently, OR has not reported yet (just-enabled). A node that
	// reports unhealthy/stale gets no route, so we never advertise dead WSS.
	healthOK := !wstHealthy.Valid || (wstHealthy.Bool && wstFresh.Valid && wstFresh.Bool)
	var wstunnelRoute *caddyapi.WstunnelRoute
	if tunnelEnabled && transport.String != "" && transport.String != "udp" && wstunnelPort.Valid &&
		wstunnelPort.Int64 > 0 && wstunnelPort.Int64 < 65536 && tunnelEndpoint.Valid && healthOK {
		hostname, _, _ := net.SplitHostPort(tunnelEndpoint.String)
		if hostname == "" {
			hostname = tunnelEndpoint.String
		}
		if validTunnelHostname(hostname) {
			wstunnelRoute = &caddyapi.WstunnelRoute{
				NodeID:   nodeID,
				Hostname: hostname,
				Port:     int(wstunnelPort.Int64),
			}
		} else {
			s.Logger.Warn("skipping wstunnel route: invalid tunnel endpoint host",
				"node_id", nodeID)
		}
	}

	cfg := caddyapi.BuildNodeConfig(built, caddyapi.NodeSettings{
		ACMEEmail:                s.ACMEEmail,
		ACMEStaging:              s.ACMEStaging,
		AskURL:                   s.AskURL,
		PanelRoute:               s.panelRoute(),
		CacheModuleAvailable:     s.CacheModuleAvailable,
		Layer4ModuleAvailable:    s.Layer4ModuleAvailable,
		RateLimitModuleAvailable: s.RateLimitModuleAvailable,
		WAFModuleAvailable:       s.WAFModuleAvailable,
		DNS01ModuleAvailable:     s.DNS01ModuleAvailable,
		WildcardPolicies:         s.buildWildcardPolicies(ctx, nodeID),
		StreamRoutes:             streams,
		ErrorBranding:            branding,
		WstunnelRoute:            wstunnelRoute,
	})
	return &nodePush{cfg: cfg, built: built, routeIDs: routeIDs, apiURL: apiURL}, nil
}

// loadNodeConfig POSTs the full config (/load) and records the per-route drift
// fingerprint. The caller MUST hold the per-node lock.
func (s *Service) loadNodeConfig(ctx context.Context, nodeID int64, np *nodePush) error {
	client := caddyapi.New(np.apiURL)
	if err := client.Load(ctx, np.cfg); err != nil {
		s.Logger.Error("caddy push failed", "node_id", nodeID, "err", err)
		if s.Metrics != nil {
			s.Metrics.CaddyPushFail()
		}
		return err
	}
	if s.Metrics != nil {
		s.Metrics.CaddyPushOK()
	}
	pushHash := hashRoutes(np.built)
	for _, id := range np.routeIDs {
		_, _ = s.DB.ExecContext(ctx,
			"UPDATE routes SET last_pushed_at = NOW(), last_pushed_hash = ? WHERE id = ?",
			pushHash, id)
	}
	s.Logger.Info("caddy push ok", "node_id", nodeID, "routes", len(np.built), "hash", pushHash[:12])
	return nil
}

// pushNodeConfig builds the config OUTSIDE the per-node lock (read-only), then
// locks only around the network Load. Stops one slow node serializing every
// push to it.
func (s *Service) pushNodeConfig(ctx context.Context, nodeID int64) error {
	np, err := s.buildNodePush(ctx, nodeID)
	if err != nil {
		return err
	}
	lock := s.nodeLock(nodeID)
	lock.Lock()
	defer lock.Unlock()
	return s.loadNodeConfig(ctx, nodeID, np)
}

// pushNodeConfigLocked is the full-/load fallback for callers that ALREADY hold
// the per-node lock (pushRouteIncremental). Builds under the held lock; the
// minor cost only applies on the rare incremental-fallback path.
func (s *Service) pushNodeConfigLocked(ctx context.Context, nodeID int64) error {
	np, err := s.buildNodePush(ctx, nodeID)
	if err != nil {
		return err
	}
	return s.loadNodeConfig(ctx, nodeID, np)
}

type routeOp int

const (
	routeUpsert routeOp = iota // add if absent, replace if present
	routeRemove                // delete by @id
)

// isNotFound reports whether a Caddy client error is a 404 (already gone).
func isNotFound(err error) bool {
	return err != nil && strings.Contains(err.Error(), "404")
}

// buildOneRoute returns the built, emit-ready Route for routeID on nodeID and
// whether it is eligible to be emitted. It reuses buildRoutesForNode (then
// filters) so the emitted object is byte-identical to a full /load element -
// which keeps drift hashing consistent. ok=false means the route is in DB but
// filtered out (not active, revoked tunnel, disallowed external, undecryptable
// secret) and should therefore be absent on the node.
func (s *Service) buildOneRoute(ctx context.Context, nodeID, routeID int64) (caddyapi.Route, bool, error) {
	built, ids, err := s.buildRoutesForNode(ctx, nodeID)
	if err != nil {
		return caddyapi.Route{}, false, err
	}
	branding := s.loadErrorBranding(ctx)
	for i, id := range ids {
		if id == routeID {
			r := built[i]
			// Match what BuildNodeConfig sets per-route on a full /load so the
			// emitted JSON is identical (drift consistency). Missing any of
			// these would both suppress the handler on incremental pushes AND
			// make the hash diverge from full-load → endless resync.
			r.ErrorBranding = branding
			r.CacheModuleAvailable = s.CacheModuleAvailable
			r.RateLimitModuleAvailable = s.RateLimitModuleAvailable
			r.WAFModuleAvailable = s.WAFModuleAvailable
			return r, true, nil
		}
	}
	return caddyapi.Route{}, false, nil
}

// routeMatchHosts extracts the host strings from a Caddy route object's match[].
func routeMatchHosts(obj map[string]any) []string {
	matches, _ := obj["match"].([]any)
	var out []string
	for _, m := range matches {
		mm, _ := m.(map[string]any)
		hs, _ := mm["host"].([]any)
		for _, h := range hs {
			if str, ok := h.(string); ok {
				out = append(out, str)
			}
		}
	}
	return out
}

// routePresenceAndHostClash GETs the node's route array and reports whether
// route_<routeID> is already present, and whether any OTHER route shares a host
// with `hosts` (in which case a POST-append could mis-order path-vs-root match
// and we must fall back to a full /load to preserve deterministic id-order).
func (s *Service) routePresenceAndHostClash(ctx context.Context, client *caddyapi.Client, routeID int64, hosts []string) (present, sharesHost bool, err error) {
	raw, err := client.GetRaw(ctx, "/config/apps/http/servers/srv0/routes")
	if err != nil {
		return false, false, err
	}
	trimmed := strings.TrimSpace(string(raw))
	if trimmed == "" || trimmed == "null" {
		return false, false, nil // no routes on the node yet
	}
	var arr []map[string]any
	if err := json.Unmarshal(raw, &arr); err != nil {
		return false, false, err
	}
	caddyID := fmt.Sprintf("route_%d", routeID)
	want := make(map[string]bool, len(hosts))
	for _, h := range hosts {
		want[h] = true
	}
	for _, obj := range arr {
		if id, _ := obj["@id"].(string); id == caddyID {
			present = true
			continue
		}
		for _, h := range routeMatchHosts(obj) {
			if want[h] {
				sharesHost = true
			}
		}
	}
	return present, sharesHost, nil
}

// pushRouteIncremental applies a single-route change to one node via Caddy @id
// endpoints, avoiding a whole-config /load. ANY failure (probe, build, HTTP, or
// an unsafe-ordering condition) falls back to a full pushNodeConfigLocked so
// behavior is never worse than a /load. last_pushed_hash is intentionally not
// rewritten here (it is write-only/unused; drift rebuilds from DB and the
// incremental object is byte-identical to a /load element, so drift is unaffected).
func (s *Service) pushRouteIncremental(ctx context.Context, nodeID, routeID int64, op routeOp) error {
	if !s.IncrementalPush {
		return s.pushNodeConfig(ctx, nodeID)
	}
	// Wildcard routes drive tls.automation.policies, which lives outside the
	// per-route @id surface; an incremental op would never emit the DNS-01
	// policy. Force a full /load so the policy set re-derives. Cheap (rare).
	if s.routeIsWildcard(ctx, routeID) {
		return s.pushNodeConfig(ctx, nodeID)
	}
	var apiURL string
	if err := s.DB.QueryRowContext(ctx, "SELECT api_url FROM caddy_nodes WHERE id = ?", nodeID).Scan(&apiURL); err != nil {
		return err
	}
	client := caddyapi.New(apiURL)
	caddyID := fmt.Sprintf("route_%d", routeID)

	lock := s.nodeLock(nodeID)
	lock.Lock()
	defer lock.Unlock()

	switch op {
	case routeRemove:
		if err := client.DeleteRoute(ctx, caddyID); err != nil {
			if isNotFound(err) {
				return nil // already gone == desired state
			}
			s.Logger.Warn("incremental delete failed, full resync", "node_id", nodeID, "route_id", routeID, "err", err)
			return s.pushNodeConfigLocked(ctx, nodeID)
		}
		return nil

	case routeUpsert:
		built, ok, berr := s.buildOneRoute(ctx, nodeID, routeID)
		if berr != nil {
			return s.pushNodeConfigLocked(ctx, nodeID)
		}
		if !ok {
			// Not eligible: ensure it is absent on the node, then done.
			if derr := client.DeleteRoute(ctx, caddyID); derr != nil && !isNotFound(derr) {
				return s.pushNodeConfigLocked(ctx, nodeID)
			}
			return nil
		}
		obj := caddyapi.BuildRoute(built)
		present, sharesHost, perr := s.routePresenceAndHostClash(ctx, client, routeID, built.Hosts)
		switch {
		case perr != nil:
			return s.pushNodeConfigLocked(ctx, nodeID)
		case present:
			// Replace in place (preserves index/order) - shape-agnostic.
			if err := client.ReplaceRoute(ctx, caddyID, obj); err != nil {
				s.Logger.Warn("incremental replace failed, full resync", "node_id", nodeID, "route_id", routeID, "err", err)
				return s.pushNodeConfigLocked(ctx, nodeID)
			}
		case sharesHost:
			return s.pushNodeConfigLocked(ctx, nodeID) // keep deterministic order
		default:
			if err := client.AddRoute(ctx, obj); err != nil {
				s.Logger.Warn("incremental add failed, full resync", "node_id", nodeID, "route_id", routeID, "err", err)
				return s.pushNodeConfigLocked(ctx, nodeID)
			}
		}
		if s.Metrics != nil {
			s.Metrics.CaddyPushOK()
		}
		return nil
	}
	return nil
}

// loadErrorBranding pulls the per-install branding bits used by
// Caddy-served error / maintenance pages. Empty struct on any failure
// so the renderer falls back to neutral defaults rather than panicking
// the resync.
func (s *Service) loadErrorBranding(ctx context.Context) caddyapi.ErrorBranding {
	b := caddyapi.ErrorBranding{}
	if s.DB == nil {
		return b
	}
	c, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	rows, err := s.DB.QueryContext(c,
		"SELECT `key`, value FROM settings WHERE `key` IN ("+
			"'branding.brand_name',"+
			"'branding.error_logo_url','branding.error_logo_link','branding.error_bg_color')")
	if err != nil {
		return b
	}
	defer rows.Close()
	for rows.Next() {
		var k, v string
		if err := rows.Scan(&k, &v); err != nil {
			continue
		}
		switch k {
		case "branding.brand_name":
			b.Brand = v
		case "branding.error_logo_url":
			b.LogoURL = v
		case "branding.error_logo_link":
			b.LogoLink = v
		case "branding.error_bg_color":
			b.BgColor = v
		}
	}
	return b
}

// buildRoutesForNode collects every active/dns_ok/pending_ssl route placed on
// the given node, applies plan overrides, and returns Caddy route structs.
func (s *Service) buildRoutesForNode(ctx context.Context, nodeID int64) ([]caddyapi.Route, []int64, error) {
	rows, err := s.DB.QueryContext(ctx,
		`SELECT r.id, r.domain, COALESCE(r.aliases,''), r.path_prefix, r.upstream_port, r.upstream_scheme, r.upstream_skip_tls_verify,
		        r.websocket, r.force_https,
		        r.http2_enabled, r.http3_enabled, r.ssl_enabled,
		        -- Per-route backend_ip_override beats both peer IP and the
		        -- shared service backend_ip, so editing one route doesn't
		        -- change every sibling route that JOINs the same service.
		        COALESCE(NULLIF(r.backend_ip_override, ''), p_use.assigned_ip, sv.backend_ip),
		        COALESCE(p_use.assigned_ip, ''),
		        r.kind, COALESCE(r.redirect_url,''), COALESCE(r.redirect_code,0),
		        r.cache_enabled, r.cache_ttl_secs, COALESCE(r.custom_headers,''),
		        r.maintenance_mode, COALESCE(r.maintenance_message,''),
		        COALESCE(r.cache_vary,''),
		        COALESCE(r.access_allow,''), COALESCE(r.access_deny,''),
		        COALESCE(r.access_block_all, 0), COALESCE(r.maintenance_allow,''),
		        COALESCE(r.custom_config,''),
		        r.via_wg_peer_id, p_use.status,
		        COALESCE(r.basic_auth_user,''), COALESCE(r.basic_auth_bcrypt,''),
		        COALESCE(r.sso_provider_url,''), COALESCE(r.sso_copy_headers,''), COALESCE(r.sso_trusted_proxies,''),
		        COALESCE(r.sso_paths,''), COALESCE(r.sso_hosts,''),
		        COALESCE(sso_peer.assigned_ip, ''),
	        COALESCE(r.upstream_external, 0), COALESCE(r.upstream_host_header, ''), COALESCE(r.proxy_secret_enc, ''),
	        COALESCE(r.compress_disabled, 0),
	        COALESCE(r.lb_policy,''),
	        COALESCE(r.health_active_uri,''), COALESCE(r.health_active_interval,10), COALESCE(r.health_active_timeout,5),
	        COALESCE(r.health_active_status,0), COALESCE(r.health_active_fails,3),
	        COALESCE(r.health_passive_enabled,0), COALESCE(r.health_passive_fail_dur,30), COALESCE(r.health_passive_max_fail,3),
	        COALESCE(r.rate_enabled,0), COALESCE(r.rate_window,''), COALESCE(r.rate_max_events,0), COALESCE(r.rate_key,''),
	        COALESCE(r.waf_enabled,0), COALESCE(r.waf_blocking,0), COALESCE(r.waf_directives,''),
	        COALESCE(r.error_override,0), COALESCE(r.error_html,''), COALESCE(r.error_logo_url,''),
	        COALESCE(r.error_brand,''), COALESCE(r.error_bg_color,'')
		 FROM routes r
		 JOIN services sv ON sv.id = r.service_id
		 LEFT JOIN customer_wg_peer p_base
		   ON p_base.id = r.via_wg_peer_id
		 LEFT JOIN customer_wg_peer p_use ON (
		     (p_base.peer_group_id IS NOT NULL
		         AND p_use.peer_group_id = p_base.peer_group_id
		         AND p_use.node_id = r.caddy_node_id
		         AND p_use.status <> 'revoked')
		     OR (p_base.peer_group_id IS NULL
		         AND p_use.id = r.via_wg_peer_id
		         AND p_use.status <> 'revoked')
		 )
		 LEFT JOIN customer_wg_peer sso_peer
		   ON sso_peer.id = r.sso_via_wg_peer_id
		      AND sso_peer.status <> 'revoked'
		 WHERE r.caddy_node_id = ? AND r.status IN ('dns_ok','active','pending_ssl')
		 ORDER BY r.id ASC`, nodeID)
	if err != nil {
		return nil, nil, err
	}
	defer rows.Close()

	var built []caddyapi.Route
	var ids []int64
	for rows.Next() {
		var (
			id                             int64
			domain, aliases                string
			path                           string
			port                           int
			scheme                         string
			skipTLS                        bool
			ws, fhttps, h2, h3, sslEnabled bool
			ip                             string
			tunnelResolverIP               string
			kind                           string
			redirURL                       string
			redirCode                      int
			cacheEnabled                   bool
			cacheTTL                       int
			headersJSON                    string
			maintMode                      bool
			maintMsg                       string
			cacheVary                      string
			accessAllow                    string
			accessDeny                     string
			accessBlockAll                 bool
			maintenanceAllow               string
			customCfg                      string
		)
		var viaPeerID sql.NullInt64
		var peerStatus sql.NullString
		var baUser, baHash string
		var ssoProviderURL, ssoCopyHeadersRaw, ssoTrustedProxies string
		var ssoPathsRaw, ssoHostsRaw string
		var ssoResolverIP string
		var upstreamExternal bool
		var upstreamHostHeader, proxySecretEnc string
		var compressDisabled bool
		var lbPolicy string
		var hActiveURI string
		var hActiveInterval, hActiveTimeout, hActiveStatus, hActiveFails int
		var hPassiveEnabled bool
		var hPassiveFailDur, hPassiveMaxFail int
		var rateEnabled bool
		var rateWindow, rateKey string
		var rateMaxEvents int
		var wafEnabled, wafBlocking bool
		var wafDirectives string
		var errOverride bool
		var errHTML, errLogo, errBrand, errBg string
		if err := rows.Scan(&id, &domain, &aliases, &path, &port, &scheme, &skipTLS, &ws, &fhttps, &h2, &h3, &sslEnabled, &ip,
			&tunnelResolverIP,
			&kind, &redirURL, &redirCode, &cacheEnabled, &cacheTTL, &headersJSON,
			&maintMode, &maintMsg, &cacheVary, &accessAllow, &accessDeny,
			&accessBlockAll, &maintenanceAllow, &customCfg,
			&viaPeerID, &peerStatus, &baUser, &baHash,
			&ssoProviderURL, &ssoCopyHeadersRaw, &ssoTrustedProxies,
			&ssoPathsRaw, &ssoHostsRaw,
			&ssoResolverIP,
			&upstreamExternal, &upstreamHostHeader, &proxySecretEnc,
			&compressDisabled,
			&lbPolicy,
			&hActiveURI, &hActiveInterval, &hActiveTimeout, &hActiveStatus, &hActiveFails,
			&hPassiveEnabled, &hPassiveFailDur, &hPassiveMaxFail,
			&rateEnabled, &rateWindow, &rateMaxEvents, &rateKey,
			&wafEnabled, &wafBlocking, &wafDirectives,
			&errOverride, &errHTML, &errLogo, &errBrand, &errBg); err != nil {
			return nil, nil, err
		}
		var ssoCopyHeaders []string
		for _, h := range strings.FieldsFunc(ssoCopyHeadersRaw, func(r rune) bool { return r == '\n' || r == '\r' || r == ',' }) {
			if v := strings.TrimSpace(h); v != "" {
				ssoCopyHeaders = append(ssoCopyHeaders, v)
			}
		}
		var ssoTrusted []string
		for _, p := range strings.FieldsFunc(ssoTrustedProxies, func(r rune) bool { return r == ',' || r == ' ' || r == '\t' }) {
			if v := strings.TrimSpace(p); v != "" {
				ssoTrusted = append(ssoTrusted, v)
			}
		}
		// Skip routes pointing at a missing or revoked tunnel rather than
		// silently falling back to the static backend_ip - Caddy returning
		// 502 is preferable to "huh, my traffic suddenly bypassed the VPN".
		if viaPeerID.Valid && (!peerStatus.Valid || peerStatus.String == "revoked") {
			s.Logger.Warn("skipping route with revoked/missing tunnel",
				"route_id", id, "domain", domain, "peer_id", viaPeerID.Int64)
			continue
		}
		hosts := []string{domain}
		for _, a := range strings.FieldsFunc(aliases, func(r rune) bool {
			return r == ',' || r == ' ' || r == '\t' || r == '\n' || r == '\r' || r == ';'
		}) {
			if v := strings.ToLower(strings.TrimSpace(a)); v != "" && v != domain {
				hosts = append(hosts, v)
			}
		}
		var vary []string
		if cacheVary != "" {
			for _, p := range strings.Split(cacheVary, ",") {
				if v := strings.TrimSpace(p); v != "" {
					vary = append(vary, v)
				}
			}
		}
		splitCIDRs := func(s string) []string {
			if s == "" {
				return nil
			}
			out := []string{}
			for _, p := range strings.FieldsFunc(s, func(r rune) bool {
				return r == ',' || r == ' ' || r == '\t' || r == '\n' || r == '\r'
			}) {
				if v := strings.TrimSpace(p); v != "" {
					out = append(out, v)
				}
			}
			return out
		}
		allowList := splitCIDRs(accessAllow)
		denyList := splitCIDRs(accessDeny)
		maintAllowList := splitCIDRs(maintenanceAllow)
		if !sslEnabled {
			fhttps = false
		}
		var headers map[string]string
		if headersJSON != "" {
			_ = json.Unmarshal([]byte(headersJSON), &headers)
		}
		// Hostname-via-tunnel-DNS feature is disabled at build time.
		// External route: the upstream FQDN (ip) is intentionally a hostname,
		// re-enforce the allowlist and decrypt the inbound bearer. Skip the
		// route entirely (never emit an ungated/disallowed external proxy)
		// if either fails - an emitted route without its gate is an open relay.
		external := upstreamExternal
		proxySecret := ""
		if external {
			if !s.externalHostAllowed(ip) {
				s.Logger.Warn("external route host not allowlisted, skipping", "route_id", id, "host", ip)
				continue
			}
			if proxySecretEnc != "" {
				if s.DecryptSecret == nil {
					s.Logger.Error("external route secret undecryptable (no key), skipping", "route_id", id)
					continue
				}
				sec, derr := s.DecryptSecret(proxySecretEnc)
				if derr != nil {
					s.Logger.Error("external route secret decrypt failed, skipping", "route_id", id, "err", derr)
					continue
				}
				proxySecret = sec
			}
		}
		// Defense in depth: if the DB still contains a hostname override
		// from before the validation landed, drop it back to peer IP so
		// the route doesn't 502 on an unresolvable name. External routes are
		// exempt - their upstream is meant to be a public FQDN.
		if !external && tunnelResolverIP != "" && ip != "" && !looksLikeIP(ip) {
			ip = tunnelResolverIP
		}
		backendResolver := ""
		built = append(built, caddyapi.Route{
			ID:                    fmt.Sprintf("%d", id),
			Hosts:                 hosts,
			PathPrefix:            path,
			UpstreamIP:            ip,
			UpstreamPort:          port,
			BackendResolver:       backendResolver,
			UpstreamScheme:        scheme,
			UpstreamSkipTLSVerify: skipTLS,
			WebSocket:             ws,
			ForceHTTPS:            fhttps,
			HTTP2:                 h2,
			HTTP3:                 h3,
			Headers:               headers,
			Kind:                  kind,
			RedirectURL:           redirURL,
			RedirectCode:          redirCode,
			CacheEnabled:          cacheEnabled,
			CacheTTLSeconds:       cacheTTL,
			CacheVary:             vary,
			MaintenanceMode:       maintMode,
			MaintenanceMessage:    maintMsg,
			AccessAllow:           allowList,
			AccessDeny:            denyList,
			AccessBlockAll:        accessBlockAll,
			MaintenanceAllow:      maintAllowList,
			CustomHandlers:        customCfg,
			BasicAuthUser:         baUser,
			BasicAuthBcrypt:       baHash,
			SSOProviderURL:        ssoProviderURL,
			SSOCopyHeaders:        ssoCopyHeaders,
			SSOTrustedProxies:     ssoTrusted,
			SSOPaths:              splitCIDRs(ssoPathsRaw),
			SSOHosts:              splitCIDRs(ssoHostsRaw),
			// SSO-via-tunnel: peer IP is used as static dial host (port
			// comes from SSO Provider URL). No DNS lookup attempted - peer
			// must expose the IdP port on its host network.
			SSOResolver: ssoResolverIP,

			// External HTTPS upstream: SNI + Host both use the stored header
			// (falls back to the FQDN in the builder); ProxySecret gates inbound.
			External:               external,
			UpstreamSNI:            upstreamHostHeader,
			UpstreamHostHeader:     upstreamHostHeader,
			ProxySecret:            proxySecret,
			CompressDisabled:       compressDisabled,
			LBPolicy:               lbPolicy,
			WeightedLBAvailable:    s.WeightedLBAvailable,
			HealthURI:              hActiveURI,
			HealthIntervalSecs:     hActiveInterval,
			HealthTimeoutSecs:      hActiveTimeout,
			HealthExpectStatus:     hActiveStatus,
			HealthFails:            hActiveFails,
			HealthPassive:          hPassiveEnabled,
			HealthFailDurationSecs: hPassiveFailDur,
			HealthMaxFails:         hPassiveMaxFail,

			RateLimitEnabled:         rateEnabled,
			RateLimitWindow:          rateWindow,
			RateLimitMaxEvents:       rateMaxEvents,
			RateLimitKey:             rateKey,
			RateLimitModuleAvailable: s.RateLimitModuleAvailable,
			WAFEnabled:               wafEnabled,
			WAFBlocking:              wafBlocking,
			WAFDirectives:            wafDirectives,
			WAFModuleAvailable:       s.WAFModuleAvailable,

			// Per-route error/maintenance page override (else node-wide branding).
			CustomErrorOverride: errOverride,
			CustomErrorHTML:     errHTML,
			CustomErrorBranding: caddyapi.ErrorBranding{LogoURL: errLogo, Brand: errBrand, BgColor: errBg},
		})
		ids = append(ids, id)
	}
	// Attach additional backends (route_upstreams) in one batched query to
	// avoid N+1; zero-row routes keep their single-dial primary. Best-effort:
	// a query error leaves routes single-dial rather than failing the build.
	s.attachRouteUpstreams(ctx, built, ids)
	return built, ids, nil
}

// attachRouteUpstreams fills caddyapi.Route.Upstreams for the built routes via
// a single IN(...) query over route_upstreams, ordered positionally so
// weighted_round_robin weights stay aligned with the emitted dial order.
func (s *Service) attachRouteUpstreams(ctx context.Context, built []caddyapi.Route, ids []int64) {
	if len(ids) == 0 {
		return
	}
	idx := make(map[int64]int, len(ids))
	ph := make([]string, len(ids))
	args := make([]any, len(ids))
	for i, id := range ids {
		idx[id] = i
		ph[i] = "?"
		args[i] = id
	}
	rows, err := s.DB.QueryContext(ctx,
		`SELECT route_id, host, port, weight FROM route_upstreams
		 WHERE route_id IN (`+strings.Join(ph, ",")+`)
		 ORDER BY route_id, sort_order ASC, id ASC`, args...)
	if err != nil {
		if s.Logger != nil {
			s.Logger.Warn("route_upstreams load failed; routes stay single-dial", "err", err)
		}
		return
	}
	defer rows.Close()
	for rows.Next() {
		var rid int64
		var host string
		var port, weight int
		if err := rows.Scan(&rid, &host, &port, &weight); err != nil {
			continue
		}
		if i, ok := idx[rid]; ok {
			built[i].Upstreams = append(built[i].Upstreams, caddyapi.Upstream{Host: host, Port: port, Weight: weight})
		}
	}
}

// buildStreamsForNode reads the stream_routes table for one node and
// returns caddyapi.StreamRoute values ready for the L4 builder. Joins on
// services for the backend_ip (admin-only field - stream routes never
// expose this to the customer).
func (s *Service) buildStreamsForNode(ctx context.Context, nodeID int64) []caddyapi.StreamRoute {
	rows, err := s.DB.QueryContext(ctx,
		`SELECT sr.id, sr.protocol, sr.listen_port, sr.upstream_port, sv.backend_ip
		 FROM stream_routes sr JOIN services sv ON sv.id = sr.service_id
		 WHERE sr.caddy_node_id = ? AND sr.status = 'active'
		 ORDER BY sr.listen_port ASC`, nodeID)
	if err != nil {
		return nil
	}
	defer rows.Close()
	var out []caddyapi.StreamRoute
	for rows.Next() {
		var r caddyapi.StreamRoute
		if err := rows.Scan(&r.ID, &r.Protocol, &r.ListenPort, &r.UpstreamPort, &r.UpstreamIP); err == nil {
			out = append(out, r)
		}
	}
	return out
}

// buildWildcardPolicies returns one WildcardPolicy per DISTINCT zone among
// this node's active wildcard routes that has a dns_providers row. The
// credential is decrypted here; a zone whose secret is missing/undecryptable
// or whose provider is unsupported is SKIPPED (logged, zone only) so the node
// never emits a DNS-01 policy without a working credential - which would fail
// the entire /load. Returns nil when the gate is off (default).
func (s *Service) buildWildcardPolicies(ctx context.Context, nodeID int64) []caddyapi.WildcardPolicy {
	if !s.DNS01ModuleAvailable || s.DecryptSecret == nil {
		return nil
	}
	rows, err := s.DB.QueryContext(ctx,
		`SELECT DISTINCT dp.name, dp.provider, dp.api_token_enc
		   FROM routes r
		   JOIN dns_providers dp ON dp.name = r.wildcard_zone
		  WHERE r.caddy_node_id = ?
		    AND r.wildcard_enabled = 1
		    AND r.status IN ('dns_ok','active','pending_ssl')
		  ORDER BY dp.name ASC`, nodeID)
	if err != nil {
		return nil
	}
	defer rows.Close()
	var out []caddyapi.WildcardPolicy
	for rows.Next() {
		var zone, provider, enc string
		if err := rows.Scan(&zone, &provider, &enc); err != nil {
			continue
		}
		if _, ok := caddyapi.DNSProviderBySlug(provider); !ok {
			s.Logger.Warn("wildcard: unsupported provider, skipping", "zone", zone, "provider", provider)
			continue
		}
		blob, derr := s.DecryptSecret(enc)
		if derr != nil || blob == "" {
			s.Logger.Error("wildcard: credential decrypt failed, skipping zone", "zone", zone)
			continue
		}
		// Decode the JSON field map; legacy cloudflare rows hold a bare token.
		fields := caddyapi.DecodeDNSFields(provider, blob)
		if len(fields) == 0 {
			s.Logger.Error("wildcard: credential blob unusable, skipping zone", "zone", zone)
			continue
		}
		out = append(out, caddyapi.WildcardPolicy{Zone: zone, Provider: provider, Fields: fields})
	}
	return out
}

// routeIsWildcard reports whether routeID has wildcard DNS-01 enabled. Used to
// force a full /load (policy set lives outside the incremental @id surface).
// Best-effort: any error returns false (caller proceeds with the normal path).
func (s *Service) routeIsWildcard(ctx context.Context, routeID int64) bool {
	var enabled bool
	if err := s.DB.QueryRowContext(ctx,
		"SELECT wildcard_enabled FROM routes WHERE id = ?", routeID).Scan(&enabled); err != nil {
		return false
	}
	return enabled
}

// hashRoutes returns a stable SHA-256 over the deterministic JSON shape Caddy
// would receive for these routes. Order is fixed by buildRoutesForNode.
func hashRoutes(rs []caddyapi.Route) string {
	objs := make([]map[string]any, 0, len(rs))
	for _, r := range rs {
		objs = append(objs, caddyapi.BuildRoute(r))
	}
	b, _ := json.Marshal(objs)
	return hashBytes(b)
}

func hashBytes(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

// canonHashBytes unmarshals JSON then re-marshals so the hash is stable
// across Caddy admin GET reformatting (Go map keys sort on Marshal).
// Uses json.Decoder + UseNumber so port/ID values above 2^53 keep
// integer precision; the default float64 path otherwise flaps the
// hash and triggers infinite drift resync.
// filterVirtualRoutes drops infra routes (panel self-route, wstunnel WSS route)
// from a Caddy srv0/routes array so drift compares only customer routes, which
// is all expectedNodeHash builds. BuildRoute emits @id="route_"+ID, so the panel
// route (ID "panel_self") lands as "route_panel_self"; the wstunnel route is
// built directly as "hpg_wstunnel_*". Customer routes are "route_<numeric>" and
// are kept. Leaves input untouched if it's not the expected array.
func filterVirtualRoutes(raw []byte) []byte {
	var arr []json.RawMessage
	if err := json.Unmarshal(raw, &arr); err != nil {
		return raw
	}
	out := arr[:0]
	for _, r := range arr {
		var probe struct {
			ID string `json:"@id"`
		}
		_ = json.Unmarshal(r, &probe)
		if probe.ID == "route_panel_self" || strings.HasPrefix(probe.ID, "hpg_") {
			continue
		}
		out = append(out, r)
	}
	b, err := json.Marshal(out)
	if err != nil {
		return raw
	}
	return b
}

func canonHashBytes(b []byte) string {
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.UseNumber()
	var v any
	if err := dec.Decode(&v); err != nil {
		return hashBytes(b)
	}
	canon, err := json.Marshal(v)
	if err != nil {
		return hashBytes(b)
	}
	return hashBytes(canon)
}

// expectedNodeHash computes the canonical-format hash of the Caddy routes
// array Caddy would currently expose, derived from the DB. The drift probe
// compares this to whatever Caddy actually returns over the admin API.
func (s *Service) expectedNodeHash(ctx context.Context, nodeID int64) (string, error) {
	built, _, err := s.buildRoutesForNode(ctx, nodeID)
	if err != nil {
		return "", err
	}
	return hashRoutes(built), nil
}

// ensureStableHash is a helper used in tests; not called from production.
func ensureStableHash(rs []caddyapi.Route) string {
	dup := make([]caddyapi.Route, len(rs))
	copy(dup, rs)
	sort.Slice(dup, func(i, j int) bool { return dup[i].ID < dup[j].ID })
	return hashRoutes(dup)
}

func validDomain(d string) bool {
	if len(d) == 0 || len(d) > 253 {
		return false
	}
	if net.ParseIP(d) != nil {
		return false // IPs not allowed as hostnames
	}
	if strings.Contains(d, "..") {
		return false
	}
	if !strings.Contains(d, ".") {
		return false
	}
	for _, c := range d {
		switch {
		case c >= 'a' && c <= 'z',
			c >= 'A' && c <= 'Z',
			c >= '0' && c <= '9',
			c == '-', c == '.':
		default:
			return false
		}
	}
	// Each DNS label: 1-63 chars, no leading or trailing hyphen (RFC 1035 §2.3.1).
	for _, label := range strings.Split(d, ".") {
		if len(label) == 0 || len(label) > 63 {
			return false
		}
		if label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
	}
	return true
}

// looksLikeIP reports whether s parses as IPv4/IPv6 (not a hostname).
func looksLikeIP(s string) bool {
	return net.ParseIP(strings.TrimSpace(s)) != nil
}

func truncErr(e error) string {
	s := e.Error()
	if len(s) > 240 {
		s = s[:240] + "..."
	}
	return s
}
