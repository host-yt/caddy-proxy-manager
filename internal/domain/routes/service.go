// Package routes owns the route lifecycle: validation, node placement,
// DNS pre-check, Caddy push.
//
// The package is split by concern, all in one package so nothing here needs an
// interface just to talk to itself:
//
//	service.go    the Service type, its wiring and the errors handlers match on
//	lifecycle.go  create / verify / delete and the state machine that advances a route
//	build.go      turning DB rows into Caddy route JSON for one node
//	streams.go    the same for L4 streams, including destination screening
//	push.go       getting that config onto a node: generations, locking, drift
//	health.go     node health probing and automatic failover
//	util.go       small shared helpers
package routes

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"log/slog"
	"runtime/debug"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/host-yt/caddy-proxy-manager/internal/caddyapi"
	"github.com/host-yt/caddy-proxy-manager/internal/quota"
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
	// ACMECaURL / ACMEEabKID / ACMEEabHMAC mirror caddyapi.NodeSettings fields.
	ACMECaURL   string
	ACMEEabKID  string
	ACMEEabHMAC string

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

	// GeoModuleAvailable gates per-route geo blocking (caddy-maxmind-geolocation).
	// Env GEOIP_AVAILABLE=1; same never-flip-early footgun as WAF/DNS01.
	GeoModuleAvailable bool

	// PanelPublicHost / PanelInternalHost / PanelInternalPort drive the
	// self-bootstrap route prepended to every node's Caddy config. When
	// PanelPublicHost is empty the bootstrap route is skipped (e.g. APP_URL
	// not configured yet, or operator opted out).
	PanelPublicHost   string
	PanelInternalHost string
	PanelInternalPort int

	// AccessLogURL, when non-empty, configures every node's Caddy to forward
	// structured access logs (JSON, one per request) to this HPG endpoint.
	// Typically "http://app:8080/internal/access-log" on the internal Docker
	// network. Empty = logs stay on Caddy stderr.
	AccessLogURL string

	// CaddyAdminListen overrides the node Caddy Admin API bind (CADDY-03).
	// Empty = "0.0.0.0:2019" (docker-bridge-scoped default). From env
	// HPG_CADDY_ADMIN_LISTEN.
	CaddyAdminListen string

	// Quota is optional. When set, route creation is bounded by the owning
	// reseller's aggregate package (domains, overselling mode). Nil = no limits.
	Quota *quota.Service

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

	// MTLSRBACKey is the MAC key for the per-(node, route) mTLS RBAC check
	// token embedded in each node's Caddy config. Derived from APP_SECRET by
	// the caller; empty disables token issuance.
	MTLSRBACKey []byte

	// DecryptNodeSecret opens values encrypted with the panel's unscoped state
	// key: today the per-node admin-proxy key written by the tunnel enable /
	// rotate flow. Nil disables agent-fronted admin access (nodes are then
	// reached directly).
	DecryptNodeSecret func(string) (string, error)

	// ExternalUpstreamAllowlist is the set of FQDNs an External proxy route
	// may target (exact host, case-insensitive). Empty = no external route is
	// permitted. Enforced at Create AND again at build time (defense in depth).
	ExternalUpstreamAllowlist []string

	// AfterPush, when set, is called after every successful PushAll so the
	// caller can fan out to slave HPG instances (instasync). Nil-safe.
	AfterPush func(ctx context.Context)

	// IncrementalPush enables per-route Caddy @id mutations (PATCH/POST/DELETE)
	// for single-route changes instead of a full /load. Kill switch: env
	// INCREMENTAL_PATCH=0 reverts to full /load with no code change. Every
	// incremental op already falls back to /load on any error.
	IncrementalPush bool

	// PushDebounceMs is the coalesce window for per-node config pushes.
	// Multiple push requests within the window collapse to one push fired
	// when the timer expires. 0 disables debouncing (immediate push).
	// Env: HPG_PUSH_DEBOUNCE_MS (default 500).
	PushDebounceMs int

	nodeMu sync.Mutex
	locks  map[int64]*sync.Mutex // per-node serialization for Caddy /load

	// genMu guards desiredGen/appliedGen: the per-node config generation.
	// Every request that changes what a node's config should contain bumps
	// desiredGen; a full push records the generation it built from and, if a
	// newer one appeared while it was pushing, rebuilds instead of leaving the
	// node on the older snapshot (see pushNodeConfig).
	genMu      sync.Mutex
	desiredGen map[int64]uint64
	appliedGen map[int64]uint64

	// debounceMu guards debouncers.
	debounceMu sync.Mutex
	debouncers map[int64]*time.Timer // pending debounced push timer per node

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

// portalDial returns the panel host:port the node's Caddy uses for the
// built-in portal forward_auth + login passthrough. Empty when the panel
// internal address isn't configured (portal then never emits, fail closed).
func (s *Service) portalDial() string {
	if s.PanelInternalHost == "" || s.PanelInternalPort == 0 {
		return ""
	}
	return fmt.Sprintf("%s:%d", s.PanelInternalHost, s.PanelInternalPort)
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

	// GroupID (host_groups FK, UI grouping) and CustomFields (JSON) are written
	// in the same INSERT so host metadata persists atomically with the route.
	GroupID      int64
	CustomFields string

	// ViaWGPeerID binds the backend dial to a WG tunnel peer (0 = none).
	ViaWGPeerID int64
}

// Validation errors exposed to handlers.
var (
	ErrPortOutOfRange = errors.New("port not in allowed range for this service")
	ErrPortInUse      = errors.New("backend port already in use by another route")
	ErrInvalidDomain  = errors.New("invalid domain")
	ErrDomainTaken    = errors.New("domain (+ path) already mapped")
	ErrNoNodeFound    = errors.New("no Caddy node available for this plan")
	// ErrNodeAtCapacity: the node chosen by placement filled its max_routes
	// between selection and the capacity claim (another concurrent create took
	// the last slot). Retrying picks a different node.
	ErrNodeAtCapacity  = errors.New("selected Caddy node reached max_routes; retry")
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
	// ErrTunnelNotOnNode: selected WG peer missing, not the client's, or not
	// present on the placed Caddy node.
	ErrTunnelNotOnNode = errors.New("selected tunnel must belong to this client and exist on the placed node")
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
