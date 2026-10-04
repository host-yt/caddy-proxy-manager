// Emission-time screening of tenant-controlled HTTP proxy targets.
package routes

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/host-yt/caddy-proxy-manager/internal/audit"
	"github.com/host-yt/caddy-proxy-manager/internal/caddyapi"
	"github.com/host-yt/caddy-proxy-manager/internal/streamguard"
)

// httpDrop records one target removed from the emitted config.
type httpDrop struct {
	route caddyapi.Route
	part  string
	cause error
}

// screenHTTPTargets re-screens every dial target of the built routes at
// emission time, so a row stored before its target became control-plane
// infrastructure (or stored through a path that predates the screener) is not
// re-emitted. A deny set that cannot be loaded fails the whole push closed.
func (s *Service) screenHTTPTargets(ctx context.Context, built []caddyapi.Route, ids []int64) ([]caddyapi.Route, []int64, []httpDrop, error) {
	if len(built) == 0 {
		return built, ids, nil, nil
	}
	infra, err := streamguard.LoadInfraTargets(ctx, s.DB)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("http target screening unavailable: %w", err)
	}
	outRoutes, outIDs, drops := screenHTTPSet(infra, built, ids, s.pinner(ctx, infra))
	for _, d := range drops {
		if s.Logger != nil {
			s.Logger.Warn("unsafe HTTP target dropped from config",
				"part", d.part, "route_id", d.route.ID, "reason", d.cause.Error())
		}
		if d.part != "primary backend" && d.part != "sso provider" {
			continue
		}
		// A dropped primary or SSO gate means the host stops being served: audit it.
		audit.Write(ctx, s.DB, s.Logger, nil, audit.Entry{
			ActorType: audit.ActorSystem,
			Action:    "route.blocked_target",
			Entity:    "route",
			EntityID:  d.route.ID,
			Meta:      map[string]any{"reason": d.cause.Error(), "backend": d.route.UpstreamIP, "part": d.part},
		})
	}
	return outRoutes, outIDs, drops, nil
}

// screenMode says how one dial target of a route is handled.
type screenMode int

const (
	modePin     screenMode = iota // dialed and pinnable: resolve, screen, emit the address
	modeScreen                    // dialed but not pinnable: resolve and screen, emit the name
	modeLiteral                   // not dialed here, or resolved on the node: deny set only
)

// pinFunc screens one dial target and returns the address to emit for it:
// the host itself when it is a literal or must stay a name, the resolved
// address when the panel pins it.
type pinFunc func(host string, port int) (string, error)

// pinEntry is the last address a backend name screened to.
type pinEntry struct {
	addr string
	at   time.Time
}

// pinnedAddrs survives across pushes on purpose. A backend name that once
// screened clean keeps its address when DNS later fails, so an outage (or a
// hostile answer that is simply withheld) freezes the destination instead of
// handing the name back to the node to resolve.
var pinnedAddrs = struct {
	sync.Mutex
	m map[string]pinEntry
}{m: map[string]pinEntry{}}

// pinFresh bounds how often one name is looked up again; emission runs on
// every push over every route, so without it a push is a DNS storm.
const pinFresh = 30 * time.Second

// pinLookupTimeout caps one lookup: a backend whose DNS server has gone dark
// must not spend the whole push deadline that every other route shares.
const pinLookupTimeout = 3 * time.Second

// pinResolve is a var so the cache behaviour can be exercised without DNS.
var pinResolve = func(ctx context.Context, infra *streamguard.InfraTargets, host string, port int) (string, error) {
	return infra.PinHTTPBackend(ctx, host, port)
}

// pinner resolves, screens and pins a backend name for this push.
func (s *Service) pinner(ctx context.Context, infra *streamguard.InfraTargets) pinFunc {
	return func(host string, port int) (string, error) {
		lctx, cancel := context.WithTimeout(ctx, pinLookupTimeout)
		defer cancel()
		return pinHTTPTarget(lctx, infra, host, port, s.Logger)
	}
}

func pinHTTPTarget(ctx context.Context, infra *streamguard.InfraTargets, host string, port int, logger *slog.Logger) (string, error) {
	key := fmt.Sprintf("%s|%d", strings.TrimSpace(host), port)
	pinnedAddrs.Lock()
	cached, ok := pinnedAddrs.m[key]
	pinnedAddrs.Unlock()
	if ok && time.Since(cached.at) < pinFresh {
		// The deny set is reloaded every push and may have grown since the
		// lookup, so the cached address is re-screened, never trusted.
		return cached.addr, infra.ScreenHTTPTargetLiteral(cached.addr, port)
	}
	addr, err := pinResolve(ctx, infra, host, port)
	if err != nil {
		if ok && errors.Is(err, streamguard.ErrUnresolved) {
			if logger != nil {
				logger.Warn("backend name did not resolve; keeping last screened address",
					"host", host, "pinned", cached.addr, "age", time.Since(cached.at).String())
			}
			return cached.addr, infra.ScreenHTTPTargetLiteral(cached.addr, port)
		}
		return "", err
	}
	pinnedAddrs.Lock()
	pinnedAddrs.m[key] = pinEntry{addr: addr, at: time.Now()}
	pinnedAddrs.Unlock()
	return addr, nil
}

// screenHTTPSet splits built routes into emittable and dropped, and pins every
// backend name the panel can resolve to the address it screened. Pure apart
// from pin, so the policy is testable without a DB or a resolver. ids follows
// the same permutation as built.
func screenHTTPSet(infra *streamguard.InfraTargets, built []caddyapi.Route, ids []int64, pin pinFunc) ([]caddyapi.Route, []int64, []httpDrop) {
	outRoutes := make([]caddyapi.Route, 0, len(built))
	outIDs := make([]int64, 0, len(ids))
	var drops []httpDrop
	for i, r := range built {
		screen := screenerFor(infra, r, pin)
		// A redirect route still emits the SSO subroutes, so the provider is
		// screened before any shortcut.
		if err := screenSSO(&r, screen); err != nil {
			drops = append(drops, httpDrop{r, "sso provider", err})
			continue
		}
		if r.Kind == "redirect" {
			outRoutes, outIDs = append(outRoutes, r), append(outIDs, idAt(ids, i))
			continue
		}
		// A pool overrides the single dial, so with one present the primary
		// is deny-set screened only: nothing dials it, and a name nobody
		// dials must not be able to drop the route.
		poolActive := !r.External && len(r.Upstreams) > 0
		primaryMode := modePin
		if poolActive {
			primaryMode = modeLiteral
		}
		addr, sni, err := screen(r.UpstreamIP, r.UpstreamPort, primaryMode)
		if err != nil {
			drops = append(drops, httpDrop{r, "primary backend", err})
			continue
		}
		r.UpstreamIP, r.PinnedSNI = addr, sni
		// The panel picked the address, so a stored resolver decides nothing:
		// drop it rather than emit a dynamic upstream that is ignored.
		if !nodeResolves(r) && net.ParseIP(r.UpstreamIP) != nil {
			r.BackendResolver, r.DNSResolverIP, r.DNSResolverViaWGPeerIP = "", "", ""
		}
		ups := r.Upstreams[:0:0]
		poolSNI, poolMode := "", modePin
		if !poolPinnable(r) {
			poolMode = modeScreen
		}
		for _, u := range r.Upstreams {
			addr, sni, err := screen(u.Host, u.Port, poolMode)
			if err != nil {
				drops = append(drops, httpDrop{r, "upstream", err})
				continue
			}
			u.Host = addr
			if sni != "" {
				poolSNI = sni
			}
			ups = append(ups, u)
		}
		r.Upstreams = ups
		if poolActive && poolSNI != "" {
			r.PinnedSNI = poolSNI
		}
		rules := r.LocationRules[:0:0]
		for _, lr := range r.LocationRules {
			if lr.Action == "proxy" {
				addr, sni, err := screen(lr.UpstreamHost, lr.UpstreamPort, modePin)
				if err != nil {
					drops = append(drops, httpDrop{r, "location rule", err})
					continue
				}
				lr.UpstreamHost, lr.PinnedSNI = addr, sni
			}
			rules = append(rules, lr)
		}
		r.LocationRules = rules
		outRoutes, outIDs = append(outRoutes, r), append(outIDs, idAt(ids, i))
	}
	return outRoutes, outIDs, drops
}

// screenerFor returns the screen+pin policy for one route. Pinning is what
// keeps a screened destination from moving under a later DNS answer, so it is
// skipped only where an operator accepted that nothing screens the answer:
// the super_admin node-side waiver and allow-listed external origins.
func screenerFor(infra *streamguard.InfraTargets, r caddyapi.Route, pin pinFunc) func(host string, port int, mode screenMode) (string, string, error) {
	nodeResolved := nodeResolves(r)
	return func(host string, port int, mode screenMode) (string, string, error) {
		host = strings.TrimSpace(host)
		if host == "" {
			return host, "", nil
		}
		if nodeResolved {
			mode = modeLiteral
		}
		if mode == modeLiteral || net.ParseIP(host) != nil {
			// Deny set only: a name the node resolves has to reach it as a
			// name, and a target nobody dials must not drop the route.
			return host, "", screenEmitted(infra, host, port)
		}
		addr, err := pin(host, port)
		if err != nil || mode == modeScreen || addr == host {
			return host, "", err
		}
		return addr, host, nil
	}
}

// screenSSO screens the route's SSO provider dial target and pins it. The
// provider feeds the UNAUTHENTICATED /outpost.goauthentik.io/* passthrough as
// well as the forward-auth subrequest, so it is a tenant-controlled dial
// target like any other (HPG-SEC-001b); the emitted config dials the screened
// address while SNI and the Host header keep the provider name.
func screenSSO(r *caddyapi.Route, screen func(string, int, screenMode) (string, string, error)) error {
	host, port, ok := caddyapi.SSODialTarget(*r)
	if !ok {
		if strings.TrimSpace(r.SSOProviderURL) == "" {
			return nil
		}
		return errors.New("provider URL has no dialable host:port")
	}
	addr, sni, err := screen(host, port, modePin)
	if err != nil {
		return err
	}
	if sni != "" {
		r.SSOResolver = addr
	}
	return nil
}

// nodeResolves reports whether the NODE, not the panel, picks the address
// behind this route's names. Nothing screens what DNS answers then, so it is
// an operator decision (super_admin waiver / allow-listed external origin) -
// a tunnel, a bound peer or a custom resolver must never grant it by itself.
func nodeResolves(r caddyapi.Route) bool { return r.ResolveNodeSide || r.External }

// tunnelBackendDial returns the address a tunnel-bound route dials for its
// backend: a name collapses to the peer address the panel already screened,
// unless the operator waived panel-side resolution (HPG-SEC-001a).
func tunnelBackendDial(external, resolveNodeSide bool, backend, peerIP string) string {
	if external || resolveNodeSide || peerIP == "" || backend == "" || looksLikeIP(backend) {
		return backend
	}
	return peerIP
}

// poolPinnable reports whether the members of a multi-backend pool may be
// pinned. One transport carries one server_name, so an https pool spread over
// several hostnames keeps its names - each dial then derives its own SNI.
func poolPinnable(r caddyapi.Route) bool {
	if r.UpstreamScheme != "https" {
		return true
	}
	name := ""
	for _, u := range r.Upstreams {
		h := strings.TrimSpace(u.Host)
		if h == "" || net.ParseIP(h) != nil {
			continue
		}
		if name != "" && !strings.EqualFold(name, h) {
			return false
		}
		name = h
	}
	return true
}

// screenEmitted applies the deny set without resolving.
func screenEmitted(infra *streamguard.InfraTargets, host string, port int) error {
	if strings.TrimSpace(host) == "" {
		return nil
	}
	// Socket and file-descriptor upstreams name no address, so the deny set
	// cannot see them; reject the whole shape before screening the rest.
	if err := caddyapi.ScreenDialTarget(host); err != nil {
		return err
	}
	return infra.ScreenHTTPTargetLiteral(host, port)
}

func idAt(ids []int64, i int) int64 {
	if i < len(ids) {
		return ids[i]
	}
	return 0
}

// firstErrOf returns the first non-nil error.
func firstErrOf(errs ...error) error {
	for _, e := range errs {
		if e != nil {
			return e
		}
	}
	return nil
}
