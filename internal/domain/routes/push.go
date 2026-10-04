// Delivering config to a node: per-node serialization, config generations,
// full /load, incremental @id mutations, and drift detection.
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
	"net"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/host-yt/caddy-proxy-manager/internal/caddyapi"
	"github.com/host-yt/caddy-proxy-manager/internal/cloudflare"
	"github.com/host-yt/caddy-proxy-manager/internal/geoip"
	"github.com/host-yt/caddy-proxy-manager/internal/security"
	"github.com/host-yt/caddy-proxy-manager/internal/store"
)

// bumpDesiredGen records that nodeID's config changed and returns the new
// generation. Called before every scheduled push so an in-flight push can tell
// that the snapshot it built is already out of date.
func (s *Service) bumpDesiredGen(nodeID int64) uint64 {
	s.genMu.Lock()
	defer s.genMu.Unlock()
	if s.desiredGen == nil {
		s.desiredGen = map[int64]uint64{}
	}
	s.desiredGen[nodeID]++
	return s.desiredGen[nodeID]
}

// currentGen returns nodeID's desired generation without bumping it.
func (s *Service) currentGen(nodeID int64) uint64 {
	s.genMu.Lock()
	defer s.genMu.Unlock()
	return s.desiredGen[nodeID]
}

// recordApplied marks gen as the generation now live on nodeID.
func (s *Service) recordApplied(nodeID int64, gen uint64) {
	s.genMu.Lock()
	defer s.genMu.Unlock()
	if s.appliedGen == nil {
		s.appliedGen = map[int64]uint64{}
	}
	if gen > s.appliedGen[nodeID] {
		s.appliedGen[nodeID] = gen
	}
}

// AppliedGeneration reports the config generation last successfully loaded on
// nodeID. Exported for tests and diagnostics.
func (s *Service) AppliedGeneration(nodeID int64) uint64 {
	s.genMu.Lock()
	defer s.genMu.Unlock()
	return s.appliedGen[nodeID]
}

// schedulePush debounces a full-config push to nodeID. Within the debounce
// window (PushDebounceMs) repeated calls reset the timer; only the last fires.
// Falls back to an immediate goroutine push when debouncing is disabled (0).
func (s *Service) schedulePush(nodeID int64) {
	s.bumpDesiredGen(nodeID)
	if s.DB != nil {
		// Durable before the in-memory timer: a crash now leaves the marker for the drain.
		mctx, mcancel := context.WithTimeout(s.BackgroundCtx(), 5*time.Second)
		if err := s.markPushPending(mctx, s.DB, nodeID); err != nil && s.Logger != nil {
			s.Logger.Warn("push marker not written; relying on drift reconcile", "node_id", nodeID, "err", err)
		}
		mcancel()
	}
	window := time.Duration(s.PushDebounceMs) * time.Millisecond
	if window <= 0 {
		go func() {
			defer recoverBg(s.Logger, "schedulePush.immediate")
			ctx, cancel := context.WithTimeout(s.BackgroundCtx(), 30*time.Second)
			defer cancel()
			if err := s.pushNodeConfig(ctx, nodeID); err != nil && s.Logger != nil {
				s.Logger.Warn("immediate push failed", "node_id", nodeID, "err", err)
			}
		}()
		return
	}
	s.debounceMu.Lock()
	defer s.debounceMu.Unlock()
	if s.debouncers == nil {
		s.debouncers = make(map[int64]*time.Timer)
	}
	if t, ok := s.debouncers[nodeID]; ok {
		t.Reset(window) // coalesce: push further into the future
		return
	}
	s.debouncers[nodeID] = time.AfterFunc(window, func() {
		s.debounceMu.Lock()
		delete(s.debouncers, nodeID)
		s.debounceMu.Unlock()
		defer recoverBg(s.Logger, "schedulePush.debounced")
		ctx, cancel := context.WithTimeout(s.BackgroundCtx(), 30*time.Second)
		defer cancel()
		if err := s.pushNodeConfig(ctx, nodeID); err != nil && s.Logger != nil {
			s.Logger.Warn("debounced push failed", "node_id", nodeID, "err", err)
		}
	})
}

// SchedulePush is the exported debounce entry-point for external callers
// (handlers, wg_bootstrap) that need to trigger a node push after a config
// change but don't want to import the full push path directly.
func (s *Service) SchedulePush(nodeID int64) { s.schedulePush(nodeID) }

// SchedulePushAllNodes re-pushes every node that hosts a route. Used when a
// panel-wide setting baked into generated config (geo-block default, error-page
// branding) changes and must reach all nodes, not just one client's.
func (s *Service) SchedulePushAllNodes(ctx context.Context) {
	if s.DB == nil {
		return
	}
	s.scheduleQueried(ctx, `SELECT DISTINCT caddy_node_id FROM routes WHERE caddy_node_id IS NOT NULL`)
}

// scheduleQueried schedules every node id the query returns. Rows are drained
// first: schedulePush writes, and SQLite has a single connection.
func (s *Service) scheduleQueried(ctx context.Context, q string, args ...any) {
	rows, err := s.DB.QueryContext(ctx, q, args...)
	if err != nil {
		return
	}
	var ids []int64
	for rows.Next() {
		var nid int64
		if rows.Scan(&nid) == nil && nid != 0 {
			ids = append(ids, nid)
		}
	}
	rows.Close()
	for _, nid := range ids {
		s.schedulePush(nid)
	}
}

// SchedulePushForClient re-pushes every node hosting a route owned by the given
// client. Used when a client-level setting (e.g. geo-block page) changes and
// must propagate to all of that client's routes.
func (s *Service) SchedulePushForClient(ctx context.Context, clientID int64) {
	if s.DB == nil || clientID == 0 {
		return
	}
	s.scheduleQueried(ctx, `SELECT DISTINCT r.caddy_node_id FROM routes r
		   JOIN services sv ON sv.id = r.service_id
		  WHERE sv.client_id = ? AND r.caddy_node_id IS NOT NULL`, clientID)
}

// SchedulePushForRoute re-pushes every node serving the given route (its direct
// caddy_node_id plus any route_node_assignments fan-out). Used when something
// off the routes table but baked into a node's config changes - e.g. a manual
// TLS cert linked to the route is imported, replaced, or deleted.
func (s *Service) SchedulePushForRoute(ctx context.Context, routeID int64) {
	if s.DB == nil || routeID == 0 {
		return
	}
	seen := map[int64]struct{}{}
	sched := func(nid int64) {
		if nid == 0 {
			return
		}
		if _, dup := seen[nid]; dup {
			return
		}
		seen[nid] = struct{}{}
		s.schedulePush(nid)
	}
	var direct sql.NullInt64
	if err := s.DB.QueryRowContext(ctx,
		`SELECT caddy_node_id FROM routes WHERE id = ?`, routeID).Scan(&direct); err != nil {
		if s.Logger != nil {
			s.Logger.Warn("push scheduling: anchor node lookup failed", "route_id", routeID, "err", err)
		}
	} else if direct.Valid {
		sched(direct.Int64)
	}
	rows, err := s.DB.QueryContext(ctx,
		`SELECT node_id FROM route_node_assignments WHERE route_id = ?`, routeID)
	if err != nil {
		// Silence here means fan-out peers keep serving the previous config
		// with nothing to show for it.
		if s.Logger != nil {
			s.Logger.Warn("push scheduling: fan-out lookup failed, assigned nodes not scheduled", "route_id", routeID, "err", err)
		}
		return
	}
	var peers []int64
	for rows.Next() {
		var nid int64
		if rows.Scan(&nid) == nil {
			peers = append(peers, nid)
		}
	}
	rows.Close()
	for _, nid := range peers {
		sched(nid)
	}
}

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
	if s.AfterPush != nil {
		s.AfterPush(ctx)
	}
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
			client := s.NodeClient(ctx, n.id, n.apiURL)
			probeCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
			actual, err := s.actualNodeManifestHash(probeCtx, client)
			cancel()
			if err != nil {
				return
			}
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
	err := s.pushNodeConfig(ctx, nodeID)
	if err == nil && s.AfterPush != nil {
		s.AfterPush(ctx)
	}
	return err
}

// NodeClient returns the admin-API client for a node.
//
// Authenticated transport is the default posture (SEC-002). A node whose agent
// fronts the Caddy admin API has a key in caddy_nodes.admin_proxy_key_enc and
// the panel presents it as a bearer token. A node without one is reached
// directly ONLY where there is no network to authenticate over (loopback, unix
// socket, the manager's own compose bridge) or where an operator has opted that
// single node into the legacy path. Anything else - including a key that will
// not decrypt - gets a client that refuses to talk, so the push fails instead
// of silently dropping to an unauthenticated control plane.
func (s *Service) NodeClient(ctx context.Context, nodeID int64, apiURL string) *caddyapi.Client {
	key, allowPlain, err := s.nodeAdminAuth(ctx, nodeID)
	switch {
	case err != nil:
		return caddyapi.NewBlocked(apiURL, err)
	case key != "":
		return caddyapi.NewAuthed(apiURL, key)
	case !security.UnauthenticatedNodeAdminURL(apiURL):
		return caddyapi.New(apiURL)
	case allowPlain:
		if s.Logger != nil {
			s.Logger.Warn("node reached over an unauthenticated Caddy admin API (per-node legacy allowance)",
				"node_id", nodeID, "api_url", apiURL)
		}
		return caddyapi.New(apiURL)
	default:
		return caddyapi.NewBlocked(apiURL, fmt.Errorf(
			"node %d has no admin-proxy key and %s is not an authenticated admin endpoint: "+
				"run the node-agent admin proxy and repoint the node at it (docs/MULTI_NODE.md), "+
				"or set caddy_nodes.allow_unauthenticated_admin=1 for this node to keep the legacy path",
			nodeID, apiURL))
	}
}

// nodeAdminAuth reads a node's admin-proxy key and its per-node legacy
// allowance. A decrypt failure is returned as an error, never as "no key":
// degrading to an unauthenticated client on a crypto error is the exact defect
// SEC-002 names. Anything else unknown reports no key and no allowance, which
// NodeClient resolves fail-closed for a remote endpoint.
func (s *Service) nodeAdminAuth(ctx context.Context, nodeID int64) (key string, allowPlain bool, err error) {
	if s.DB == nil || nodeID <= 0 {
		return "", false, nil
	}
	c, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	var enc sql.NullString
	var allow bool
	if qerr := s.DB.QueryRowContext(c,
		"SELECT admin_proxy_key_enc, COALESCE(allow_unauthenticated_admin,0) FROM caddy_nodes WHERE id = ?",
		nodeID).Scan(&enc, &allow); qerr != nil {
		if s.Logger != nil && !errors.Is(qerr, sql.ErrNoRows) {
			s.Logger.Warn("node admin transport lookup failed; treating the node as unauthenticated",
				"node_id", nodeID, "err", qerr)
		}
		return "", false, nil
	}
	if !enc.Valid || enc.String == "" {
		return "", allow, nil
	}
	if s.DecryptNodeSecret == nil {
		return "", false, fmt.Errorf("node %d has an admin-proxy key but no decryptor is wired", nodeID)
	}
	k, derr := s.DecryptNodeSecret(enc.String)
	if derr != nil {
		return "", false, fmt.Errorf("node %d admin-proxy key could not be decrypted "+
			"(wrong APP_SECRET or a corrupted row): %w", nodeID, derr)
	}
	if allow {
		// The node is authenticated now; the legacy allowance only invites a
		// silent downgrade if the key ever stops decrypting.
		if _, uerr := s.DB.ExecContext(c,
			"UPDATE caddy_nodes SET allow_unauthenticated_admin = 0 WHERE id = ?", nodeID); uerr != nil && s.Logger != nil {
			s.Logger.Warn("could not clear the legacy admin allowance", "node_id", nodeID, "err", uerr)
		}
	}
	return k, false, nil
}

// nodePush is the built, ready-to-Load config for one node plus the data
// loadNodeConfig needs for fingerprinting.
type nodePush struct {
	cfg      map[string]any
	built    []caddyapi.Route
	routeIDs []int64
	apiURL   string
	// settings is kept so the node config can be re-rendered from a modified
	// route set without a second DB pass (see isolateWAFFailure).
	settings caddyapi.NodeSettings
	// pendingSeq is the push marker's seq read before the build (outbox.go).
	pendingSeq int64
}

// render re-renders this node's config from a modified route set.
func (np *nodePush) render(built []caddyapi.Route) map[string]any {
	return caddyapi.BuildNodeConfig(built, np.settings)
}

// buildNodePush renders the full Caddy config for a node from DB. Read-only;
// holds no lock.
func (s *Service) buildNodePush(ctx context.Context, nodeID int64) (*nodePush, error) {
	built, routeIDs, err := s.buildRoutesForNode(ctx, nodeID)
	if err != nil {
		return nil, err
	}
	// Directives a node already refused stay parked until they are edited.
	s.applyWAFQuarantine(ctx, built, routeIDs)
	var (
		apiURL              string
		transport           sql.NullString
		wstunnelPort        sql.NullInt64
		tunnelEndpoint      sql.NullString
		tunnelEnabled       bool
		wstHealthy          sql.NullBool
		wstFresh            sql.NullBool
		proxyProtoIn        bool
		proxyProtoAllow     string
		proxyProtoTimeoutMs int
	)
	var nodeHasWAF, nodeHasL4, nodeHasGeoIP, nodeHasRateLimit, nodeHasDNS, nodeGeoDB sql.NullBool
	var nodeCaddyVersion string
	if err := s.DB.QueryRowContext(ctx,
		`SELECT api_url, tunnel_transport, tunnel_wstunnel_port, tunnel_endpoint, tunnel_enabled,
		        tunnel_wstunnel_healthy,
		        tunnel_wstunnel_reported_at > `+store.DateSub(3, "MINUTE")+`,
		        CASE WHEN modules_probed_at IS NOT NULL THEN has_waf       ELSE NULL END,
		        CASE WHEN modules_probed_at IS NOT NULL THEN has_l4        ELSE NULL END,
		        CASE WHEN modules_probed_at IS NOT NULL THEN has_geoip     ELSE NULL END,
		        CASE WHEN modules_probed_at IS NOT NULL THEN has_rate_limit ELSE NULL END,
		        CASE WHEN modules_probed_at IS NOT NULL THEN has_dns_module ELSE NULL END,
		        geoip_db_present,
		        proxy_protocol_in, proxy_protocol_allow, proxy_protocol_timeout_ms,
		        COALESCE(caddy_version,'')
		   FROM caddy_nodes WHERE id = ?`,
		nodeID).Scan(&apiURL, &transport, &wstunnelPort, &tunnelEndpoint, &tunnelEnabled,
		&wstHealthy, &wstFresh,
		&nodeHasWAF, &nodeHasL4, &nodeHasGeoIP, &nodeHasRateLimit, &nodeHasDNS, &nodeGeoDB,
		&proxyProtoIn, &proxyProtoAllow, &proxyProtoTimeoutMs,
		&nodeCaddyVersion); err != nil {
		return nil, err
	}
	// If the node has been probed, its per-node capability flags are authoritative.
	// Unprobed nodes fall back to the global env-configured flags so existing
	// deployments are not affected before the first probe runs.
	probedOr := func(probed sql.NullBool, global bool) bool {
		if probed.Valid {
			return probed.Bool
		}
		return global
	}
	// Fail closed: an unscreened stream set must never reach a node.
	streams, err := s.buildStreamsForNode(ctx, nodeID)
	if err != nil {
		return nil, err
	}
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

	// PQ-only is gated on the node's DECLARED Caddy version (operator-entered,
	// same trust model as has_waf/has_geoip): an older Caddy rejects the whole
	// /load on the unknown x25519mlkem768 curve. Warn loudly when a host asked
	// for it and the gate dropped it, otherwise the toggle looks active but the
	// policy is never emitted.
	pqAvailable := caddyapi.CaddySupportsPQCurve(nodeCaddyVersion)
	if !pqAvailable {
		for _, r := range built {
			if r.TLSPQOnly {
				s.Logger.Warn("PQ-only TLS policy dropped: node has not declared Caddy 2.10+",
					"node_id", nodeID, "caddy_version", nodeCaddyVersion, "route_id", r.ID)
			}
		}
	}

	mtlsFailOpen := s.loadMTLSFailOpen(ctx)
	trustCFIP := s.loadTrustCloudflareIP(ctx)
	settings := caddyapi.NodeSettings{
		ACMEEmail:                s.ACMEEmail,
		ACMEStaging:              s.ACMEStaging,
		ACMECaURL:                s.ACMECaURL,
		ACMEEabKID:               s.ACMEEabKID,
		ACMEEabHMAC:              s.ACMEEabHMAC,
		AskURL:                   s.AskURL,
		PanelRoute:               s.panelRoute(),
		CacheModuleAvailable:     s.CacheModuleAvailable,
		Layer4ModuleAvailable:    probedOr(nodeHasL4, s.Layer4ModuleAvailable),
		RateLimitModuleAvailable: probedOr(nodeHasRateLimit, s.RateLimitModuleAvailable),
		WAFModuleAvailable:       probedOr(nodeHasWAF, s.WAFModuleAvailable),
		GeoModuleAvailable:       probedOr(nodeHasGeoIP, s.GeoModuleAvailable) && geoip.NodeHasCountryDB(nodeGeoDB),
		DNS01ModuleAvailable:     probedOr(nodeHasDNS, s.DNS01ModuleAvailable),
		WildcardPolicies:         s.buildWildcardPolicies(ctx, nodeID),
		StreamRoutes:             streams,
		ErrorBranding:            branding,
		WstunnelRoute:            wstunnelRoute,
		AccessLogURL:             s.AccessLogURL,
		MTLSFailOpen:             mtlsFailOpen,
		PQCurveAvailable:         pqAvailable,
		AdminListen:              s.adminListenFor(nodeID),
		TrustCloudflareIP:        trustCFIP,
		CloudflareRanges:         cloudflare.EdgeCIDRs(),
		ProxyProtocolIn:          proxyProtoIn,
		ProxyProtocolAllow:       proxyProtoAllow,
		ProxyProtocolTimeoutMs:   proxyProtoTimeoutMs,
		ManualCerts:              s.buildManualCertsForNode(ctx, nodeID),
	}
	np := &nodePush{built: built, routeIDs: routeIDs, apiURL: apiURL, settings: settings}
	np.cfg = np.render(built)
	return np, nil
}

// loadNodeConfig POSTs the full config (/load) and records the per-route drift
// fingerprint. The caller MUST hold the per-node lock.
func (s *Service) loadNodeConfig(ctx context.Context, nodeID int64, np *nodePush) error {
	seq := np.pendingSeq
	client := s.NodeClient(ctx, nodeID, np.apiURL)
	if err := client.Load(ctx, np.cfg); err != nil {
		// One tenant's custom SecLang must not hold a whole node's config
		// hostage: park it and publish the rest (SEC-006).
		recovered := s.isolateWAFFailure(ctx, nodeID, client, np, err)
		if recovered == nil {
			s.Logger.Error("caddy push failed", "node_id", nodeID, "err", err)
			if s.Metrics != nil {
				s.Metrics.CaddyPushFail()
			}
			s.recordNodeApply(ctx, nodeID, "", err)
			s.settlePending(ctx, nodeID, seq, err)
			return err
		}
		np = recovered
	}
	if s.Metrics != nil {
		s.Metrics.CaddyPushOK()
	}
	pushHash := hashRoutes(np.built)
	s.recordNodeApply(ctx, nodeID, pushHash, nil)
	s.settlePending(ctx, nodeID, seq, nil)
	if err := s.markRoutesPushed(ctx, np.routeIDs, pushHash); err != nil {
		// The /load already succeeded - the config IS live. This bookkeeping
		// failure only means last_pushed_at/hash may now lag reality, so log
		// it rather than fail an otherwise-successful push (HPG-021).
		s.Logger.Warn("push metadata update failed; last_pushed_at/hash may lag the live config",
			"node_id", nodeID, "err", err)
	}
	s.Logger.Info("caddy push ok", "node_id", nodeID, "routes", len(np.built), "hash", pushHash[:12])
	return nil
}

// pushMetaChunkSize bounds how many route IDs land in one UPDATE's IN(...)
// list, so a 10k-route push issues ~20 statements instead of one per route.
const pushMetaChunkSize = 500

// markRoutesPushed batch-updates last_pushed_at/last_pushed_hash for every
// route in the just-applied snapshot (HPG-021). Previously this ran one
// ExecContext per route with errors discarded (`_, _ =`), so a 10k-route push
// issued ~10k statements and a failing one went unnoticed.
//
// The timestamp/hash mean "this route was included in the snapshot the node
// was told to load", not "this route was individually verified live" - Load
// is one atomic all-or-nothing call, so the whole batch either happened or
// the push already returned an error before this is ever called.
func (s *Service) markRoutesPushed(ctx context.Context, ids []int64, hash string) error {
	for len(ids) > 0 {
		n := pushMetaChunkSize
		if n > len(ids) {
			n = len(ids)
		}
		chunk := ids[:n]
		ids = ids[n:]
		placeholders := strings.Repeat("?,", len(chunk))
		placeholders = placeholders[:len(placeholders)-1]
		args := make([]any, 0, len(chunk)+1)
		args = append(args, hash)
		for _, id := range chunk {
			args = append(args, id)
		}
		q := "UPDATE routes SET last_pushed_at = NOW(), last_pushed_hash = ? WHERE id IN (" + placeholders + ")"
		if _, err := s.DB.ExecContext(ctx, q, args...); err != nil {
			return fmt.Errorf("mark routes pushed: %w", err)
		}
	}
	return nil
}

// maxPushGenerations bounds the rebuild loop in pushNodeConfig. A node under a
// constant stream of edits would otherwise never hand the lock back; the edits
// that lose their turn have already scheduled their own push.
const maxPushGenerations = 3

// pushNodeConfig loads the node's full config, building it UNDER the per-node
// lock and re-checking the config generation afterwards.
//
// Building outside the lock (as this used to) let an older snapshot win: build
// at generation 10, block on the lock while another writer pushed generation
// 11, then /load the generation-10 snapshot and silently revert it. The lock
// serialized the request to Caddy but said nothing about how fresh the state
// behind it was. Building under the lock means a push always reflects DB state
// at least as new as any push that finished before it; the generation re-check
// then covers a change committed while this push was in flight, so the node
// converges immediately instead of waiting for the next debounce or drift
// sweep.
func (s *Service) pushNodeConfig(ctx context.Context, nodeID int64) error {
	lock := s.nodeLock(nodeID)
	lock.Lock()
	defer lock.Unlock()

	for attempt := 0; attempt < maxPushGenerations; attempt++ {
		gen := s.currentGen(nodeID)
		seq := s.pendingSeq(ctx, nodeID)
		np, err := s.buildNodePush(ctx, nodeID)
		if err != nil {
			return err
		}
		np.pendingSeq = seq
		if err := s.loadNodeConfig(ctx, nodeID, np); err != nil {
			return err
		}
		s.recordApplied(nodeID, gen)
		if s.currentGen(nodeID) == gen {
			return nil
		}
		// A change landed while we were pushing: rebuild rather than leave the
		// node on the snapshot we just applied.
		if ctx.Err() != nil {
			return ctx.Err()
		}
	}
	if s.Logger != nil {
		s.Logger.Warn("node config still changing after repeated pushes; leaving convergence to the next scheduled push",
			"node_id", nodeID, "attempts", maxPushGenerations)
	}
	return nil
}

// pushNodeConfigLocked is the full-/load fallback for callers that ALREADY hold
// the per-node lock (pushRouteIncremental). Builds under the held lock; the
// minor cost only applies on the rare incremental-fallback path.
func (s *Service) pushNodeConfigLocked(ctx context.Context, nodeID int64) error {
	seq := s.pendingSeq(ctx, nodeID)
	np, err := s.buildNodePush(ctx, nodeID)
	if err != nil {
		return err
	}
	np.pendingSeq = seq
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
	for _, obj := range arr {
		if id, _ := obj["@id"].(string); id == caddyID {
			present = true
			continue
		}
		// Wildcard-aware: an existing "*.example.com" catch-all also matches a
		// new "app.example.com" and would shadow it if we merely appended.
		if caddyapi.HostSetsOverlap(hosts, routeMatchHosts(obj)) {
			sharesHost = true
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
	client := s.NodeClient(ctx, nodeID, apiURL)
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
// from a Caddy srv0/routes array so drift compares only customer routes -
// neither lives in the routes table, so the DB-derived side never carries
// them either (see stripVirtualRoutes). BuildRoute emits @id="route_"+ID, so
// the panel route (ID "panel_self") lands as "route_panel_self"; the wstunnel
// route is built directly as "hpg_wstunnel_*". Customer routes are
// "route_<numeric>" and are kept. Leaves input untouched if it's not the
// expected array.
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

// managedConfigPaths are the Caddy admin-API subtrees push actually writes on
// every /load, in GET-path form. Reconcile hashes exactly these on both sides
// (HPG-010): before this, drift only compared the bare HTTP route array, so a
// TLS connection policy, a wildcard DNS-01 policy, or an L4 stream set could
// diverge on a node and no resync would ever fire.
//
// Ownership contract - deliberately NOT compared, so these stay unmanaged by
// reconcile:
//   - admin.listen / top-level logging: infra bind, not DB-derived customer
//     state; an operator changing it is an explicit resync, not drift.
//   - apps.cache: static per-install block with no per-node deterministic
//     field beyond what's already implied by route matching.
//   - apps.tls.certificates: Caddy populates this itself as ACME/manual certs
//     are obtained. It is never byte-equal to anything we send, so comparing
//     it would make every node "drift" forever.
//
// Any manual edit an operator made inside a path THIS list does cover was
// already being silently clobbered by the next full push - reconcile noticing
// it sooner (and resyncing) is the intended effect of this fix, not a new one.
var managedConfigPaths = []string{
	"apps/http/servers/srv0",
	"apps/tls/automation/policies",
	"apps/layer4",
}

// lookupConfigPath walks a slash-separated path through nested
// map[string]any, mirroring the shape of a Caddy config GET path.
func lookupConfigPath(cfg any, path string) (any, bool) {
	cur := cfg
	for _, seg := range strings.Split(path, "/") {
		m, ok := cur.(map[string]any)
		if !ok {
			return nil, false
		}
		cur, ok = m[seg]
		if !ok {
			return nil, false
		}
	}
	return cur, true
}

// stripVirtualRoutes removes the panel-self and wstunnel infra routes from a
// srv0 section's "routes" array (they don't live in the routes table, so the
// DB-derived side never carries them - see filterVirtualRoutes). Returns a
// shallow copy; never mutates the map that will actually be /load'ed.
func stripVirtualRoutes(srv0 map[string]any) map[string]any {
	routes, ok := srv0["routes"]
	if !ok {
		return srv0
	}
	b, err := json.Marshal(routes)
	if err != nil {
		return srv0
	}
	var filtered []any
	if err := json.Unmarshal(filterVirtualRoutes(b), &filtered); err != nil {
		return srv0
	}
	out := make(map[string]any, len(srv0))
	for k, v := range srv0 {
		out[k] = v
	}
	out["routes"] = filtered
	return out
}

// nodeSnapshotManifest picks the managedConfigPaths sections out of a full
// node config (as buildNodePush produces it) into one canonical, hashable
// structure. Both the expected (DB-built) and actual (node-fetched) sides
// run through this so they are compared shape-for-shape.
func nodeSnapshotManifest(cfg map[string]any) map[string]any {
	manifest := map[string]any{}
	for _, path := range managedConfigPaths {
		if v, ok := lookupConfigPath(cfg, path); ok {
			manifest[path] = v
		}
	}
	if srv0, ok := manifest["apps/http/servers/srv0"].(map[string]any); ok {
		manifest["apps/http/servers/srv0"] = stripVirtualRoutes(srv0)
	}
	return manifest
}

// expectedNodeHash computes the canonical hash of the managed config sections
// built from DB state via buildNodePush - the same builder the real push
// uses, not a separate narrower projection (HPG-010).
func (s *Service) expectedNodeHash(ctx context.Context, nodeID int64) (string, error) {
	np, err := s.buildNodePush(ctx, nodeID)
	if err != nil {
		return "", err
	}
	b, err := json.Marshal(nodeSnapshotManifest(np.cfg))
	if err != nil {
		return "", err
	}
	return canonHashBytes(b), nil
}

// actualNodeManifestHash fetches managedConfigPaths from the live node and
// hashes them the same way nodeSnapshotManifest does. apps/http/servers/srv0
// must always exist, so an error there aborts the probe (inconclusive, try
// next sweep); the other paths are module-gated and simply absent when the
// node hasn't mounted that app - matching an expected side that omits them
// too.
func (s *Service) actualNodeManifestHash(ctx context.Context, client *caddyapi.Client) (string, error) {
	manifest := map[string]any{}
	for _, path := range managedConfigPaths {
		raw, err := client.GetRaw(ctx, "/config/"+path)
		if err != nil {
			if path == "apps/http/servers/srv0" {
				return "", err
			}
			continue
		}
		trimmed := strings.TrimSpace(string(raw))
		if trimmed == "" || trimmed == "null" {
			continue
		}
		var v any
		if err := json.Unmarshal(raw, &v); err != nil {
			return "", err
		}
		manifest[path] = v
	}
	if srv0, ok := manifest["apps/http/servers/srv0"].(map[string]any); ok {
		manifest["apps/http/servers/srv0"] = stripVirtualRoutes(srv0)
	}
	// Canonicalise before hashing: Caddy may reformat the GET response (map key
	// order, whitespace, number encoding) so a raw hash flaps even when the
	// config is identical, triggering an infinite resync loop.
	b, err := json.Marshal(manifest)
	if err != nil {
		return "", err
	}
	return canonHashBytes(b), nil
}

// ensureStableHash is a helper used in tests; not called from production.
func ensureStableHash(rs []caddyapi.Route) string {
	dup := make([]caddyapi.Route, len(rs))
	copy(dup, rs)
	sort.Slice(dup, func(i, j int) bool { return dup[i].ID < dup[j].ID })
	return hashRoutes(dup)
}

// adminListenFor returns the Caddy Admin API bind to push to one node. The
// bind is fleet-wide unless the operator named the nodes it applies to, which
// is how a socket endpoint is rolled out one node at a time.
func (s *Service) adminListenFor(nodeID int64) string {
	if s.CaddyAdminListen == "" || strings.TrimSpace(s.CaddyAdminListenNodes) == "" {
		return s.CaddyAdminListen
	}
	want := strconv.FormatInt(nodeID, 10)
	for _, f := range strings.Split(s.CaddyAdminListenNodes, ",") {
		if strings.TrimSpace(f) == want {
			return s.CaddyAdminListen
		}
	}
	return ""
}
