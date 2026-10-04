package handlers

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/host-yt/caddy-proxy-manager/internal/audit"
	"github.com/host-yt/caddy-proxy-manager/internal/caddyapi"
	"github.com/host-yt/caddy-proxy-manager/internal/httpserver/middleware"
	"github.com/host-yt/caddy-proxy-manager/internal/security"
)

// genProxySecret returns a random URL-safe inbound bearer for an external
// upstream route. Shown to the operator once; stored encrypted at rest.
func genProxySecret() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return "hpgx_" + base64.RawURLEncoding.EncodeToString(b), nil
}

// HostsDelete: POST /admin/hosts/{id}/delete. Removes the route + tells
// the assigned Caddy node to re-load its config (handled by Routes.Delete).
func (h *AdminHandlers) HostsDelete(w http.ResponseWriter, r *http.Request) {
	if h.Routes == nil || h.DB() == nil {
		http.Error(w, "not ready", http.StatusServiceUnavailable)
		return
	}
	sess := middleware.SessionFromContext(r.Context())
	id, _ := strconv.ParseInt(chiURLParamHosts(r, "id"), 10, 64)
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()
	// Scoped admins may only act on routes within their assigned clients.
	if !h.scopeCheckRoute(ctx, sess, id) {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	var domain string
	_ = h.DB().QueryRowContext(ctx, "SELECT domain FROM routes WHERE id = ?", id).Scan(&domain)
	if err := h.Routes.Delete(ctx, 0, id); err != nil {
		h.Logger.Warn("admin hosts delete", "id", id, "err", err)
		redirectWithFlash(w, r, "/admin/hosts", "", "delete failed: "+sanitizeErr(err))
		return
	}
	audit.Write(ctx, h.DB(), h.Logger, r, audit.Entry{
		UserID: actorUserID(sess), Action: "admin.host.delete", Entity: "route",
		EntityID: itoa64(id), Meta: map[string]any{"domain": domain},
	})
	// htmx: the row was hx-swap'd, so reply with an empty 200 (the target row
	// is replaced by nothing = removed). No-JS clients get the redirect.
	if isHTMXRequest(r) {
		w.WriteHeader(http.StatusOK)
		return
	}
	redirectWithFlash(w, r, "/admin/hosts", "Host removed", "")
}

// isHTMXRequest reports whether the request came from htmx (so the handler can
// return an HTML fragment / empty body instead of a full-page redirect).
func isHTMXRequest(r *http.Request) bool {
	return r.Header.Get("HX-Request") == "true"
}

// HostsToggle flips a route between active and disabled. Disabled
// routes are excluded from buildRoutesForNode, so the next push (kicked
// off here) removes them from Caddy without deleting the DB row.
func (h *AdminHandlers) HostsToggle(w http.ResponseWriter, r *http.Request) {
	if h.Routes == nil || h.DB() == nil {
		http.Error(w, "not ready", http.StatusServiceUnavailable)
		return
	}
	sess := middleware.SessionFromContext(r.Context())
	id, _ := strconv.ParseInt(chiURLParamHosts(r, "id"), 10, 64)
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()
	// Scoped admins may only act on routes within their assigned clients.
	if !h.scopeCheckRoute(ctx, sess, id) {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	var (
		status string
		nodeID int64
	)
	if err := h.DB().QueryRowContext(ctx,
		"SELECT status, caddy_node_id FROM routes WHERE id = ?", id,
	).Scan(&status, &nodeID); err != nil {
		redirectWithFlash(w, r, "/admin/hosts", "", "route not found")
		return
	}
	next := "disabled"
	if status == "disabled" {
		// Re-enabling: reset to pending_dns so the reconciler verifies
		// DNS still resolves before pushing back to Caddy.
		next = "pending_dns"
		if err := h.revalidateStoredWAF(ctx, sess, id); err != nil {
			redirectWithFlash(w, r, "/admin/hosts", "", "WAF: "+sanitizeErr(err))
			return
		}
	}
	if _, err := h.DB().ExecContext(ctx,
		"UPDATE routes SET status = ?, updated_at = NOW() WHERE id = ?", next, id); err != nil {
		redirectWithFlash(w, r, "/admin/hosts", "", "update failed")
		return
	}
	go func() {
		defer recoverBg(h.Logger, "resync")
		ctx, cancel := context.WithTimeout(h.Routes.BackgroundCtx(), 30*time.Second)
		defer cancel()
		_ = h.Routes.Resync(ctx, nodeID)
	}()
	audit.Write(ctx, h.DB(), h.Logger, r, audit.Entry{
		UserID: actorUserID(sess), Action: "admin.host.toggle", Entity: "route",
		EntityID: itoa64(id), Meta: map[string]any{"from": status, "to": next},
	})
	redirectWithFlash(w, r, "/admin/hosts", "Host "+next, "")
}

func chiURLParamHosts(r *http.Request, key string) string { return chi.URLParam(r, key) }

// cloneSkipColumns are the route columns a clone never copies: auto-generated
// values, per-route hostnames/ownership proof, and the two node-operator
// fields (custom_config, waf_directives) whose write is super_admin-gated - a
// clone must not be a way around that gate.
var cloneSkipColumns = map[string]bool{
	"id": true, "created_at": true, "updated_at": true,
	"last_error": true, "last_push_at": true, "proxy_secret_hash": true,
	"custom_config": true, "waf_directives": true,
	"aliases": true, "aliases_verified": true,
	"domain_verified": true, "verify_token": true,
}

// HostsClone copies an existing route row into a new inactive clone.
// Uses information_schema to build a dynamic INSERT so future column additions don't require handler changes.
func (h *AdminHandlers) HostsClone(w http.ResponseWriter, r *http.Request) {
	if h.DB() == nil {
		http.Error(w, "no db", http.StatusServiceUnavailable)
		return
	}
	sess := middleware.SessionFromContext(r.Context())
	id, _ := strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)
	db := h.DB()
	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()
	// Scoped admins may only clone routes within their assigned clients.
	if !h.scopeCheckRoute(ctx, sess, id) {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}

	// Verify route exists and fetch its domain for the audit entry.
	var domain string
	if err := db.QueryRowContext(ctx, "SELECT domain FROM routes WHERE id=?", id).Scan(&domain); err != nil {
		http.NotFound(w, r)
		return
	}

	// Discover columns at runtime so the clone stays correct after migrations.
	colRows, err := db.QueryContext(ctx,
		`SELECT COLUMN_NAME FROM information_schema.COLUMNS
		 WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='routes'
		 ORDER BY ORDINAL_POSITION`)
	if err != nil {
		http.Error(w, "db error", http.StatusInternalServerError)
		return
	}
	defer colRows.Close()
	var allCols []string
	for colRows.Next() {
		var c string
		_ = colRows.Scan(&c)
		allCols = append(allCols, c)
	}

	// Columns excluded from the copy (auto-generated or intentionally reset).
	skip := cloneSkipColumns
	// Columns where the cloned value differs from the source.
	override := map[string]string{
		"domain":           `CONCAT('clone-of-', domain)`,
		"status":           `'inactive'`,
		"maintenance_mode": `0`,
	}
	var insertCols, selectExprs []string
	for _, c := range allCols {
		if skip[c] {
			continue
		}
		insertCols = append(insertCols, c)
		if expr, ok := override[c]; ok {
			selectExprs = append(selectExprs, expr)
		} else {
			selectExprs = append(selectExprs, c)
		}
	}
	cloneSQL := "INSERT INTO routes (" + strings.Join(insertCols, ",") + ") SELECT " +
		strings.Join(selectExprs, ",") + " FROM routes WHERE id=?"
	res, err := db.ExecContext(ctx, cloneSQL, id)
	if err != nil {
		redirectWithFlash(w, r, "/admin/hosts", "", "clone failed: "+sanitizeErr(err))
		return
	}
	newID, _ := res.LastInsertId()
	audit.Write(ctx, db, h.Logger, r, audit.Entry{
		UserID: actorUserID(sess), Action: "admin.host.clone", Entity: "route",
		EntityID: itoa64(newID),
		Meta:     map[string]any{"source_id": id, "domain": "clone-of-" + domain},
	})
	redirectWithFlash(w, r, fmt.Sprintf("/admin/hosts/%d/edit", newID), "Route cloned - update domain + activate.", "")
}

// HostsToggleMaintenance flips maintenance_mode for a single route and resyncs Caddy.
func (h *AdminHandlers) HostsToggleMaintenance(w http.ResponseWriter, r *http.Request) {
	if h.Routes == nil || h.DB() == nil {
		http.Error(w, "not ready", http.StatusServiceUnavailable)
		return
	}
	sess := middleware.SessionFromContext(r.Context())
	id, _ := strconv.ParseInt(chiURLParamHosts(r, "id"), 10, 64)
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()
	// Scoped admins may only act on routes within their assigned clients.
	if !h.scopeCheckRoute(ctx, sess, id) {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	var current int
	var nodeID int64
	if err := h.DB().QueryRowContext(ctx,
		"SELECT COALESCE(maintenance_mode,0), caddy_node_id FROM routes WHERE id = ?", id,
	).Scan(&current, &nodeID); err != nil {
		redirectWithFlash(w, r, "/admin/hosts", "", "route not found")
		return
	}
	newMode := 1 - current
	if _, err := h.DB().ExecContext(ctx,
		"UPDATE routes SET maintenance_mode = ?, updated_at = NOW() WHERE id = ?", newMode, id,
	); err != nil {
		redirectWithFlash(w, r, "/admin/hosts", "", "update failed")
		return
	}
	go func() {
		defer recoverBg(h.Logger, "maint-resync")
		h.Routes.SchedulePush(nodeID)
	}()
	onOff := "disabled"
	if newMode == 1 {
		onOff = "enabled"
	}
	audit.Write(ctx, h.DB(), h.Logger, r, audit.Entry{
		UserID: actorUserID(sess), Action: "admin.host.maintenance.toggle", Entity: "route",
		EntityID: itoa64(id), Meta: map[string]any{"maintenance_mode": newMode},
	})
	redirectWithFlash(w, r, "/admin/hosts", "Maintenance mode "+onOff, "")
}

// HostsPurgeCache flushes the Souin origin cache on the node that
// serves this route. Useful after the operator points the route at a
// new backend or invalidates content out-of-band. POST only.
//
// Node-wide flush (not per-route) - Souin's per-key purge requires the
// exact internal cache key, which we don't track in the panel. The
// extra blast radius is acceptable: the cache rebuilds on the next
// request and TTLs are short by default.
func (h *AdminHandlers) HostsPurgeCache(w http.ResponseWriter, r *http.Request) {
	if h.DB() == nil {
		http.Error(w, "no db", http.StatusServiceUnavailable)
		return
	}
	id, _ := strconv.ParseInt(chiURLParamHosts(r, "id"), 10, 64)
	if id == 0 {
		http.Redirect(w, r, "/admin/hosts", http.StatusSeeOther)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()
	// Scoped admins may only purge cache for routes within their assigned clients.
	if !h.scopeCheckRoute(ctx, middleware.SessionFromContext(r.Context()), id) {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}

	var apiURL, domain string
	var nodeID int64
	if err := h.DB().QueryRowContext(ctx,
		`SELECT n.id, n.api_url, r.domain
		 FROM routes r JOIN caddy_nodes n ON n.id = r.caddy_node_id
		 WHERE r.id = ?`, id).Scan(&nodeID, &apiURL, &domain); err != nil {
		redirectWithFlash(w, r, "/admin/hosts", "", "route not found")
		return
	}

	// Authenticated when the node's agent fronts its admin API.
	client := caddyapi.New(apiURL)
	if h.Routes != nil {
		client = h.Routes.NodeClient(ctx, nodeID, apiURL)
	}
	if err := client.PurgeCache(ctx); err != nil {
		h.Metrics.CacheOp("purge", "fail")
		if errors.Is(err, caddyapi.ErrNotFound) {
			// 404 on every Souin path. Distinguish "panel never pushed
			// apps.cache" from "panel pushed it but Caddy build lacks
			// cache-handler module" by introspecting the live config.
			loaded, lerr := client.CacheAppLoaded(ctx)
			msg := ""
			switch {
			case lerr != nil:
				msg = "cache purge failed: 404, and config introspection failed: " + sanitizeErr(lerr)
			case !loaded:
				msg = "cache purge failed: node has no apps.cache in running config. CACHE_HANDLER_AVAILABLE may be off, or last Resync failed (check /admin/nodes logs)."
			default:
				msg = "cache purge failed: apps.cache loaded but neither the Souin admin endpoint nor the re-provision fallback worked. Restart the Caddy container as a last resort."
			}
			h.Logger.Warn("cache purge 404", "id", id, "node", apiURL, "loaded", loaded, "introspect_err", lerr)
			redirectWithFlash(w, r, "/admin/hosts/"+strconv.FormatInt(id, 10)+"/edit", "", msg)
			return
		}
		h.Logger.Warn("cache purge", "id", id, "err", err)
		redirectWithFlash(w, r, "/admin/hosts/"+strconv.FormatInt(id, 10)+"/edit", "",
			"cache purge failed: "+sanitizeErr(err))
		return
	}

	h.Metrics.CacheOp("purge", "success")
	sess := middleware.SessionFromContext(r.Context())
	audit.Write(ctx, h.DB(), h.Logger, r, audit.Entry{
		UserID: actorUserID(sess), Action: "admin.host.cache.purge", Entity: "route",
		EntityID: itoa64(id), Meta: map[string]any{"domain": domain},
	})
	redirectWithFlash(w, r, "/admin/hosts/"+strconv.FormatInt(id, 10)+"/edit",
		"Cache flushed on the node serving "+domain, "")
}

// HostsCheckDNS is the JSON endpoint behind the "Check DNS" button on
// the /admin/hosts/new form. It does a fast A-record lookup for the
// supplied domain and compares the resolved IPs against the chosen
// node's public IP, returning a small JSON payload the form's inline
// JS renders next to the domain field. This is a UX hint only - the
// real DNS gate still runs server-side in routes.Service.Create.
func (h *AdminHandlers) HostsCheckDNS(w http.ResponseWriter, r *http.Request) {
	domain := strings.TrimSpace(strings.ToLower(r.URL.Query().Get("domain")))
	nodeID, _ := strconv.ParseInt(r.URL.Query().Get("node_id"), 10, 64)
	groupID, _ := strconv.ParseInt(r.URL.Query().Get("group_id"), 10, 64)
	resp := map[string]any{"domain": domain}
	if domain == "" || (nodeID == 0 && groupID == 0) {
		resp["error"] = "domain and node_id or group_id required"
		apiJSON(w, http.StatusBadRequest, resp)
		return
	}
	db := h.DB()
	if db == nil {
		resp["error"] = "db unavailable"
		apiJSON(w, http.StatusServiceUnavailable, resp)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 4*time.Second)
	defer cancel()

	// Expected IP set: the single node (legacy) or every eligible node of the
	// group - placement is group-scoped, so any group member IP is a valid target.
	var expectedIPs []string
	var hostname string
	if groupID != 0 {
		rows, err := db.QueryContext(ctx,
			`SELECT COALESCE(public_ip,''), public_hostname FROM caddy_nodes
			 WHERE node_group_id = ? AND approved_at IS NOT NULL AND is_enabled = 1
			 ORDER BY name`, groupID)
		if err != nil {
			resp["error"] = "group lookup failed"
			apiJSON(w, http.StatusInternalServerError, resp)
			return
		}
		defer rows.Close()
		for rows.Next() {
			var ip, hn string
			if rows.Scan(&ip, &hn) == nil {
				if ip != "" {
					expectedIPs = append(expectedIPs, ip)
				}
				if hostname == "" {
					hostname = hn
				}
			}
		}
		if len(expectedIPs) == 0 && hostname == "" {
			resp["error"] = "group has no eligible nodes"
			apiJSON(w, http.StatusNotFound, resp)
			return
		}
	} else {
		var expectedIP string
		if err := db.QueryRowContext(ctx,
			"SELECT COALESCE(public_ip,''), public_hostname FROM caddy_nodes WHERE id = ?", nodeID,
		).Scan(&expectedIP, &hostname); err != nil {
			resp["error"] = "node not found"
			apiJSON(w, http.StatusNotFound, resp)
			return
		}
		if expectedIP != "" {
			expectedIPs = append(expectedIPs, expectedIP)
		}
		resp["expected_ip"] = expectedIP
	}
	resp["expected_ips"] = expectedIPs
	resp["node_hostname"] = hostname

	resolver := &net.Resolver{}
	addrs, err := resolver.LookupHost(ctx, domain)
	if err != nil {
		h.Logger.Warn("dns lookup failed", "domain", domain, "err", err)
		resp["resolved"] = []string{}
		resp["match"] = false
		resp["error"] = "lookup failed"
		apiJSON(w, http.StatusOK, resp)
		return
	}
	resp["resolved"] = addrs
	match := false
	for _, want := range expectedIPs {
		for _, a := range addrs {
			if a == want {
				match = true
				break
			}
		}
	}
	resp["match"] = match
	apiJSON(w, http.StatusOK, resp)
}

// HostsDNSTest performs a real DNS lookup through the resolver configured for
// a route (dns_resolver_ip or the WG peer's assigned_ip) and returns latency +
// resolved addresses. Used by the "Test resolver" button on the DNS tab.
func (h *AdminHandlers) HostsDNSTest(w http.ResponseWriter, r *http.Request) {
	idStr := chi.URLParam(r, "id")
	id, _ := strconv.ParseInt(idStr, 10, 64)
	resp := map[string]any{"route_id": id}
	if id == 0 {
		apiJSON(w, http.StatusBadRequest, map[string]any{"error": "bad route id"})
		return
	}
	db := h.DB()
	if db == nil {
		apiJSON(w, http.StatusServiceUnavailable, map[string]any{"error": "db unavailable"})
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 8*time.Second)
	defer cancel()
	if !h.scopeCheckRoute(ctx, middleware.SessionFromContext(r.Context()), id) {
		apiJSON(w, http.StatusForbidden, map[string]any{"error": "forbidden"})
		return
	}
	var resolverIP, resolverPeerIP, upstreamHost, addressFamily string
	err := db.QueryRowContext(ctx,
		`SELECT COALESCE(r.dns_resolver_ip,''), COALESCE(dns_peer.assigned_ip,''),
		        COALESCE(NULLIF(r.backend_ip_override,''), s.backend_ip),
		        COALESCE(r.dns_address_family,'any')
		   FROM routes r
		   JOIN services s ON s.id = r.service_id
		   LEFT JOIN customer_wg_peer dns_peer
		     ON dns_peer.id = r.dns_resolver_via_wg_peer_id AND dns_peer.status <> 'revoked'
		  WHERE r.id = ?`, id,
	).Scan(&resolverIP, &resolverPeerIP, &upstreamHost, &addressFamily)
	if err != nil {
		apiJSON(w, http.StatusNotFound, map[string]any{"error": "route not found"})
		return
	}
	// Pick effective resolver: direct IP wins over peer IP.
	effectiveResolver := resolverIP
	if effectiveResolver == "" {
		effectiveResolver = resolverPeerIP
	}
	resp["resolver"] = effectiveResolver
	resp["host"] = upstreamHost
	resp["address_family"] = addressFamily
	// When upstream is already a bare IP, there is nothing to resolve.
	if net.ParseIP(upstreamHost) != nil {
		resp["resolved"] = []string{upstreamHost}
		resp["latency_ms"] = 0
		resp["ok"] = true
		resp["note"] = "upstream is a bare IP, no DNS lookup needed"
		apiJSON(w, http.StatusOK, resp)
		return
	}
	// Build a resolver pointed at the configured DNS server.
	resolver := net.DefaultResolver
	if effectiveResolver != "" {
		// Refuse loopback/link-local/unspecified resolvers (SSRF guard, also
		// covers legacy rows saved before save-time validation existed).
		if ip := net.ParseIP(effectiveResolver); ip == nil || security.IsDangerousProxyBackend(ip) {
			resp["ok"] = false
			resp["error"] = "resolver address not allowed"
			apiJSON(w, http.StatusOK, resp)
			return
		}
		dialAddr := net.JoinHostPort(effectiveResolver, "53")
		resolver = &net.Resolver{
			PreferGo: true,
			Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
				d := net.Dialer{}
				return d.DialContext(ctx, "udp", dialAddr)
			},
		}
	}
	start := time.Now()
	network := "ip4"
	if addressFamily == "ipv6" {
		network = "ip6"
	}
	addrs, lookupErr := resolver.LookupNetIP(ctx, network, upstreamHost)
	latencyMs := time.Since(start).Milliseconds()
	resp["latency_ms"] = latencyMs
	if lookupErr != nil {
		if h.Logger != nil {
			h.Logger.Warn("dns resolver test failed", "route_id", id, "host", upstreamHost,
				"resolver", effectiveResolver, "err", lookupErr)
		}
		resp["ok"] = false
		// Return a sanitized category, not the raw resolver error (which can
		// leak internal addresses/ports); full detail goes to the log above.
		resp["error"] = dnsTestErrorCategory(lookupErr)
		resp["resolved"] = []string{}
		apiJSON(w, http.StatusOK, resp)
		return
	}
	strs := make([]string, 0, len(addrs))
	for _, a := range addrs {
		strs = append(strs, a.String())
	}
	resp["resolved"] = strs
	resp["ok"] = len(strs) > 0
	apiJSON(w, http.StatusOK, resp)
}

// dnsTestErrorCategory maps a resolver error to a coarse, non-leaky label so
// the test endpoint never echoes raw internal addresses or ports to the admin.
func dnsTestErrorCategory(err error) string {
	if err == nil {
		return ""
	}
	var dnsErr *net.DNSError
	if errors.As(err, &dnsErr) {
		switch {
		case dnsErr.IsTimeout:
			return "resolver timed out"
		case dnsErr.IsNotFound:
			return "name not found (NXDOMAIN)"
		}
		return "resolver query failed"
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return "resolver timed out"
	}
	return "DNS lookup failed"
}

// HostsTestBackend makes a TCP dial to the route's upstream backend and returns
// reachability + latency. Useful for operators debugging why a route isn't
// forwarding — confirms the panel host can reach the backend before Caddy is
// even involved. RFC1918 is allowed (WG mesh peers live there); loopback and
// link-local are blocked via IsDangerousProxyBackend.
func (h *AdminHandlers) HostsTestBackend(w http.ResponseWriter, r *http.Request) {
	id, _ := strconv.ParseInt(chiURLParamHosts(r, "id"), 10, 64)
	if id == 0 {
		apiJSON(w, http.StatusBadRequest, map[string]any{"error": "bad route id"})
		return
	}
	db := h.DB()
	if db == nil {
		apiJSON(w, http.StatusServiceUnavailable, map[string]any{"error": "db unavailable"})
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()
	if !h.scopeCheckRoute(ctx, middleware.SessionFromContext(r.Context()), id) {
		apiJSON(w, http.StatusForbidden, map[string]any{"error": "forbidden"})
		return
	}

	var backendHost string
	var upstreamPort int
	err := db.QueryRowContext(ctx,
		`SELECT COALESCE(NULLIF(r.backend_ip_override,''), s.backend_ip), r.upstream_port
		   FROM routes r JOIN services s ON s.id = r.service_id WHERE r.id = ?`, id,
	).Scan(&backendHost, &upstreamPort)
	if err != nil {
		apiJSON(w, http.StatusNotFound, map[string]any{"error": "route not found"})
		return
	}
	// Resolve hostname if needed, then SSRF-check the resulting IP.
	ip := net.ParseIP(backendHost)
	if ip == nil {
		// hostname — resolve first so the SSRF check sees the real IP
		addrs, err := net.DefaultResolver.LookupNetIP(ctx, "ip", backendHost)
		if err != nil || len(addrs) == 0 {
			apiJSON(w, http.StatusOK, map[string]any{
				"reachable": false,
				"error":     "hostname resolution failed",
				"host":      backendHost,
				"port":      upstreamPort,
			})
			return
		}
		ip = addrs[0].AsSlice()
	}
	if security.IsDangerousProxyBackend(ip) {
		apiJSON(w, http.StatusForbidden, map[string]any{"error": "backend address not allowed"})
		return
	}
	addr := net.JoinHostPort(backendHost, strconv.Itoa(upstreamPort))
	dialCtx, dialCancel := context.WithTimeout(ctx, 5*time.Second)
	defer dialCancel()
	start := time.Now()
	conn, dialErr := (&net.Dialer{}).DialContext(dialCtx, "tcp", addr)
	latencyMs := time.Since(start).Milliseconds()
	if dialErr != nil {
		apiJSON(w, http.StatusOK, map[string]any{
			"reachable":  false,
			"latency_ms": latencyMs,
			"error":      "connection refused or timed out",
			"host":       backendHost,
			"port":       upstreamPort,
		})
		return
	}
	_ = conn.Close()
	apiJSON(w, http.StatusOK, map[string]any{
		"reachable":  true,
		"latency_ms": latencyMs,
		"host":       backendHost,
		"port":       upstreamPort,
	})
}

// HostsRetry re-runs the DNS check on a single route and re-pushes the
// node config. Surfaces "force a renewal" semantically - Caddy's on-
// demand TLS issues / renews certs as part of evaluating the pushed
// config, so a clean re-push is the right unblock when ACME has been
// failing for known-DNS-already-correct hosts.
func (h *AdminHandlers) HostsRetry(w http.ResponseWriter, r *http.Request) {
	if h.Routes == nil || h.DB() == nil {
		http.Error(w, "not ready", http.StatusServiceUnavailable)
		return
	}
	sess := middleware.SessionFromContext(r.Context())
	id, _ := strconv.ParseInt(chiURLParamHosts(r, "id"), 10, 64)
	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()
	// Scoped admins may only retry routes within their assigned clients.
	if !h.scopeCheckRoute(ctx, sess, id) {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	if err := h.Routes.VerifyDNS(ctx, 0, id); err != nil {
		redirectWithFlash(w, r, "/admin/hosts", "", "retry failed: "+sanitizeErr(err))
		return
	}
	audit.Write(ctx, h.DB(), h.Logger, r, audit.Entry{
		UserID: actorUserID(sess), Action: "admin.host.retry", Entity: "route", EntityID: itoa64(id),
	})
	redirectWithFlash(w, r, "/admin/hosts", "Retry triggered", "")
}

// HostsRegenerateSecret rotates the inbound bearer for an external-upstream
// route. Only the AES-GCM ciphertext is stored and it is never logged
// (secret never logged); the new plaintext is recoverable via the audited
// Reveal button, never spliced into a redirect URL.
func (h *AdminHandlers) HostsRegenerateSecret(w http.ResponseWriter, r *http.Request) {
	if h.Routes == nil || h.DB() == nil {
		http.Error(w, "not ready", http.StatusServiceUnavailable)
		return
	}
	sess := middleware.SessionFromContext(r.Context())
	id, _ := strconv.ParseInt(chiURLParamHosts(r, "id"), 10, 64)
	edit := "/admin/hosts/" + strconv.FormatInt(id, 10) + "/edit"
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()
	// Scoped admins may only rotate secrets for routes within their assigned clients.
	if !h.scopeCheckRoute(ctx, sess, id) {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}

	var external bool
	var nodeID int64
	if err := h.DB().QueryRowContext(ctx,
		"SELECT COALESCE(upstream_external,0), caddy_node_id FROM routes WHERE id = ?", id,
	).Scan(&external, &nodeID); err != nil {
		redirectWithFlash(w, r, "/admin/hosts", "", "route not found")
		return
	}
	if !external {
		redirectWithFlash(w, r, edit, "", "not an external route")
		return
	}
	if h.Routes.EncryptSecret == nil {
		redirectWithFlash(w, r, edit, "", "secret encryption not configured")
		return
	}
	plain, err := genProxySecret()
	if err != nil {
		redirectWithFlash(w, r, edit, "", "secret generation failed")
		return
	}
	enc, err := h.Routes.EncryptSecret(plain)
	if err != nil {
		redirectWithFlash(w, r, edit, "", "secret encrypt failed")
		return
	}
	if _, err := h.DB().ExecContext(ctx,
		"UPDATE routes SET proxy_secret_enc = ?, updated_at = NOW() WHERE id = ?", enc, id); err != nil {
		redirectWithFlash(w, r, edit, "", "secret update failed")
		return
	}
	// Re-push so the node enforces the new bearer immediately.
	go func() {
		defer recoverBg(h.Logger, "resync")
		c, cn := context.WithTimeout(h.Routes.BackgroundCtx(), 30*time.Second)
		defer cn()
		_ = h.Routes.Resync(c, nodeID)
	}()
	audit.Write(ctx, h.DB(), h.Logger, r, audit.Entry{
		UserID: actorUserID(sess), Action: "admin.host.regenerate_secret", Entity: "route",
		EntityID: itoa64(id), // never log the plaintext
	})
	redirectWithFlash(w, r, edit, "Bearer rotated. Click Reveal to copy the new inbound token.", "")
}

// HostsRevealSecret returns the current inbound bearer plaintext for an
// external-upstream route so the operator can copy it into their caller.
// Admin-only + CSRF + audited; decrypted from the AES-GCM ciphertext and never
// logged. Deliberate owner-only reveal of a recoverable (not hashed) secret.
func (h *AdminHandlers) HostsRevealSecret(w http.ResponseWriter, r *http.Request) {
	if h.Routes == nil || h.DB() == nil {
		http.Error(w, "not ready", http.StatusServiceUnavailable)
		return
	}
	sess := middleware.SessionFromContext(r.Context())
	id, _ := strconv.ParseInt(chiURLParamHosts(r, "id"), 10, 64)
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()
	// Scoped admins may only reveal secrets for routes within their assigned
	// clients; without this a scoped admin could disclose a foreign tenant's bearer.
	if !h.scopeCheckRoute(ctx, sess, id) {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}

	var external bool
	var enc string
	if err := h.DB().QueryRowContext(ctx,
		"SELECT COALESCE(upstream_external,0), COALESCE(proxy_secret_enc,'') FROM routes WHERE id = ?", id,
	).Scan(&external, &enc); err != nil {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	if !external || enc == "" {
		http.Error(w, "no bearer set", http.StatusNotFound)
		return
	}
	if h.Routes.DecryptSecret == nil {
		http.Error(w, "secret decryption not configured", http.StatusServiceUnavailable)
		return
	}
	plain, err := h.Routes.DecryptSecret(enc)
	if err != nil {
		http.Error(w, "decrypt failed", http.StatusInternalServerError)
		return
	}
	audit.Write(ctx, h.DB(), h.Logger, r, audit.Entry{
		UserID: actorUserID(sess), Action: "admin.host.reveal_secret", Entity: "route",
		EntityID: itoa64(id), // never log the plaintext
	})
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	_ = json.NewEncoder(w).Encode(map[string]string{"secret": plain})
}
