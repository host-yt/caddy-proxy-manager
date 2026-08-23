// Config build: turning route rows into the Caddy JSON one node should serve.
package routes

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/host-yt/caddy-proxy-manager/internal/audit"
	"github.com/host-yt/caddy-proxy-manager/internal/caddyapi"
	"github.com/host-yt/caddy-proxy-manager/internal/geoip"
	"github.com/host-yt/caddy-proxy-manager/internal/security"
)

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
	// Mirror the full /load module gating (probe OR env): the WAF/Geo/RateLimit
	// availability must use the node's probed capability, not just the env flag,
	// or an incremental push emits JSON WITHOUT the handler while a full /load
	// emits it WITH - suppressing the handler and diverging the config hash
	// (endless resync). This is why geo blocking silently dropped on nodes whose
	// module is probe-detected but GEOIP_AVAILABLE is unset.
	probedOr := func(probed sql.NullBool, global bool) bool {
		if probed.Valid {
			return probed.Bool
		}
		return global
	}
	var nHasWAF, nHasGeoIP, nHasRate sql.NullBool
	_ = s.DB.QueryRowContext(ctx,
		`SELECT CASE WHEN modules_probed_at IS NOT NULL THEN has_waf        END,
		        CASE WHEN modules_probed_at IS NOT NULL THEN has_geoip      END,
		        CASE WHEN modules_probed_at IS NOT NULL THEN has_rate_limit END
		   FROM caddy_nodes WHERE id = ?`, nodeID).Scan(&nHasWAF, &nHasGeoIP, &nHasRate)
	for i, id := range ids {
		if id == routeID {
			r := built[i]
			// Match what BuildNodeConfig sets per-route on a full /load so the
			// emitted JSON is identical (drift consistency).
			r.ErrorBranding = branding
			r.CacheModuleAvailable = s.CacheModuleAvailable
			r.RateLimitModuleAvailable = probedOr(nHasRate, s.RateLimitModuleAvailable)
			r.WAFModuleAvailable = probedOr(nHasWAF, s.WAFModuleAvailable)
			r.GeoModuleAvailable = probedOr(nHasGeoIP, s.GeoModuleAvailable) && geoip.HasCountryDB()
			return r, true, nil
		}
	}
	return caddyapi.Route{}, false, nil
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

// geoBlockCfg is the resolved geo-block response config for a route: either the
// owning client's customisation or the panel-wide default.
type geoBlockCfg struct {
	action, redirectURL, title, message, logoURL, bgColor string
}

// loadGeoBlockDefault reads the panel-wide geo-block response default from the
// settings KV table. Used as the fallback when a client has not customised it.
func (s *Service) loadGeoBlockDefault(ctx context.Context) geoBlockCfg {
	var g geoBlockCfg
	if s.DB == nil {
		return g
	}
	c, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	rows, err := s.DB.QueryContext(c,
		"SELECT `key`, value FROM settings WHERE `key` IN ("+
			"'geoblock.action','geoblock.redirect_url','geoblock.title',"+
			"'geoblock.message','geoblock.logo_url','geoblock.bg_color')")
	if err != nil {
		return g
	}
	defer rows.Close()
	for rows.Next() {
		var k, v string
		if err := rows.Scan(&k, &v); err != nil {
			continue
		}
		switch k {
		case "geoblock.action":
			g.action = v
		case "geoblock.redirect_url":
			g.redirectURL = v
		case "geoblock.title":
			g.title = v
		case "geoblock.message":
			g.message = v
		case "geoblock.logo_url":
			g.logoURL = v
		case "geoblock.bg_color":
			g.bgColor = v
		}
	}
	return g
}

// loadTrustCloudflareIP reads the global cloudflare.trust_connecting_ip setting
// (default false). Same key the panel's own CloudflareIP middleware honours, so
// one toggle covers both the panel and the nodes.
func (s *Service) loadTrustCloudflareIP(ctx context.Context) bool {
	if s.DB == nil {
		return false
	}
	c, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	var v string
	_ = s.DB.QueryRowContext(c, "SELECT value FROM settings WHERE `key` = 'cloudflare.trust_connecting_ip'").Scan(&v)
	return v == "1"
}

// loadMTLSFailOpen reads the global mtls.fail_open setting (default false = fail closed).
func (s *Service) loadMTLSFailOpen(ctx context.Context) bool {
	if s.DB == nil {
		return false
	}
	c, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	var v string
	_ = s.DB.QueryRowContext(c, "SELECT value FROM settings WHERE `key` = 'mtls.fail_open'").Scan(&v)
	return v == "1"
}

// resolveRandomEgressIP picks a stable IP for a route from the node's inventory.
// Uses route ID mod len(ips) so the same route always maps to the same IP across rebuilds.
func resolveRandomEgressIP(ips []string, routeID int64) string {
	if len(ips) == 0 {
		return ""
	}
	return ips[int(routeID)%len(ips)]
}

// buildRoutesForNode collects every active/dns_ok/pending_ssl route placed on
// the given node, applies plan overrides, and returns Caddy route structs.
func (s *Service) buildRoutesForNode(ctx context.Context, nodeID int64) ([]caddyapi.Route, []int64, error) {
	// Fetch node's outbound IP inventory for 'random' egress mode resolution.
	var nodeOutboundIPsJSON sql.NullString
	_ = s.DB.QueryRowContext(ctx,
		`SELECT outbound_ips FROM caddy_nodes WHERE id = ?`, nodeID,
	).Scan(&nodeOutboundIPsJSON)
	var nodeOutboundIPs []string
	if nodeOutboundIPsJSON.Valid && nodeOutboundIPsJSON.String != "" {
		_ = json.Unmarshal([]byte(nodeOutboundIPsJSON.String), &nodeOutboundIPs)
	}
	// Panel-wide geo-block default + brand name, used when a client has not
	// customised its own geo-block response. Loaded once per build.
	geoDefault := s.loadGeoBlockDefault(ctx)
	geoBrand := s.loadErrorBranding(ctx).Brand
	// Operator's fail-open choice governs whether a route whose mTLS enforcement
	// cannot be emitted is served open or denied. Loaded once per build.
	mtlsFailOpen := s.loadMTLSFailOpen(ctx)
	rows, err := s.DB.QueryContext(ctx,
		`SELECT r.id, r.domain, COALESCE(r.aliases,''), COALESCE(r.aliases_verified,''), r.path_prefix, r.upstream_port, r.upstream_scheme, r.upstream_skip_tls_verify,
		        r.websocket, r.force_https,
		        r.http2_enabled, r.http3_enabled, r.ssl_enabled,
		        -- Per-route backend_ip_override beats both peer IP and the
		        -- shared service backend_ip, so editing one route doesn't
		        -- change every sibling route that JOINs the same service.
		        COALESCE(NULLIF(r.backend_ip_override, ''), p_use.assigned_ip, sv.backend_ip),
		        COALESCE(p_use.assigned_ip, ''),
		        r.kind, COALESCE(r.redirect_url,''), COALESCE(r.redirect_code,0),
		        r.cache_enabled, r.cache_ttl_secs, COALESCE(r.cache_public,0), COALESCE(r.custom_headers,''),
		        r.maintenance_mode, COALESCE(r.maintenance_message,''),
		        COALESCE(r.cache_vary,''),
		        COALESCE(r.access_allow,''), COALESCE(r.access_deny,''),
		        COALESCE(r.access_block_all, 0), COALESCE(r.maintenance_allow,''),
		        COALESCE(r.custom_config,''),
		        r.via_wg_peer_id, p_use.status,
		        COALESCE(r.basic_auth_user,''), COALESCE(r.basic_auth_bcrypt,''),
		        COALESCE(r.sso_provider_url,''), COALESCE(r.sso_copy_headers,''), COALESCE(r.sso_trusted_proxies,''),
		        COALESCE(r.sso_paths,''), COALESCE(r.sso_hosts,''),
		        COALESCE(r.sso_strict_mode,0),
		        COALESCE(sso_peer.assigned_ip, ''),
	        -- Built-in portal: gate only when the flag is on AND >=1 grant exists,
	        -- otherwise the route would be gated with nobody allowed (effective
	        -- lockout). The verifier still re-checks membership per request.
	        (COALESCE(r.portal_protect,0)=1 AND EXISTS(SELECT 1 FROM route_access_grants rag WHERE rag.route_id=r.id)),
	        COALESCE(r.upstream_external, 0), COALESCE(r.upstream_host_header, ''), COALESCE(r.proxy_secret_enc, ''),
	        COALESCE(r.compress_disabled, 0),
	        COALESCE(r.lb_policy,''),
	        COALESCE(r.lb_header_field,''), COALESCE(r.lb_cookie_name,''), COALESCE(r.lb_cookie_secret,''),
	        COALESCE(r.health_active_uri,''), COALESCE(r.health_active_interval,10), COALESCE(r.health_active_timeout,5),
	        COALESCE(r.health_active_status,0), COALESCE(r.health_active_fails,3),
	        COALESCE(r.health_passive_enabled,0), COALESCE(r.health_passive_fail_dur,30), COALESCE(r.health_passive_max_fail,3),
	        COALESCE(r.lb_try_duration_ms,5000), COALESCE(r.lb_try_interval_ms,250),
	        COALESCE(r.rate_enabled,0), COALESCE(r.rate_window,''), COALESCE(r.rate_max_events,0), COALESCE(r.rate_key,''),
	        COALESCE(r.waf_enabled,0), COALESCE(r.waf_blocking,0), COALESCE(r.waf_directives,''),
	        COALESCE(r.geo_mode,'off'), COALESCE(r.geo_countries,''),
	        COALESCE(r.geo_response_code,403), COALESCE(r.geo_fail_closed,0), COALESCE(r.geo_allow_cidrs,''),
	        COALESCE(r.geo_continents,''), r.geo_block_cidrs,
	        COALESCE(r.error_override,0), COALESCE(r.error_html,''), COALESCE(r.error_logo_url,''),
	        COALESCE(r.error_brand,''), COALESCE(r.error_bg_color,''),
	        COALESCE(r.outbound_ip_mode,'default'), COALESCE(r.outbound_ip,''),
	        COALESCE(pl.allow_egress_ip, 0),
	        COALESCE(r.dns_resolver_ip,''), COALESCE(dns_peer.assigned_ip,''),
	        COALESCE(r.dns_address_family,'any'),
	        COALESCE(r.require_client_cert,0), COALESCE(mca.cert_pem,''),
	        COALESCE(r.dial_timeout_ms,0), COALESCE(r.response_header_timeout_ms,0),
	        COALESCE(cl.geo_block_action,''), COALESCE(cl.geo_block_redirect_url,''),
	        COALESCE(cl.geo_block_title,''), COALESCE(cl.geo_block_message,''),
	        COALESCE(cl.geo_block_logo_url,''), COALESCE(cl.geo_block_bg_color,'')
		 FROM routes r
		 JOIN services sv ON sv.id = r.service_id
		 LEFT JOIN clients cl ON cl.id = sv.client_id
		 LEFT JOIN plans pl ON pl.id = sv.plan_id
		 LEFT JOIN mtls_cas mca ON mca.id = r.mtls_ca_id AND mca.status = 'active'
		 LEFT JOIN customer_wg_peer p_base
		   ON p_base.id = r.via_wg_peer_id
		 LEFT JOIN customer_wg_peer p_use ON (
		     (p_base.peer_group_id IS NOT NULL
		         AND p_use.peer_group_id = p_base.peer_group_id
		         AND p_use.node_id = ?
		         AND p_use.status <> 'revoked')
		     OR (p_base.peer_group_id IS NULL
		         AND p_use.id = r.via_wg_peer_id
		         AND p_use.status <> 'revoked')
		 )
		 LEFT JOIN customer_wg_peer sso_peer
		   ON sso_peer.id = r.sso_via_wg_peer_id
		      AND sso_peer.status <> 'revoked'
		 -- DNS peer is node-scoped like p_use: fan-out nodes must query their
		 -- own group member, not the primary's peer IP.
		 LEFT JOIN customer_wg_peer dns_base
		   ON dns_base.id = r.dns_resolver_via_wg_peer_id
		 LEFT JOIN customer_wg_peer dns_peer ON (
		     (dns_base.peer_group_id IS NOT NULL
		         AND dns_peer.peer_group_id = dns_base.peer_group_id
		         AND dns_peer.node_id = ?
		         AND dns_peer.status <> 'revoked')
		     OR (dns_base.peer_group_id IS NULL
		         AND dns_peer.id = r.dns_resolver_via_wg_peer_id
		         AND dns_peer.status <> 'revoked')
		 )
		 -- Anchor routes plus fan-out copies (active_active/failover peers live
		 -- only in route_node_assignments; without this peers pushed routes: 0).
		 WHERE (r.caddy_node_id = ?
		        OR EXISTS (SELECT 1 FROM route_node_assignments rna
		                    WHERE rna.route_id = r.id AND rna.node_id = ?))
		   AND r.status IN ('dns_ok','active','pending_ssl')
		   -- Defence in depth: only advanceRoute should be able to put a route
		   -- in a serving status, and it refuses unverified ones. A status set
		   -- by any other path must still not emit an unproven host matcher.
		   AND COALESCE(r.domain_verified, 0) = 1
		 ORDER BY r.id ASC`, nodeID, nodeID, nodeID, nodeID)
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
			aliasesVerified                string
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
			cachePublic                    bool
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
		var ssoStrictMode bool
		var ssoResolverIP string
		var portalProtect bool
		var upstreamExternal bool
		var upstreamHostHeader, proxySecretEnc string
		var compressDisabled bool
		var lbPolicy string
		var lbHeaderField, lbCookieName, lbCookieSecret string
		var hActiveURI string
		var hActiveInterval, hActiveTimeout, hActiveStatus, hActiveFails int
		var hPassiveEnabled bool
		var hPassiveFailDur, hPassiveMaxFail int
		var lbTryDurationMs, lbTryIntervalMs int
		var rateEnabled bool
		var rateWindow, rateKey string
		var rateMaxEvents int
		var wafEnabled, wafBlocking bool
		var wafDirectives string
		var geoMode, geoCountries string
		var geoResponseCode int
		var geoFailClosed bool
		var geoAllowCIDRs string
		var geoContinents string
		var geoBlockCIDRs sql.NullString
		var errOverride bool
		var errHTML, errLogo, errBrand, errBg string
		var outboundIPMode, outboundIP string
		var planAllowEgress bool
		var dnsResolverIP, dnsResolverPeerIP, dnsAddressFamily string
		var requireClientCert bool
		var mtlsCACertPEM string
		var dialTimeoutMs, responseHeaderTimeoutMs int
		var clGeoAction, clGeoRedirect, clGeoTitle, clGeoMessage, clGeoLogo, clGeoBg string
		if err := rows.Scan(&id, &domain, &aliases, &aliasesVerified, &path, &port, &scheme, &skipTLS, &ws, &fhttps, &h2, &h3, &sslEnabled, &ip,
			&tunnelResolverIP,
			&kind, &redirURL, &redirCode, &cacheEnabled, &cacheTTL, &cachePublic, &headersJSON,
			&maintMode, &maintMsg, &cacheVary, &accessAllow, &accessDeny,
			&accessBlockAll, &maintenanceAllow, &customCfg,
			&viaPeerID, &peerStatus, &baUser, &baHash,
			&ssoProviderURL, &ssoCopyHeadersRaw, &ssoTrustedProxies,
			&ssoPathsRaw, &ssoHostsRaw,
			&ssoStrictMode,
			&ssoResolverIP,
			&portalProtect,
			&upstreamExternal, &upstreamHostHeader, &proxySecretEnc,
			&compressDisabled,
			&lbPolicy,
			&lbHeaderField, &lbCookieName, &lbCookieSecret,
			&hActiveURI, &hActiveInterval, &hActiveTimeout, &hActiveStatus, &hActiveFails,
			&hPassiveEnabled, &hPassiveFailDur, &hPassiveMaxFail,
			&lbTryDurationMs, &lbTryIntervalMs,
			&rateEnabled, &rateWindow, &rateMaxEvents, &rateKey,
			&wafEnabled, &wafBlocking, &wafDirectives,
			&geoMode, &geoCountries,
			&geoResponseCode, &geoFailClosed, &geoAllowCIDRs,
			&geoContinents, &geoBlockCIDRs,
			&errOverride, &errHTML, &errLogo, &errBrand, &errBg,
			&outboundIPMode, &outboundIP, &planAllowEgress,
			&dnsResolverIP, &dnsResolverPeerIP, &dnsAddressFamily,
			&requireClientCert, &mtlsCACertPEM,
			&dialTimeoutMs, &responseHeaderTimeoutMs,
			&clGeoAction, &clGeoRedirect, &clGeoTitle, &clGeoMessage, &clGeoLogo, &clGeoBg); err != nil {
			return nil, nil, err
		}
		// Re-check plan entitlement at build time so revoking the flag takes effect immediately.
		if !planAllowEgress {
			outboundIPMode = "default"
			outboundIP = ""
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
		// Resolve 'random' egress to a stable concrete IP so static Caddy config can use it.
		if outboundIPMode == "random" {
			if picked := resolveRandomEgressIP(nodeOutboundIPs, id); picked != "" {
				outboundIP = picked
			} else {
				outboundIPMode = "default"
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
		// Only PROVEN aliases become host matchers: an alias whose ownership was
		// never demonstrated would otherwise intercept the real owner's traffic.
		proven := map[string]bool{}
		for _, a := range splitHostList(aliasesVerified) {
			proven[a] = true
		}
		hosts := []string{domain}
		for _, a := range splitHostList(aliases) {
			if a != domain && proven[a] {
				hosts = append(hosts, a)
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
		// Hostname backend over tunnel needs a DNS resolver (dynamic
		// upstreams resolve it via the peer). Without one, fall back to
		// peer IP so the route doesn't 502 on an unresolvable name.
		// External routes exempt - their upstream is a public FQDN.
		if !external && tunnelResolverIP != "" && ip != "" && !looksLikeIP(ip) &&
			dnsResolverIP == "" && dnsResolverPeerIP == "" {
			ip = tunnelResolverIP
		}
		backendResolver := ""
		// lb_cookie_secret is stored encrypted at rest (SECRET-02); decrypt for
		// the Caddy push. Legacy plaintext rows fall through unchanged.
		if lbCookieSecret != "" && s.DecryptSecret != nil {
			if dec, derr := s.DecryptSecret(lbCookieSecret); derr == nil {
				lbCookieSecret = dec
			}
		}
		// Resolve geo-block response: a client's own customisation wins over the
		// panel-wide default (empty client action = inherit the default).
		gb := geoDefault
		if strings.TrimSpace(clGeoAction) != "" {
			gb = geoBlockCfg{clGeoAction, clGeoRedirect, clGeoTitle, clGeoMessage, clGeoLogo, clGeoBg}
		}
		// An enabled auth gate that cannot be emitted must not silently vanish.
		// mTLS respects the operator's mtls.fail_open; the portal never does.
		portalReady := s.PanelInternalHost != "" && s.PanelInternalPort != 0
		mtlsEnforceable := sslEnabled && mtlsCACertPEM != "" && caddyapi.MTLSCAUsable(mtlsCACertPEM)
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
			CachePublic:           cachePublic,
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
			SSOResolver:   ssoResolverIP,
			SSOStrictMode: ssoStrictMode,

			// Built-in forward-auth portal. Verify + login are dialed at the
			// panel (same internal host:port as the self-bootstrap route). Plain
			// HTTP over the internal network; the panel sets the protected-host
			// cookie itself. Skipped entirely when PanelInternalHost is unset.
			PortalProtect: portalProtect && portalReady,
			PortalDial:    s.portalDial(),
			// Portal is an explicit per-route opt-in: no verifier means deny,
			// never silently serve the protected backend to the public.
			PortalDenyOnMisconfig: portalProtect && !portalReady,

			// External HTTPS upstream: SNI + Host both use the stored header
			// (falls back to the FQDN in the builder); ProxySecret gates inbound.
			External:                external,
			UpstreamSNI:             upstreamHostHeader,
			UpstreamHostHeader:      upstreamHostHeader,
			ProxySecret:             proxySecret,
			CompressDisabled:        compressDisabled,
			LBPolicy:                lbPolicy,
			LBHeaderField:           lbHeaderField,
			LBCookieName:            lbCookieName,
			LBCookieSecret:          lbCookieSecret,
			WeightedLBAvailable:     s.WeightedLBAvailable,
			LBTryDurationMs:         lbTryDurationMs,
			LBTryIntervalMs:         lbTryIntervalMs,
			DialTimeoutMs:           dialTimeoutMs,
			ResponseHeaderTimeoutMs: responseHeaderTimeoutMs,
			HealthURI:               hActiveURI,
			HealthIntervalSecs:      hActiveInterval,
			HealthTimeoutSecs:       hActiveTimeout,
			HealthExpectStatus:      hActiveStatus,
			HealthFails:             hActiveFails,
			HealthPassive:           hPassiveEnabled,
			HealthFailDurationSecs:  hPassiveFailDur,
			HealthMaxFails:          hPassiveMaxFail,

			RateLimitEnabled:         rateEnabled,
			RateLimitWindow:          rateWindow,
			RateLimitMaxEvents:       rateMaxEvents,
			RateLimitKey:             rateKey,
			RateLimitModuleAvailable: s.RateLimitModuleAvailable,
			WAFEnabled:               wafEnabled,
			WAFBlocking:              wafBlocking,
			WAFDirectives:            wafDirectives,
			WAFModuleAvailable:       s.WAFModuleAvailable,
			GeoMode:                  geoMode,
			GeoCountries:             geoCountries,
			GeoModuleAvailable:       s.GeoModuleAvailable && geoip.HasCountryDB(),
			GeoResponseCode:          geoResponseCode,
			GeoFailClosed:            geoFailClosed,
			GeoAllowCIDRs:            geoAllowCIDRs,
			GeoContinents:            geoContinents,
			GeoBlockCIDRs:            geoBlockCIDRs.String,
			GeoBlockAction:           gb.action,
			GeoRedirectURL:           gb.redirectURL,
			GeoBlockTitle:            gb.title,
			GeoBlockMessage:          gb.message,
			GeoBlockBranding:         caddyapi.ErrorBranding{Brand: geoBrand, LogoURL: gb.logoURL, BgColor: gb.bgColor},

			// Per-route error/maintenance page override (else node-wide branding).
			CustomErrorOverride: errOverride,
			CustomErrorHTML:     errHTML,
			CustomErrorBranding: caddyapi.ErrorBranding{LogoURL: errLogo, Brand: errBrand, BgColor: errBg},

			OutboundIPMode: outboundIPMode,
			OutboundIP:     outboundIP,

			DNSResolverIP:          dnsResolverIP,
			DNSResolverViaWGPeerIP: dnsResolverPeerIP,
			DNSAddressFamily:       dnsAddressFamily,

			// mTLS client-cert enforcement only over TLS, and only when the
			// selected CA is still active AND parsable (JOIN yields '' otherwise).
			RequireClientCert: requireClientCert && mtlsEnforceable,
			MTLSCACertPEM:     mtlsCACertPEM,
			// No enforceable policy + fail-closed operator setting = deny the
			// route instead of serving it with no client-cert requirement.
			MTLSDenyOnMisconfig: requireClientCert && !mtlsEnforceable && !mtlsFailOpen,
			PanelBaseURL:        panelBaseURL(s.AskURL),
		})
		// Audit the quarantine: BuildRoute replaces the whole route with a 503,
		// so without this the operator sees an outage with no stated cause.
		if reason := caddyapi.CustomHandlerQuarantine(built[len(built)-1]); reason != "" {
			s.Logger.Error("route quarantined: custom handler chain rejected",
				"route_id", id, "domain", domain, "reason", reason)
			audit.Write(ctx, s.DB, s.Logger, nil, audit.Entry{
				ActorType: audit.ActorSystem,
				Action:    "route.custom_handlers.quarantined",
				Entity:    "route",
				EntityID:  fmt.Sprintf("%d", id),
				Meta:      map[string]any{"domain": domain, "reason": reason},
			})
		}
		// Audit when require_client_cert=1 but enforcement is skipped (no active
		// CA, SSL off, unparsable PEM, or mtls_ca_id NULL).
		if requireClientCert && !mtlsEnforceable {
			audit.Write(ctx, s.DB, s.Logger, nil, audit.Entry{
				ActorType: audit.ActorSystem,
				Action:    "route.mtls.pushed_without_tls",
				Entity:    "route",
				EntityID:  fmt.Sprintf("%d", id),
				Meta:      map[string]any{"domain": domain, "fail_open": mtlsFailOpen},
			})
		}
		ids = append(ids, id)
	}
	// Attach additional backends (route_upstreams) in one batched query to
	// avoid N+1; zero-row routes keep their single-dial primary. Best-effort:
	// a query error leaves routes single-dial rather than failing the build.
	s.attachRouteUpstreams(ctx, built, ids)
	s.attachLocationRules(ctx, built, ids)
	s.attachBasicAuthUsers(ctx, built, ids)
	s.attachMTLSPathRules(ctx, built, ids)
	s.attachRBACTokens(built, ids, nodeID)
	// Emission order, not DB id order: a catch-all ahead of a narrower sibling
	// on the same host would shadow it. ids must follow the same permutation -
	// buildOneRoute pairs ids[i] with built[i].
	if ord := caddyapi.EmissionOrder(built); len(ids) == len(built) {
		sortedBuilt := make([]caddyapi.Route, len(built))
		sortedIDs := make([]int64, len(ids))
		for k, i := range ord {
			sortedBuilt[k] = built[i]
			sortedIDs[k] = ids[i]
		}
		built, ids = sortedBuilt, sortedIDs
	}
	return built, ids, nil
}

// attachBasicAuthUsers loads route_basic_auth_users in one IN(...) query and
// maps them onto the built routes. Routes with users get BasicAuthUsers set;
// routes without rows keep the legacy single-user BasicAuthUser/BasicAuthBcrypt.
func (s *Service) attachBasicAuthUsers(ctx context.Context, built []caddyapi.Route, ids []int64) {
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
		`SELECT route_id, username, bcrypt_hash
		   FROM route_basic_auth_users
		  WHERE route_id IN (`+strings.Join(ph, ",")+`)
		  ORDER BY route_id, username ASC`, args...)
	if err != nil {
		if s.Logger != nil {
			s.Logger.Warn("route_basic_auth_users load failed; using single-user fallback", "err", err)
		}
		return
	}
	defer rows.Close()
	for rows.Next() {
		var rid int64
		var u caddyapi.BasicAuthUser
		if err := rows.Scan(&rid, &u.Username, &u.Hash); err != nil {
			continue
		}
		if i, ok := idx[rid]; ok {
			built[i].BasicAuthUsers = append(built[i].BasicAuthUsers, u)
		}
	}
}

// attachMTLSPathRules loads mtls_path_rules for the given route IDs in one
// batch query and sets MTLSPathRules on each matching route.
func (s *Service) attachMTLSPathRules(ctx context.Context, built []caddyapi.Route, ids []int64) {
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
		`SELECT pr.route_id, ro.name, pr.path_pattern
		   FROM mtls_path_rules pr
		   JOIN mtls_roles ro ON ro.id = pr.required_role_id
		  WHERE pr.route_id IN (`+strings.Join(ph, ",")+`)
		  ORDER BY pr.route_id, pr.id ASC`, args...)
	if err != nil {
		if s.Logger != nil {
			s.Logger.Warn("mtls_path_rules load failed", "err", err)
		}
		return
	}
	defer rows.Close()
	for rows.Next() {
		var rid int64
		var role, pattern string
		if err := rows.Scan(&rid, &role, &pattern); err != nil {
			continue
		}
		if i, ok := idx[rid]; ok {
			built[i].MTLSPathRules = append(built[i].MTLSPathRules, caddyapi.MTLSPathRule{
				PathPattern:  pattern,
				RequiredRole: role,
			})
		}
	}
}

// attachRBACTokens stamps the per-(node, route) mTLS RBAC check token onto
// every route that runs a forward_auth role check. The token proves to the
// panel that the check subrequest comes from a node the control plane actually
// placed the route on, instead of from any host that happens to sit inside the
// mesh or trusted-proxy CIDRs (MTLS-01). No key configured = no token: the
// panel then falls back to its allow-list-only behaviour.
func (s *Service) attachRBACTokens(built []caddyapi.Route, ids []int64, nodeID int64) {
	if len(s.MTLSRBACKey) == 0 || nodeID <= 0 || len(ids) != len(built) {
		return
	}
	for i := range built {
		if len(built[i].MTLSPathRules) == 0 {
			continue
		}
		built[i].RBACNodeID = nodeID
		built[i].RBACToken = security.MTLSRBACToken(s.MTLSRBACKey, nodeID, ids[i])
	}
}

// panelBaseURL extracts scheme://host from a full URL (e.g. AskURL).
func panelBaseURL(askURL string) string {
	if askURL == "" {
		return ""
	}
	u, err := url.Parse(askURL)
	if err != nil || u.Host == "" {
		return ""
	}
	return u.Scheme + "://" + u.Host
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
		`SELECT route_id, host, port, weight, COALESCE(max_requests,0), COALESCE(enabled,1)
		   FROM route_upstreams
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
		var port, weight, maxReq int
		var enabled bool
		if err := rows.Scan(&rid, &host, &port, &weight, &maxReq, &enabled); err != nil {
			continue
		}
		// Soft-disabled upstreams are excluded from the emitted pool.
		if !enabled {
			continue
		}
		if i, ok := idx[rid]; ok {
			built[i].Upstreams = append(built[i].Upstreams, caddyapi.Upstream{
				Host:        host,
				Port:        port,
				Weight:      weight,
				MaxRequests: maxReq,
			})
		}
	}
}

func (s *Service) attachLocationRules(ctx context.Context, built []caddyapi.Route, ids []int64) {
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
		`SELECT route_id, path_glob, action, COALESCE(upstream_host,''), COALESCE(upstream_port,0),
		        upstream_scheme, COALESCE(redirect_url,''), COALESCE(redirect_code,308), COALESCE(rewrite_uri,'')
		   FROM route_location_rules
		  WHERE route_id IN (`+strings.Join(ph, ",")+`)
		  ORDER BY route_id, sort_order ASC, id ASC`, args...)
	if err != nil {
		if s.Logger != nil {
			s.Logger.Warn("route_location_rules load failed; path rules skipped", "err", err)
		}
		return
	}
	defer rows.Close()
	for rows.Next() {
		var rid int64
		var rule caddyapi.LocationRule
		if err := rows.Scan(&rid, &rule.Path, &rule.Action, &rule.UpstreamHost, &rule.UpstreamPort,
			&rule.UpstreamScheme, &rule.RedirectURL, &rule.RedirectCode, &rule.RewriteURI); err != nil {
			continue
		}
		if i, ok := idx[rid]; ok {
			built[i].LocationRules = append(built[i].LocationRules, rule)
		}
	}
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

// buildManualCertsForNode returns operator-imported certs to load into this
// node's Caddy cert pool: every manual_cert linked to a route this node serves
// (direct caddy_node_id or a route_node_assignments fan-out), with its private
// key decrypted. Same node-membership + status filter as buildRoutesForNode so
// a cert is only shipped when its route is actually emitted. Unlinked certs
// (route_id NULL) are stored-only and never pushed - the link is the binding.
func (s *Service) buildManualCertsForNode(ctx context.Context, nodeID int64) []caddyapi.ManualCertPEM {
	if s.DB == nil || s.DecryptSecret == nil {
		return nil
	}
	rows, err := s.DB.QueryContext(ctx,
		`SELECT mc.cert_pem, COALESCE(mc.chain_pem,''), mc.key_pem_enc
		   FROM manual_certs mc
		   JOIN routes r ON r.id = mc.route_id
		  WHERE (r.caddy_node_id = ?
		         OR EXISTS (SELECT 1 FROM route_node_assignments rna
		                     WHERE rna.route_id = r.id AND rna.node_id = ?))
		    AND r.ssl_enabled = 1
		    AND r.status IN ('dns_ok','active','pending_ssl')
		  ORDER BY mc.id ASC`, nodeID, nodeID)
	if err != nil {
		s.Logger.Error("manual certs: query failed", "node_id", nodeID, "err", err)
		return nil
	}
	defer rows.Close()
	var out []caddyapi.ManualCertPEM
	for rows.Next() {
		var certPEM, chainPEM, keyEnc string
		if err := rows.Scan(&certPEM, &chainPEM, &keyEnc); err != nil {
			continue
		}
		key, derr := s.DecryptSecret(keyEnc)
		if derr != nil || key == "" {
			// Never emit a cert with no key: Caddy would reject the whole /load.
			s.Logger.Error("manual certs: key decrypt failed, skipping", "node_id", nodeID)
			continue
		}
		// Caddy's load_pem wants leaf + chain in one PEM blob.
		bundle := strings.TrimRight(certPEM, "\n")
		if c := strings.TrimSpace(chainPEM); c != "" {
			bundle += "\n" + c
		}
		out = append(out, caddyapi.ManualCertPEM{CertPEM: bundle, KeyPEM: key})
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
