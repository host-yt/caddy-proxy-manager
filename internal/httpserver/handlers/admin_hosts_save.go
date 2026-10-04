package handlers

import (
	"context"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/host-yt/caddy-proxy-manager/internal/audit"
	"github.com/host-yt/caddy-proxy-manager/internal/caddyapi"
	"github.com/host-yt/caddy-proxy-manager/internal/customfields"
	"github.com/host-yt/caddy-proxy-manager/internal/domain/routes"
	"github.com/host-yt/caddy-proxy-manager/internal/geoip"
	"github.com/host-yt/caddy-proxy-manager/internal/httpserver/middleware"
	"github.com/host-yt/caddy-proxy-manager/internal/security"
)

// HostsUpdate handles POST /admin/hosts/{id}/edit.
func (h *AdminHandlers) HostsUpdate(w http.ResponseWriter, r *http.Request) {
	if h.Routes == nil || h.DB() == nil {
		http.Error(w, "not ready", http.StatusServiceUnavailable)
		return
	}
	id, _ := strconv.ParseInt(chiURLParamHosts(r, "id"), 10, 64)
	if id == 0 {
		http.Redirect(w, r, "/admin/hosts", http.StatusSeeOther)
		return
	}
	sess := middleware.SessionFromContext(r.Context())
	// Scoped admins must not update hosts outside their client scope.
	if !h.scopeCheckRoute(r.Context(), sess, id) {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	// Needed up front: a validation failure anywhere below re-renders the edit
	// form, which needs this route's owning client to reload its reference data.
	var ownerClientID int64
	_ = h.DB().QueryRowContext(r.Context(),
		`SELECT s.client_id FROM routes r JOIN services s ON s.id = r.service_id WHERE r.id = ?`, id).Scan(&ownerClientID)
	_ = r.ParseForm()
	domain := strings.TrimSpace(strings.ToLower(r.FormValue("domain")))
	pathPrefix := strings.TrimSpace(r.FormValue("path_prefix"))
	backendIP := strings.TrimSpace(r.FormValue("backend_ip"))
	port, _ := strconv.Atoi(r.FormValue("port"))
	kind := strings.TrimSpace(r.FormValue("kind"))
	if kind != "redirect" {
		kind = "proxy"
	}
	// External HTTPS upstream (admin-only). Parsed early so the customer-backend
	// port/host validation below is skipped; full validation + force-shape +
	// mutual exclusion happens once via_wg_peer_id is parsed.
	external := r.FormValue("upstream_external") == "1"
	externalHost := strings.ToLower(strings.TrimSpace(r.FormValue("external_host")))
	extHostHeader := strings.TrimSpace(r.FormValue("upstream_host_header"))
	if external {
		kind = "proxy"
	}
	redirectURL := strings.TrimSpace(r.FormValue("redirect_url"))
	redirectCode, _ := strconv.Atoi(r.FormValue("redirect_code"))
	ssl := r.FormValue("ssl") == "1"
	forceHTTPS := r.FormValue("force_https") == "1"
	websocket := r.FormValue("websocket") == "1"
	http2 := r.FormValue("http2") == "1"
	http3 := r.FormValue("http3") == "1"
	cacheEnabled := r.FormValue("cache_enabled") == "1"
	// Shared caching is opt-in: without it the route is private-only, because
	// the panel cannot see auth the upstream performs itself.
	cachePublic := r.FormValue("cache_public") == "1"
	compressDisabled := r.FormValue("compress_disabled") == "1"

	// Load balancing + health checks (A2). Policy is allowlisted; weighted is
	// rejected unless the module gate is on so stock nodes never break.
	lbPolicy := r.FormValue("lb_policy")
	switch lbPolicy {
	case "", "round_robin", "least_conn", "ip_hash", "uri_hash", "header", "cookie",
		"random", "random_choose", "client_ip_hash", "query", "first":
	case "weighted_round_robin":
		if !h.Routes.WeightedLBAvailable {
			lbPolicy = "round_robin"
		}
	default:
		lbPolicy = ""
	}
	lbHeaderField := strings.TrimSpace(r.FormValue("lb_header_field"))
	lbCookieName := strings.TrimSpace(r.FormValue("lb_cookie_name"))
	lbCookieSecret := strings.TrimSpace(r.FormValue("lb_cookie_secret"))
	// Encrypt the LB sticky-cookie signing secret at rest (SECRET-02); the
	// Caddy push path decrypts it. Form carries the plaintext (edit view
	// decrypts for display), so a re-save re-seals cleanly.
	if lbCookieSecret != "" && h.Routes.EncryptSecret != nil {
		if enc, eerr := h.Routes.EncryptSecret(lbCookieSecret); eerr == nil {
			lbCookieSecret = enc
		}
	}
	healthURI := strings.TrimSpace(r.FormValue("health_uri"))
	if healthURI != "" && !strings.HasPrefix(healthURI, "/") {
		healthURI = "/" + healthURI
	}
	healthInterval := clampInt(atoiDefault(r.FormValue("health_interval"), 10), 1, 300)
	healthTimeout := clampInt(atoiDefault(r.FormValue("health_timeout"), 5), 1, 60)
	healthStatus := atoiDefault(r.FormValue("health_expect_status"), 0)
	if healthStatus != 0 && (healthStatus < 100 || healthStatus > 599) {
		healthStatus = 0
	}
	healthFails := clampInt(atoiDefault(r.FormValue("health_fails"), 3), 1, 10)
	healthPassive := r.FormValue("health_passive") == "1"
	healthFailDur := clampInt(atoiDefault(r.FormValue("health_fail_dur"), 30), 1, 600)
	healthMaxFails := clampInt(atoiDefault(r.FormValue("health_max_fails"), 3), 1, 10)
	// Retry timing: total budget (0 = default 5000ms) and per-attempt delay
	// (0 = no inter-attempt delay). Clamped: duration 100-300000ms, interval 0-60000ms.
	lbTryDurationMs := clampInt(atoiDefault(r.FormValue("lb_try_duration_ms"), 5000), 100, 300000)
	lbTryIntervalMs := clampInt(atoiDefault(r.FormValue("lb_try_interval_ms"), 250), 0, 60000)
	dialTimeoutMs := clampInt(atoiDefault(r.FormValue("dial_timeout_ms"), 0), 0, 300000)
	responseHeaderTimeoutMs := clampInt(atoiDefault(r.FormValue("response_header_timeout_ms"), 0), 0, 300000)
	// Additional backends arrive as parallel arrays. Admin-only internal
	// targets (same trust level as backend_ip) so the host validator suffices.
	upHosts := r.Form["upstream_host[]"]
	upPorts := r.Form["upstream_port[]"]
	upWeights := r.Form["upstream_weight[]"]
	upMaxReqs := r.Form["upstream_max_requests[]"]
	upEnabled := r.Form["upstream_enabled[]"] // checkbox: present = enabled
	var newUpstreams []upstreamRow
	for i := range upHosts {
		host := strings.TrimSpace(upHosts[i])
		if host == "" {
			continue
		}
		port := 0
		if i < len(upPorts) {
			port = atoiDefault(upPorts[i], 0)
		}
		if !isValidUpstreamHost(host) || port < 1 || port > 65535 {
			continue
		}
		weight := 1
		if i < len(upWeights) {
			weight = clampInt(atoiDefault(upWeights[i], 1), 1, 100)
		}
		maxReq := 0
		if i < len(upMaxReqs) {
			maxReq = clampInt(atoiDefault(upMaxReqs[i], 0), 0, 100000)
		}
		// Checkboxes only submit when ticked; presence of index in enabled slice signals enabled.
		enabled := true
		if i < len(upEnabled) {
			enabled = upEnabled[i] == "1"
		}
		newUpstreams = append(newUpstreams, upstreamRow{
			Host: host, Port: port, Weight: weight, MaxRequests: maxReq, Enabled: enabled,
		})
	}
	newLocationRules, locErr := sanitizeLocationRules(r.Form)
	if locErr != nil {
		redirectWithFlash(w, r, "/admin/hosts/"+strconv.FormatInt(id, 10)+"/edit#tab=locations", "", "routing rule: "+sanitizeErr(locErr))
		return
	}

	// Rate limiting (A3). Window must be a valid Go duration when enabled.
	rateEnabled := r.FormValue("rate_enabled") == "1"
	rateWindow := strings.TrimSpace(r.FormValue("rate_window"))
	if rateWindow == "" {
		rateWindow = "1m"
	}
	rateMaxEvents := atoiDefault(r.FormValue("rate_max_events"), 100)
	if rateMaxEvents <= 0 {
		rateMaxEvents = 100
	}
	rateKey := strings.TrimSpace(r.FormValue("rate_key"))
	if rateKey == "custom" {
		rateKey = strings.TrimSpace(r.FormValue("rate_key_custom"))
	}
	if rateKey == "" {
		rateKey = "{http.request.remote.host}"
	}
	// Stored even when the limiter is off, so screen it with the same policy
	// emission uses instead of letting it quarantine the host at the next push.
	if err := caddyapi.ScreenTenantRateKey(rateKey); err != nil {
		redirectWithFlash(w, r, "/admin/hosts/"+strconv.FormatInt(id, 10)+"/edit", "", "rate limit key: "+sanitizeErr(err))
		return
	}
	if rateEnabled {
		if _, derr := time.ParseDuration(rateWindow); derr != nil {
			redirectWithFlash(w, r, "/admin/hosts/"+strconv.FormatInt(id, 10)+"/edit", "", "rate limit: invalid window (e.g. 1m, 30s)")
			return
		}
		if rateMaxEvents < 1 || rateMaxEvents > 1000000 {
			redirectWithFlash(w, r, "/admin/hosts/"+strconv.FormatInt(id, 10)+"/edit", "", "rate limit: max events must be 1-1000000")
			return
		}
	}
	// WAF (A4). Detection-only unless blocking is also ticked.
	wafEnabled := r.FormValue("waf_enabled") == "1"
	wafBlocking := r.FormValue("waf_blocking") == "1"
	wafDirectives := strings.TrimSpace(r.FormValue("waf_directives"))
	if len(wafDirectives) > 16384 {
		redirectWithFlash(w, r, "/admin/hosts/"+strconv.FormatInt(id, 10)+"/edit", "", "WAF: custom directives too long (16 KiB max)")
		return
	}
	if wafDirectives != "" {
		if err := h.checkWAFDirectives(r.Context(), sess, id, wafDirectives); err != nil {
			redirectWithFlash(w, r, "/admin/hosts/"+strconv.FormatInt(id, 10)+"/edit#tab=waf", "", "WAF: "+sanitizeErr(err))
			return
		}
	}
	// Geo blocking. Normalize codes (uppercase, dedupe, drop junk); off when no mode.
	geoMode := strings.ToLower(strings.TrimSpace(r.FormValue("geo_mode")))
	if geoMode != "allow" && geoMode != "deny" {
		geoMode = "off"
	}
	geoCountries := geoip.NormalizeCountries(r.FormValue("geo_countries"))
	geoResponseCodeRaw, _ := strconv.Atoi(r.FormValue("geo_response_code"))
	if geoResponseCodeRaw == 0 {
		geoResponseCodeRaw = 403
	}
	geoFailClosed := r.FormValue("geo_fail_closed") == "1"
	// Validate + normalize to a comma list: a bad entry must surface to the
	// operator, not silently vanish (block-list drops would fail open) or reach
	// Caddy as a newline blob that rejects the whole /load.
	geoAllowCIDRs, errGA := sanitizeCIDRList(r.FormValue("geo_allow_cidrs"))
	if errGA != nil {
		redirectWithFlash(w, r, "/admin/hosts/"+strconv.FormatInt(id, 10)+"/edit", "", "geo allow list: "+sanitizeErr(errGA))
		return
	}
	geoContinents := geoip.NormalizeCountries(r.FormValue("geo_continents"))
	geoBlockCIDRs, errGB := sanitizeCIDRList(r.FormValue("geo_block_cidrs"))
	if errGB != nil {
		redirectWithFlash(w, r, "/admin/hosts/"+strconv.FormatInt(id, 10)+"/edit", "", "geo block list: "+sanitizeErr(errGB))
		return
	}
	// Post-quantum-only TLS: no validation needed, it is a pure connection
	// policy knob whose blast radius is documented inline in the form.
	tlsPQOnly := r.FormValue("tls_pq_only") == "1"
	// mTLS client-cert enforcement. require_client_cert needs a valid CA; an
	// enforced host with no CA would brick the handshake, so reject early.
	requireClientCert := r.FormValue("require_client_cert") == "1"
	mtlsCAID, _ := strconv.ParseInt(r.FormValue("mtls_ca_id"), 10, 64)
	if requireClientCert && mtlsCAID <= 0 {
		redirectWithFlash(w, r, "/admin/hosts/"+strconv.FormatInt(id, 10)+"/edit", "", "require_client_cert needs an mTLS CA assigned")
		return
	}
	if requireClientCert && mtlsCAID > 0 {
		// Reject if CA has no uploaded certificate or is not active.
		var caCount int
		_ = h.DB().QueryRowContext(r.Context(),
			"SELECT COUNT(*) FROM mtls_cas WHERE id=? AND status='active' AND cert_pem IS NOT NULL AND cert_pem != ''",
			mtlsCAID).Scan(&caCount)
		if caCount == 0 {
			redirectWithFlash(w, r, "/admin/hosts/"+strconv.FormatInt(id, 10)+"/edit", "", "selected mTLS CA is not active - upload a certificate first")
			return
		}
	}
	if !requireClientCert {
		mtlsCAID = 0 // clear the anchor when enforcement is off
	}
	// Wildcard DNS-01 (B1). Zone must cover the route domain when enabled.
	wildcardEnabled := r.FormValue("wildcard_enabled") == "1"
	wildcardZone := strings.ToLower(strings.TrimSpace(r.FormValue("wildcard_zone")))
	if wildcardEnabled {
		d := strings.ToLower(domain)
		if wildcardZone == "" || (d != wildcardZone && !strings.HasSuffix(d, "."+wildcardZone)) {
			redirectWithFlash(w, r, "/admin/hosts/"+strconv.FormatInt(id, 10)+"/edit", "", "wildcard: zone must cover the domain (e.g. zone customer.com for app.customer.com)")
			return
		}
	}

	// Outbound/egress IP. Only proxy routes need it; ignored for redirect/maintenance.
	outboundIPMode := r.FormValue("outbound_ip_mode")
	switch outboundIPMode {
	case "fixed", "random":
	default:
		outboundIPMode = "default"
	}
	outboundIP := strings.TrimSpace(r.FormValue("outbound_ip"))
	// Plan gate: check whether the plan allows non-default egress.
	editPath := "/admin/hosts/" + strconv.FormatInt(id, 10) + "/edit"
	// Hard block: reject save when a module-gated feature is on but the node lacks
	// the Caddy module. Effective capability = the per-node operator-declared flag
	// if the node was declared (modules_probed_at set), else the fleet-wide env
	// flag. Mirrors probedOr() in routes.Service.buildNodePush so the gate matches
	// what actually gets emitted.
	{
		var probedWAF, probedGeo, probedRate sql.NullBool
		_ = h.DB().QueryRowContext(r.Context(),
			`SELECT CASE WHEN n.modules_probed_at IS NOT NULL THEN n.has_waf        END,
			        CASE WHEN n.modules_probed_at IS NOT NULL THEN n.has_geoip      END,
			        CASE WHEN n.modules_probed_at IS NOT NULL THEN n.has_rate_limit END
			   FROM routes r JOIN caddy_nodes n ON n.id = r.caddy_node_id WHERE r.id = ?`, id,
		).Scan(&probedWAF, &probedGeo, &probedRate)
		// Default true (don't block) when env flags are unknown; emission still
		// gates via probedOr, so a false env never breaks the node here.
		effWAF, effGeo, effRate := true, true, true
		if h.Routes != nil {
			effWAF = h.Routes.WAFModuleAvailable
			effGeo = h.Routes.GeoModuleAvailable
			effRate = h.Routes.RateLimitModuleAvailable
		}
		if probedWAF.Valid {
			effWAF = probedWAF.Bool
		}
		if probedGeo.Valid {
			effGeo = probedGeo.Bool
		}
		if probedRate.Valid {
			effRate = probedRate.Bool
		}
		if wafEnabled && !effWAF {
			redirectWithFlash(w, r, editPath, "", "WAF requires the coraza-caddy/v2 module. Enable WAF_MODULE_AVAILABLE, or tick WAF (Coraza) under Module capabilities on the node edit page once Caddy is built with it.")
			return
		}
		if geoMode != "off" && !effGeo {
			redirectWithFlash(w, r, editPath, "", "GeoIP filtering requires the caddy-maxmind-geolocation module. Enable GEOIP_AVAILABLE, or tick GeoIP under Module capabilities on the node edit page once Caddy is built with it.")
			return
		}
		if rateEnabled && !effRate {
			redirectWithFlash(w, r, editPath, "", "Rate limiting requires the caddy-ratelimit module. Enable RATE_LIMIT_AVAILABLE, or tick Rate limit under Module capabilities on the node edit page once Caddy is built with it.")
			return
		}
	}
	if outboundIPMode != "default" {
		var planAllowEgress bool
		_ = h.DB().QueryRowContext(r.Context(),
			`SELECT COALESCE(p.allow_egress_ip,0)
			   FROM routes r
			   JOIN services s ON s.id = r.service_id
			   JOIN plans p ON p.id = s.plan_id
			  WHERE r.id = ?`, id,
		).Scan(&planAllowEgress)
		if !planAllowEgress {
			redirectWithFlash(w, r, editPath, "", "egress: plan does not allow custom egress IP")
			return
		}
	}
	if outboundIPMode == "fixed" && outboundIP == "" {
		redirectWithFlash(w, r, editPath, "", "egress: IP required when mode is fixed")
		return
	}
	if outboundIP != "" && net.ParseIP(outboundIP) == nil {
		redirectWithFlash(w, r, editPath, "", "egress: invalid IP address")
		return
	}
	// Reject fixed IP that is not in the node's inventory (prevents source-IP spoof).
	// If the inventory is absent/empty, skip the membership check for backward compat.
	if outboundIPMode == "fixed" && outboundIP != "" {
		var nodeIPsJSON sql.NullString
		_ = h.DB().QueryRowContext(r.Context(),
			`SELECT n.outbound_ips FROM routes r JOIN caddy_nodes n ON n.id = r.caddy_node_id WHERE r.id = ?`, id,
		).Scan(&nodeIPsJSON)
		if nodeIPsJSON.Valid && nodeIPsJSON.String != "" && nodeIPsJSON.String != "[]" {
			var nodeIPs []string
			if err2 := json.Unmarshal([]byte(nodeIPsJSON.String), &nodeIPs); err2 != nil || len(nodeIPs) == 0 {
				// Corrupt or empty JSON with non-empty string - treat as non-empty inventory with no match.
				redirectWithFlash(w, r, editPath, "", "egress: IP not in node's outbound_ips inventory")
				return
			}
			found := false
			for _, nip := range nodeIPs {
				if nip == outboundIP {
					found = true
					break
				}
			}
			if !found {
				redirectWithFlash(w, r, editPath, "", "egress: IP not in node's outbound_ips inventory")
				return
			}
		}
	}
	// random mode: clear outbound_ip (resolved at build time from node inventory).
	if outboundIPMode == "random" {
		outboundIP = ""
	} else if outboundIPMode != "fixed" {
		outboundIP = ""
	}

	// DNS controls: optional custom resolver IP or WG peer, plus address-family.
	dnsResolverIP := strings.TrimSpace(r.FormValue("dns_resolver_ip"))
	if dnsResolverIP != "" {
		ip := net.ParseIP(dnsResolverIP)
		if ip == nil {
			redirectWithFlash(w, r, editPath, "", "DNS resolver: must be a valid IP address (IPv4 or IPv6)")
			return
		}
		// Block loopback/link-local/unspecified to limit SSRF via the test
		// endpoint; RFC1918 stays allowed (resolvers live on the WG mesh).
		if security.IsDangerousProxyBackend(ip) {
			redirectWithFlash(w, r, editPath, "", "DNS resolver: loopback, link-local and unspecified addresses are not allowed")
			return
		}
	}
	dnsResolverViaWGID, _ := strconv.ParseInt(r.FormValue("dns_resolver_via_wg_peer_id"), 10, 64)
	// Write-time half of HPG-SEC-001a: a submitted resolver needs the same
	// waiver as node-side resolution, the panel's own tunnel auto-bind does not.
	dnsResolverIP, dnsResolverViaWGID, dnsResolverAutoBound, dnsResolverErr := resolverForSave(
		sessRole(sess), dnsResolverIP, dnsResolverViaWGID,
		kind, backendIP, int64Default(r.FormValue("via_wg_peer_id")))
	if dnsResolverErr != nil {
		redirectWithFlash(w, r, editPath, "", dnsResolverErr.Error())
		return
	}
	if dnsResolverAutoBound {
		h.Logger.Info("host save: hostname backend with tunnel, auto-binding peer DNS resolver",
			"route_id", id, "backend", backendIP, "peer", dnsResolverViaWGID)
	}
	dnsAddressFamily := r.FormValue("dns_address_family")
	switch dnsAddressFamily {
	case "ipv4", "ipv6":
	default:
		dnsAddressFamily = "any"
	}

	groupID, _ := strconv.ParseInt(r.FormValue("group_id"), 10, 64)

	cacheTTL, _ := strconv.Atoi(r.FormValue("cache_ttl_secs"))
	if cacheTTL <= 0 {
		cacheTTL = 60
	}
	tag := strings.TrimSpace(r.FormValue("tag"))
	if len(tag) > 64 {
		tag = tag[:64]
	}
	headersRaw := r.FormValue("custom_headers")
	maintenanceMode := r.FormValue("maintenance_mode") == "1"
	maintenanceMsg := strings.TrimSpace(r.FormValue("maintenance_message"))
	if len(maintenanceMsg) > 500 {
		maintenanceMsg = maintenanceMsg[:500]
	}
	// Per-route error/maintenance page override (admin-only). HTML capped at
	// 100 KB and stored verbatim (rendered as static_response body, not templated).
	errOverride := r.FormValue("error_override") == "1"
	errHTML := r.FormValue("error_html")
	if len(errHTML) > 100*1024 {
		errHTML = errHTML[:100*1024]
	}
	errLogoURL := strings.TrimSpace(r.FormValue("error_logo_url"))
	errBrand := strings.TrimSpace(r.FormValue("error_brand"))
	if len(errBrand) > 128 {
		errBrand = errBrand[:128]
	}
	errBgColor := strings.TrimSpace(r.FormValue("error_bg_color"))
	if len(errBgColor) > 32 {
		errBgColor = errBgColor[:32]
	}
	// Same validation the node-wide branding path enforces (admin_branding.go):
	// error_logo_url lands in <img src> and error_bg_color is spliced into an
	// inline <style> block on the Caddy error page, so reject non-http(s) URLs
	// and unsafe CSS colours instead of only length-capping.
	if errLogoURL != "" && !isHTTPURL(errLogoURL) {
		h.renderHostEditValidationError(w, r, sess, id, ownerClientID, "error_logo_url", "error logo URL must be http(s)://")
		return
	}
	// These values reach a static_response body or Location header, which
	// Caddy expands; env/file placeholders there would read the node.
	for _, v := range []string{maintenanceMsg, errHTML, errLogoURL, errBrand, errBgColor} {
		if err := caddyapi.ScreenReplacerValue(v); err != nil {
			redirectWithFlash(w, r, "/admin/hosts/"+strconv.FormatInt(id, 10)+"/edit", "", "error/maintenance page: "+err.Error())
			return
		}
	}
	if errBgColor != "" && !isSafeCSSColor(errBgColor) {
		h.renderHostEditValidationError(w, r, sess, id, ownerClientID, "error_bg_color", "error background must be #RGB / #RRGGBB / #RRGGBBAA or rgb()/rgba()")
		return
	}
	// HPG-001: Caddy expands placeholders in a static_response body and in the
	// Location header, so a tenant string landing there is screened at write
	// time, not only before emission. Fail closed.
	// HTML and free text carry legitimate braces; URLs never do.
	for _, f := range []struct{ name, val string }{
		{"custom error HTML", errHTML},
		{"maintenance message", maintenanceMsg},
	} {
		if err := routes.ScreenTenantText(f.val); err != nil {
			redirectWithFlash(w, r, "/admin/hosts/"+strconv.FormatInt(id, 10)+"/edit", "", f.name+": "+sanitizeErr(err))
			return
		}
	}
	if err := screenTenantURLFields(redirectURL, extHostHeader); err != nil {
		redirectWithFlash(w, r, "/admin/hosts/"+strconv.FormatInt(id, 10)+"/edit", "", err.Error())
		return
	}
	cacheVary := sanitizeHeaderList(r.FormValue("cache_vary"))
	accessAllow, err1 := sanitizeCIDRList(r.FormValue("access_allow"))
	if err1 != nil {
		h.renderHostEditValidationError(w, r, sess, id, ownerClientID, "access_allow", "allow list: "+sanitizeErr(err1))
		return
	}
	accessDeny, err2 := sanitizeCIDRList(r.FormValue("access_deny"))
	if err2 != nil {
		h.renderHostEditValidationError(w, r, sess, id, ownerClientID, "access_deny", "deny list: "+sanitizeErr(err2))
		return
	}
	accessBlockAll := r.FormValue("access_block_all") == "1"
	maintenanceAllow, errMA := sanitizeCIDRList(r.FormValue("maintenance_allow"))
	if errMA != nil {
		h.renderHostEditValidationError(w, r, sess, id, ownerClientID, "maintenance_allow", "maintenance allow: "+sanitizeErr(errMA))
		return
	}
	ssoPaths := sanitizePathList(r.FormValue("sso_paths"))
	ssoHosts := sanitizeHostList(r.FormValue("sso_hosts"))
	ssoViaPeerID, _ := strconv.ParseInt(r.FormValue("sso_via_wg_peer_id"), 10, 64)
	// Built-in portal toggle + selected group IDs.
	portalProtect := r.FormValue("portal_protect") == "1"
	// Empty = no exceptions; every protected request hits the verifier.
	portalPublicPathsVal := sanitizePathList(r.FormValue("portal_public_paths"))
	var portalGroupIDs []int64
	for _, v := range r.Form["portal_group_ids"] {
		if gid, perr := strconv.ParseInt(v, 10, 64); perr == nil && gid > 0 {
			portalGroupIDs = append(portalGroupIDs, gid)
		}
	}
	// Raw Caddy handlers are node-operator power, not route-owner power: only a
	// full platform admin may change them. Limited admins keep the stored chain.
	cfgCtx, cfgCancel := context.WithTimeout(r.Context(), 3*time.Second)
	customCfg, err3 := h.resolveCustomConfig(cfgCtx, sess, id, r.FormValue("custom_config"))
	cfgCancel()
	if err3 != nil {
		redirectWithFlash(w, r, "/admin/hosts/"+strconv.FormatInt(id, 10)+"/edit", "", "custom config: "+sanitizeErr(err3))
		return
	}
	aliases, errAli := sanitizeAliases(r.FormValue("aliases"), domain)
	if errAli != nil {
		h.renderHostEditValidationError(w, r, sess, id, ownerClientID, "aliases", "aliases: "+sanitizeErr(errAli))
		return
	}
	// Reject aliases that shadow another route's domain or alias (cross-tenant hijack).
	if aliases != "" {
		acx, acancel := context.WithTimeout(r.Context(), 3*time.Second)
		clash, cerr := aliasCollision(acx, h.DB(), aliases, id)
		acancel()
		if cerr != nil {
			redirectWithFlash(w, r, "/admin/hosts/"+strconv.FormatInt(id, 10)+"/edit", "", "aliases: collision check failed")
			return
		}
		if clash != "" {
			h.renderHostEditValidationError(w, r, sess, id, ownerClientID, "aliases", "alias "+clash+" is already used by another route")
			return
		}
	}
	// Basic auth: empty user/pass disables the gate; non-empty user + new
	// password triggers fresh bcrypt + base64 (Caddy http_basic format).
	// User can change just the username (keep password) by leaving the
	// password field empty + ticking 'Keep current password'.
	ssoProviderURL := strings.TrimSpace(r.FormValue("sso_provider_url"))
	ssoCopyHeaders := strings.TrimSpace(r.FormValue("sso_copy_headers"))
	ssoTrustedProxies := strings.TrimSpace(r.FormValue("sso_trusted_proxies"))
	// trusted_proxies feeds Caddy forward_auth; a malformed entry fails the
	// whole /load and wedges the node's resync. Validate as IPs or CIDRs.
	if ssoTrustedProxies != "" {
		for _, p := range strings.Fields(strings.ReplaceAll(ssoTrustedProxies, ",", " ")) {
			if _, _, errCIDR := net.ParseCIDR(p); errCIDR != nil && net.ParseIP(p) == nil {
				redirectWithFlash(w, r, "/admin/hosts/"+strconv.FormatInt(id, 10)+"/edit", "", "sso trusted proxies must be IPs or CIDRs")
				return
			}
		}
	}
	// Copy-header names become header keys and placeholder names. The provider
	// URL itself is screened below by screenSSOTarget (HPG-SEC-001b).
	for _, hn := range strings.FieldsFunc(ssoCopyHeaders, func(c rune) bool { return c == '\n' || c == '\r' || c == ',' }) {
		if hn = strings.TrimSpace(hn); hn != "" && !caddyapi.ValidHeaderName(hn) {
			redirectWithFlash(w, r, "/admin/hosts/"+strconv.FormatInt(id, 10)+"/edit", "", "sso copy headers must be header names")
			return
		}
	}
	var ssoProviderURLVal, ssoCopyHeadersVal, ssoTrustedProxiesVal sql.NullString
	if ssoProviderURL != "" {
		ssoProviderURLVal = sql.NullString{String: ssoProviderURL, Valid: true}
	}
	if ssoCopyHeaders != "" {
		ssoCopyHeadersVal = sql.NullString{String: ssoCopyHeaders, Valid: true}
	}
	if ssoTrustedProxies != "" {
		ssoTrustedProxiesVal = sql.NullString{String: ssoTrustedProxies, Valid: true}
	}
	basicUser := strings.TrimSpace(r.FormValue("basic_auth_user"))
	basicPass := r.FormValue("basic_auth_pass")
	keepPass := r.FormValue("basic_auth_keep") == "1"
	var basicHashUpdate sql.NullString
	var basicUserUpdate sql.NullString
	if len(basicUser) > 64 {
		basicUser = basicUser[:64]
	}
	if basicUser == "" {
		// Clearing user clears the whole gate.
		basicUserUpdate = sql.NullString{}
		basicHashUpdate = sql.NullString{}
	} else {
		basicUserUpdate = sql.NullString{String: basicUser, Valid: true}
		if !keepPass && basicPass != "" {
			hashBytes, herr := bcryptHash([]byte(basicPass))
			if herr != nil {
				redirectWithFlash(w, r, "/admin/hosts/"+strconv.FormatInt(id, 10)+"/edit", "", "basic auth hash: "+sanitizeErr(herr))
				return
			}
			b64 := base64.StdEncoding.EncodeToString(hashBytes)
			basicHashUpdate = sql.NullString{String: b64, Valid: true}
		} else if !keepPass && basicPass == "" {
			// User typed name but no password - refuse (otherwise we'd
			// silently wipe the existing hash and lock the operator out
			// of an unauthenticated route).
			redirectWithFlash(w, r, "/admin/hosts/"+strconv.FormatInt(id, 10)+"/edit", "", "basic auth: password required (or tick 'keep current')")
			return
		} else {
			// keepPass==true: leave hash column alone - handled via separate
			// UPDATE branch below.
		}
	}

	if domain == "" {
		h.renderHostEditValidationError(w, r, sess, id, ownerClientID, "domain", "domain required")
		return
	}
	// Same shape check Create enforces: an unvalidated edit let a verified route
	// be re-pointed at any hostname (domain takeover). ValidHostMatcher also
	// keeps out forms the shadow-ordering predicate cannot model.
	if !routes.ValidDomain(domain) || !caddyapi.ValidHostMatcher(domain) {
		h.renderHostEditValidationError(w, r, sess, id, ownerClientID, "domain", "invalid domain")
		return
	}
	if pathPrefix != "" {
		if !strings.HasPrefix(pathPrefix, "/") {
			pathPrefix = "/" + pathPrefix
		}
		if strings.Contains(pathPrefix, "..") {
			h.renderHostEditValidationError(w, r, sess, id, ownerClientID, "path_prefix", "invalid path prefix")
			return
		}
	}
	// Matcher (domain+path+aliases) change: load the stored set so the collision
	// checks and the ownership-proof reset below both key off a real diff.
	// Aliases count: they are emitted into the same Caddy host matcher, so an
	// alias-only edit is a hostname claim exactly like a domain change.
	mctx, mcancel := context.WithTimeout(r.Context(), 5*time.Second)
	var oldDomain, oldPath, oldAliases, oldAliasesVerified string
	if merr := h.DB().QueryRowContext(mctx,
		`SELECT LOWER(domain), COALESCE(path_prefix,''), COALESCE(aliases,''),
		        COALESCE(aliases_verified,'') FROM routes WHERE id = ?`, id,
	).Scan(&oldDomain, &oldPath, &oldAliases, &oldAliasesVerified); merr != nil {
		mcancel()
		redirectWithFlash(w, r, "/admin/hosts/"+strconv.FormatInt(id, 10)+"/edit", "", "route not found")
		return
	}
	matcherChanged := matcherChangedForUpdate(oldDomain, oldPath, oldAliases, domain, pathPrefix, aliases)
	if matcherChanged {
		// The new hostname must not already be another route's domain or alias,
		// regardless of path: a more specific path would still shadow it.
		if clash, cerr := domainCollision(mctx, h.DB(), domain, id); cerr != nil {
			mcancel()
			redirectWithFlash(w, r, "/admin/hosts/"+strconv.FormatInt(id, 10)+"/edit", "", "domain collision check failed")
			return
		} else if clash {
			mcancel()
			h.renderHostEditValidationError(w, r, sess, id, ownerClientID, "domain", "domain "+domain+" is already used by another route")
			return
		}
	}
	mcancel()
	if kind == "proxy" && !external && (port <= 0 || port > 65535) {
		h.renderHostEditValidationError(w, r, sess, id, ownerClientID, "port", "port invalid for proxy route")
		return
	}
	if kind == "proxy" && !external && backendIP != "" && !isValidUpstreamHost(backendIP) {
		h.renderHostEditValidationError(w, r, sess, id, ownerClientID, "backend_ip", "backend must be a valid IP or hostname")
		return
	}
	upstreamScheme := strings.TrimSpace(r.FormValue("upstream_scheme"))
	if upstreamScheme != "https" {
		upstreamScheme = "http"
	}
	upstreamSkipTLS := r.FormValue("upstream_skip_tls_verify") == "1"
	// Disabling upstream cert verification enables MITM to the backend: only
	// super_admin may turn it on. Unchecking (safe direction) stays allowed.
	if upstreamSkipTLS && (sess == nil || sess.Role != "super_admin") {
		editPath := "/admin/hosts/" + strconv.FormatInt(id, 10) + "/edit"
		redirectWithFlash(w, r, editPath, "", "skip upstream TLS verify requires super_admin")
		return
	}
	viaPeerID, _ := strconv.ParseInt(r.FormValue("via_wg_peer_id"), 10, 64)
	resolveNodeSide := r.FormValue("backend_resolve_node_side") == "1"
	if err := checkNodeSideResolve(sess, resolveNodeSide); err != nil {
		editPath := "/admin/hosts/" + strconv.FormatInt(id, 10) + "/edit"
		redirectWithFlash(w, r, editPath, "", err.Error())
		return
	}
	if external {
		editPath := "/admin/hosts/" + strconv.FormatInt(id, 10) + "/edit"
		// MUTUAL EXCLUSION: an external route must NOT be bound to a WG peer -
		// binding one would NULL backend_ip_override (the FQDN) and break it.
		if viaPeerID > 0 {
			redirectWithFlash(w, r, editPath, "", "external upstream cannot also use a WG tunnel - clear 'Backend via'")
			return
		}
		// Allowlist + public-address check for wildcard hits, same as Create.
		cctx, ccancel := context.WithTimeout(r.Context(), 10*time.Second)
		cerr := h.Routes.CheckExternalHost(cctx, externalHost)
		ccancel()
		if cerr != nil {
			redirectWithFlash(w, r, editPath, "", cerr.Error())
			return
		}
		// Force the route shape (mirrors Create).
		upstreamScheme = "https"
		ssl = true
		if port == 0 {
			port = 443
		}
		if extHostHeader == "" {
			extHostHeader = externalHost
		}
	}
	// mTLS needs TLS: the client-auth policy is part of the route's TLS
	// connection policy, so saving enforcement with SSL off yields a host the
	// panel calls locked while Caddy either serves it wide open (fail_open) or
	// 503s every request. Checked here, not up with the other mTLS validation,
	// because the external branch above is the last writer of `ssl`.
	if requireClientCert && !ssl {
		redirectWithFlash(w, r, editPath, "",
			"client certificates require SSL - enable SSL for this host or turn mTLS off")
		return
	}
	// mTLS implies HTTPS-only: the node redirects :80 for an enforced host
	// whatever the box says (BuildRoute derives it), so store what is served.
	forceHTTPS = forceHTTPS || requireClientCert
	// SSRF screen: EVERY tenant-controlled dial target of this save - primary
	// backend, extra upstreams and path-rule upstreams - goes through the same
	// fail-closed screener. Redirect routes never dial, so skip them.
	if kind == "proxy" {
		screenHost := backendIP
		screenPort := port
		if external {
			screenHost = externalHost
		}
		sctx, scancel := context.WithTimeout(r.Context(), 10*time.Second)
		infra, ierr := loadInfraOrFail(sctx, h.DB(), h.Logger)
		if ierr != nil {
			scancel()
			redirectWithFlash(w, r, "/admin/hosts/"+strconv.FormatInt(id, 10)+"/edit", "", ierr.Error())
			return
		}
		// Only the operator's node-side-resolution opt-in waives the
		// resolving step, and it never waives the deny set.
		serr := screenBackendWith(sctx, infra, screenHost, screenPort, resolveNodeSide)
		for _, u := range newUpstreams {
			if serr != nil {
				break
			}
			serr = screenBackendWith(sctx, infra, u.Host, u.Port, resolveNodeSide)
		}
		for _, lr := range newLocationRules {
			if serr != nil {
				break
			}
			if lr.Action != "proxy" {
				continue
			}
			serr = screenBackendWith(sctx, infra, lr.UpstreamHost, lr.UpstreamPort, resolveNodeSide)
		}
		// A tenant-set Host naming infrastructure is how a screened dial gets
		// re-aimed at a vhost of the control plane; nobody needs it.
		for k, v := range parseHeaderMap(headersRaw) {
			if !strings.EqualFold(k, "Host") {
				continue
			}
			hv := v
			if hh, _, err := net.SplitHostPort(v); err == nil {
				hv = hh
			}
			if infra.Blocked(hv) {
				serr = fmt.Errorf("Host header %q names control-plane infrastructure", v)
			}
		}
		scancel()
		if serr != nil {
			h.Logger.Warn("host save: backend screen failed", "host", screenHost, "err", serr)
			redirectWithFlash(w, r, "/admin/hosts/"+strconv.FormatInt(id, 10)+"/edit", "",
				unresolvedHint(serr, "upstream address blocked or unresolvable: "+sanitizeErr(serr)))
			return
		}
	}
	// HPG-SEC-001b: the SSO provider is a dial target like any other, and
	// emission holds the whole route back when it fails. Screen it here too so
	// the operator hears about it at save time instead of losing the host.
	if ssoProviderURL != "" {
		octx, ocancel := context.WithTimeout(r.Context(), 10*time.Second)
		var ssoPeerIP string
		if ssoViaPeerID > 0 {
			// The bound peer replaces the URL host, so that is what gets dialed.
			_ = h.DB().QueryRowContext(octx,
				"SELECT COALESCE(assigned_ip,'') FROM customer_wg_peer WHERE id = ? AND status <> 'revoked'",
				ssoViaPeerID).Scan(&ssoPeerIP)
		}
		infra, ierr := loadInfraOrFail(octx, h.DB(), h.Logger)
		oerr := ierr
		if oerr == nil {
			oerr = screenSSOTarget(octx, infra, ssoProviderURL, ssoPeerIP)
		}
		ocancel()
		if oerr != nil {
			h.Logger.Warn("host save: SSO provider screen failed", "err", oerr)
			redirectWithFlash(w, r, editPath, "", "SSO provider: "+sanitizeErr(oerr))
			return
		}
	}
	// Cross-tenant + node-topology guard: tunnel must belong to the same
	// client that owns the route's service AND live on the same Caddy
	// node as the route. The second check matters because wg-tun0 only
	// exists on the tunnel's home node - pointing a route on node A at a
	// peer on node B would yield 502s once Caddy tries to dial the
	// tunnel IP through a nonexistent interface.
	if viaPeerID > 0 {
		gctx, gcancel := context.WithTimeout(r.Context(), 2*time.Second)
		var owns int
		_ = h.DB().QueryRowContext(gctx,
			`SELECT COUNT(*) FROM customer_wg_peer p
			   JOIN routes r ON r.id = ?
			   JOIN services s ON s.id = r.service_id
			  WHERE p.id = ?
			    AND p.client_id = s.client_id
			    AND p.node_id   = r.caddy_node_id
			    AND p.status <> 'revoked'`,
			id, viaPeerID).Scan(&owns)
		gcancel()
		if owns == 0 {
			redirectWithFlash(w, r, "/admin/hosts/"+strconv.FormatInt(id, 10)+"/edit", "", "selected tunnel must belong to this route's client AND its assigned Caddy node")
			return
		}
	}
	if ssoViaPeerID > 0 {
		gctx, gcancel := context.WithTimeout(r.Context(), 2*time.Second)
		var owns int
		_ = h.DB().QueryRowContext(gctx,
			`SELECT COUNT(*) FROM customer_wg_peer p
			   JOIN routes r ON r.id = ?
			   JOIN services s ON s.id = r.service_id
			  WHERE p.id = ?
			    AND p.client_id = s.client_id
			    AND p.node_id   = r.caddy_node_id
			    AND p.status <> 'revoked'`,
			id, ssoViaPeerID).Scan(&owns)
		gcancel()
		if owns == 0 {
			redirectWithFlash(w, r, "/admin/hosts/"+strconv.FormatInt(id, 10)+"/edit", "", "selected SSO tunnel must belong to this route's client AND its assigned Caddy node")
			return
		}
	}
	// IDOR guard: DNS resolver peer must belong to the same client/node as this route.
	if dnsResolverViaWGID > 0 {
		gctx, gcancel := context.WithTimeout(r.Context(), 2*time.Second)
		var owns int
		_ = h.DB().QueryRowContext(gctx,
			`SELECT COUNT(*) FROM customer_wg_peer p
			   JOIN routes r ON r.id = ?
			   JOIN services s ON s.id = r.service_id
			  WHERE p.id = ?
			    AND p.client_id = s.client_id
			    AND p.node_id   = r.caddy_node_id
			    AND p.status <> 'revoked'`,
			id, dnsResolverViaWGID).Scan(&owns)
		gcancel()
		if owns == 0 {
			redirectWithFlash(w, r, "/admin/hosts/"+strconv.FormatInt(id, 10)+"/edit", "", "selected DNS tunnel must belong to this route's client AND its assigned Caddy node")
			return
		}
	}
	if kind == "redirect" && redirectURL == "" {
		redirectWithFlash(w, r, "/admin/hosts/"+strconv.FormatInt(id, 10)+"/edit", "", "redirect URL required for redirect route")
		return
	}
	if err := caddyapi.ScreenReplacerValue(redirectURL); err != nil {
		redirectWithFlash(w, r, "/admin/hosts/"+strconv.FormatInt(id, 10)+"/edit", "", "redirect URL: "+err.Error())
		return
	}
	if kind == "redirect" {
		if redirectCode == 0 {
			redirectCode = 308
		}
		switch redirectCode {
		case 301, 302, 307, 308:
		default:
			redirectWithFlash(w, r, "/admin/hosts/"+strconv.FormatInt(id, 10)+"/edit", "", "redirect_code must be 301/302/307/308")
			return
		}
	}

	headersJSON, hdrErr := parseHeaderLines(headersRaw)
	if hdrErr != nil {
		redirectWithFlash(w, r, "/admin/hosts/"+strconv.FormatInt(id, 10)+"/edit", "", sanitizeErr(hdrErr))
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()

	var nodeID, serviceID int64
	var currentBackendIP string
	var prevOverride sql.NullString
	var prevRequireClientCert bool
	var prevDNSSteeringEnabled bool
	var prevSSOStrict bool
	if err := h.DB().QueryRowContext(ctx,
		`SELECT r.caddy_node_id, r.service_id, s.backend_ip, r.backend_ip_override,
		        COALESCE(r.require_client_cert, 0), COALESCE(r.dns_steering_enabled, 0),
		        COALESCE(r.sso_strict_mode, 0)
		 FROM routes r JOIN services s ON s.id = r.service_id
		 WHERE r.id = ?`, id,
	).Scan(&nodeID, &serviceID, &currentBackendIP, &prevOverride, &prevRequireClientCert, &prevDNSSteeringEnabled,
		&prevSSOStrict); err != nil {
		redirectWithFlash(w, r, "/admin/hosts", "", "route not found")
		return
	}
	ssoStrictMode := ssoStrictFromForm(r.Form, prevSSOStrict)

	// HPG-008: the edit form used to write a port or path the create path would
	// have refused. Same command, same rules, full resulting state.
	if err := h.Routes.ValidateRouteState(ctx, serviceID, id, routes.RouteState{
		Kind: kind, External: external, UpstreamPort: port, PathPrefix: pathPrefix,
		SSL: ssl, WebSocket: websocket, RedirectURL: redirectURL,
	}); err != nil {
		redirectWithFlash(w, r, "/admin/hosts/"+strconv.FormatInt(id, 10)+"/edit", "", sanitizeErr(err))
		return
	}

	// Backend edits are PER-ROUTE via routes.backend_ip_override so editing
	// one route does NOT cascade to siblings sharing the same service.
	// Always write the override on save (not gated by diff vs current view
	// value) so clearing the field reliably resets to NULL. Redirect-kind
	// routes never need an override - clear it so a future kind flip
	// doesn't restore stale data.
	var newOverride sql.NullString
	switch {
	case external:
		// External route: the override column carries the upstream FQDN.
		newOverride = sql.NullString{String: externalHost, Valid: true}
	case kind == "proxy" && backendIP != "":
		newOverride = sql.NullString{String: backendIP, Valid: true}
	}
	if _, err := h.DB().ExecContext(ctx,
		"UPDATE routes SET backend_ip_override = ? WHERE id = ?", newOverride, id); err != nil {
		h.Logger.Warn("host update: route backend_ip_override", "route_id", id, "err", err)
		redirectWithFlash(w, r, "/admin/hosts/"+strconv.FormatInt(id, 10)+"/edit", "", "backend IP update failed")
		return
	}
	// Audit on EFFECTIVE-backend change. Prev = prior override if set else
	// service backend. New = new override if set else service backend.
	// This catches override clears (override→null falls back to service)
	// and audits stale-override drops on kind=redirect, which the simple
	// `backendIP != currentBackendIP` gate would silently miss.
	prevEffective := currentBackendIP
	if prevOverride.Valid && prevOverride.String != "" {
		prevEffective = prevOverride.String
	}
	newEffective := currentBackendIP
	if newOverride.Valid && newOverride.String != "" {
		newEffective = newOverride.String
	}
	if prevEffective != newEffective {
		audit.Write(ctx, h.DB(), h.Logger, r, audit.Entry{
			UserID: actorUserID(sess), Action: "admin.route.backend_ip.change", Entity: "route",
			EntityID: itoa64(id),
			Meta:     map[string]any{"old": prevEffective, "new": newEffective},
		})
	}
	_ = serviceID

	var tagVal sql.NullString
	if tag != "" {
		tagVal = sql.NullString{String: tag, Valid: true}
	}
	var redirURLVal sql.NullString
	if redirectURL != "" {
		redirURLVal = sql.NullString{String: redirectURL, Valid: true}
	}
	var redirCodeVal sql.NullInt32
	if kind == "redirect" {
		redirCodeVal = sql.NullInt32{Int32: int32(redirectCode), Valid: true}
	}
	var headersVal sql.NullString
	if headersJSON != "" {
		headersVal = sql.NullString{String: headersJSON, Valid: true}
	}
	var maintMsgVal sql.NullString
	if maintenanceMsg != "" {
		maintMsgVal = sql.NullString{String: maintenanceMsg, Valid: true}
	}
	var cacheVaryVal sql.NullString
	if cacheVary != "" {
		cacheVaryVal = sql.NullString{String: cacheVary, Valid: true}
	}
	var accessAllowVal, accessDenyVal, customCfgVal, aliasesVal sql.NullString
	var maintAllowVal, ssoPathsVal, ssoHostsVal sql.NullString
	if accessAllow != "" {
		accessAllowVal = sql.NullString{String: accessAllow, Valid: true}
	}
	if accessDeny != "" {
		accessDenyVal = sql.NullString{String: accessDeny, Valid: true}
	}
	if customCfg != "" {
		customCfgVal = sql.NullString{String: customCfg, Valid: true}
	}
	if aliases != "" {
		aliasesVal = sql.NullString{String: aliases, Valid: true}
	}
	if maintenanceAllow != "" {
		maintAllowVal = sql.NullString{String: maintenanceAllow, Valid: true}
	}
	if ssoPaths != "" {
		ssoPathsVal = sql.NullString{String: ssoPaths, Valid: true}
	}
	if ssoHosts != "" {
		ssoHostsVal = sql.NullString{String: ssoHosts, Valid: true}
	}

	// External upstream columns. proxy_secret_enc is NEVER written here (only
	// Create or the regenerate endpoint set it), so a normal edit can't wipe
	// the bearer. When not external, host_header is cleared to NULL.
	var extHostHeaderVal sql.NullString
	if external && extHostHeader != "" {
		extHostHeaderVal = sql.NullString{String: extHostHeader, Valid: true}
	}

	// Load host custom field defs and encode submitted values for this update.
	cfDefs, _ := customfields.LoadDefs(ctx, h.DB(), "host")
	cfJSON, cfErr := customfields.EncodeFromForm(cfDefs, r.Form)
	if cfErr != nil {
		// EncodeFromForm doesn't say which def failed; defs are validated in the
		// same order, so replay just enough to find the offending key.
		cfField := ""
		for _, def := range cfDefs {
			if _, err := customfields.EncodeFromForm([]customfields.Def{def}, r.Form); err != nil {
				cfField = "cf_" + def.Key
				break
			}
		}
		if cfField == "" {
			redirectWithFlash(w, r, "/admin/hosts/"+strconv.FormatInt(id, 10)+"/edit", "", cfErr.Error())
			return
		}
		h.renderHostEditValidationError(w, r, sess, id, ownerClientID, cfField, cfErr.Error())
		return
	}
	var cfVal sql.NullString
	if cfJSON != "" {
		cfVal = sql.NullString{String: cfJSON, Valid: true}
	}

	// A matcher change re-arms ownership proof for every non-platform caller:
	// otherwise a scoped admin re-points a verified route at a victim hostname
	// and the next resync serves it. Reset rides the same tx as the edit so no
	// resync window ever sees the new domain still flagged verified.
	resetVerification := h.verificationResetRequired(ctx, sess, matcherChanged)
	// Aliases carry their own proof. Only a full platform admin is trusted to
	// name a hostname outright; for anyone else a newly added alias stays
	// unproven, so it is neither emitted nor eligible for a certificate.
	aliasesVerified := aliases
	if h.verificationResetRequired(ctx, sess, true) {
		aliasesVerified = keepProvenHosts(oldAliasesVerified, aliases)
	}
	var aliasesVerifiedVal sql.NullString
	if aliasesVerified != "" {
		aliasesVerifiedVal = sql.NullString{String: aliasesVerified, Valid: true}
	}
	var verifyToken string
	if resetVerification {
		t, terr := routes.NewVerifyToken()
		if terr != nil {
			redirectWithFlash(w, r, "/admin/hosts/"+strconv.FormatInt(id, 10)+"/edit", "", "update failed")
			return
		}
		verifyToken = t
	}

	tx, txErr := h.DB().BeginTx(ctx, nil)
	if txErr != nil {
		h.Logger.Warn("host update: begin tx", "id", id, "err", txErr)
		redirectWithFlash(w, r, "/admin/hosts/"+strconv.FormatInt(id, 10)+"/edit", "", "update failed")
		return
	}
	defer func() { _ = tx.Rollback() }() // no-op once committed

	// Re-check the hostname claims INSIDE the tx: the pre-checks above race a
	// concurrent save that could land the same domain or alias in between.
	if matcherChanged {
		if clash, cerr := domainCollision(ctx, tx, domain, id); cerr != nil {
			redirectWithFlash(w, r, "/admin/hosts/"+strconv.FormatInt(id, 10)+"/edit", "", "domain collision check failed")
			return
		} else if clash {
			h.renderHostEditValidationError(w, r, sess, id, ownerClientID, "domain", "domain "+domain+" is already used by another route")
			return
		}
	}
	if aliases != "" {
		clash, cerr := aliasCollision(ctx, tx, aliases, id)
		if cerr != nil {
			redirectWithFlash(w, r, "/admin/hosts/"+strconv.FormatInt(id, 10)+"/edit", "", "aliases: collision check failed")
			return
		}
		if clash != "" {
			h.renderHostEditValidationError(w, r, sess, id, ownerClientID, "aliases", "alias "+clash+" is already used by another route")
			return
		}
	}

	// Two UPDATE branches: when 'keep current password' is ticked we
	// must NOT touch basic_auth_bcrypt. Cleanest split is two queries.
	var err error
	if basicUser != "" && keepPass {
		_, err = tx.ExecContext(ctx,
			`UPDATE routes SET
			   domain = ?, aliases = ?, aliases_verified = ?, path_prefix = ?, upstream_port = ?, upstream_scheme = ?, upstream_skip_tls_verify = ?,
			   upstream_external = ?, upstream_host_header = ?,
			   via_wg_peer_id = ?,
			   kind = ?, redirect_url = ?, redirect_code = ?,
			   ssl_enabled = ?, force_https = ?, websocket = ?,
			   http2_enabled = ?, http3_enabled = ?,
			   cache_enabled = ?, cache_ttl_secs = ?, cache_public = ?,
			   compress_disabled = ?,
			   lb_policy = ?, lb_header_field = ?, lb_cookie_name = ?, lb_cookie_secret = ?,
			   health_active_uri = ?, health_active_interval = ?, health_active_timeout = ?,
			   health_active_status = ?, health_active_fails = ?,
			   health_passive_enabled = ?, health_passive_fail_dur = ?, health_passive_max_fail = ?,
			   lb_try_duration_ms = ?, lb_try_interval_ms = ?,
			   dial_timeout_ms = ?, response_header_timeout_ms = ?,
			   rate_enabled = ?, rate_window = ?, rate_max_events = ?, rate_key = ?,
			   waf_enabled = ?, waf_blocking = ?, waf_directives = ?,
			   geo_mode = ?, geo_countries = ?,
			   geo_response_code = ?, geo_fail_closed = ?, geo_allow_cidrs = ?,
			   geo_continents = ?, geo_block_cidrs = ?,
			   require_client_cert = ?, mtls_ca_id = ?, tls_pq_only = ?,
			   wildcard_enabled = ?, wildcard_zone = ?,
			   custom_headers = ?, tag = ?,
			   maintenance_mode = ?, maintenance_message = ?,
			   error_override = ?, error_html = ?, error_logo_url = ?, error_brand = ?, error_bg_color = ?,
			   cache_vary = ?,
			   access_allow = ?, access_deny = ?,
			   access_block_all = ?, maintenance_allow = ?,
			   custom_config = ?,
			   basic_auth_user = ?,
			   sso_provider_url = ?, sso_copy_headers = ?, sso_trusted_proxies = ?,
			   sso_paths = ?, sso_hosts = ?, sso_via_wg_peer_id = ?, sso_strict_mode = ?,
			   portal_public_paths = ?,
			   outbound_ip_mode = ?, outbound_ip = ?,
			   dns_resolver_ip = ?, dns_resolver_via_wg_peer_id = ?, dns_address_family = ?,
			   group_id = NULLIF(?, 0),
			   custom_fields = ?,
			   updated_at = NOW()
			 WHERE id = ?`,
			domain, aliasesVal, aliasesVerifiedVal, pathPrefix, port, upstreamScheme, upstreamSkipTLS,
			external, extHostHeaderVal,
			nullableInt64(viaPeerID),
			kind, redirURLVal, redirCodeVal,
			ssl, forceHTTPS, websocket,
			http2, http3,
			cacheEnabled, cacheTTL, cachePublic,
			compressDisabled,
			lbPolicy, lbHeaderField, lbCookieName, lbCookieSecret,
			healthURI, healthInterval, healthTimeout,
			healthStatus, healthFails,
			healthPassive, healthFailDur, healthMaxFails,
			lbTryDurationMs, lbTryIntervalMs,
			dialTimeoutMs, responseHeaderTimeoutMs,
			rateEnabled, rateWindow, rateMaxEvents, rateKey,
			wafEnabled, wafBlocking, wafDirectives,
			geoMode, geoCountries,
			geoResponseCodeRaw, geoFailClosed, geoAllowCIDRs,
			geoContinents, geoBlockCIDRs,
			requireClientCert, nullableInt64(mtlsCAID), tlsPQOnly,
			wildcardEnabled, wildcardZone,
			headersVal, tagVal,
			maintenanceMode, maintMsgVal,
			errOverride, errHTML, errLogoURL, errBrand, errBgColor,
			cacheVaryVal,
			accessAllowVal, accessDenyVal,
			accessBlockAll, maintAllowVal,
			customCfgVal,
			basicUserUpdate,
			ssoProviderURLVal, ssoCopyHeadersVal, ssoTrustedProxiesVal,
			ssoPathsVal, ssoHostsVal, nullableInt64(ssoViaPeerID), ssoStrictMode,
			portalPublicPathsVal,
			outboundIPMode, nullableString(outboundIP),
			nullableString(dnsResolverIP), nullableInt64(dnsResolverViaWGID), dnsAddressFamily,
			groupID,
			cfVal,
			id)
	} else {
		_, err = tx.ExecContext(ctx,
			`UPDATE routes SET
			   domain = ?, aliases = ?, aliases_verified = ?, path_prefix = ?, upstream_port = ?, upstream_scheme = ?, upstream_skip_tls_verify = ?,
			   upstream_external = ?, upstream_host_header = ?,
			   via_wg_peer_id = ?,
			   kind = ?, redirect_url = ?, redirect_code = ?,
			   ssl_enabled = ?, force_https = ?, websocket = ?,
			   http2_enabled = ?, http3_enabled = ?,
			   cache_enabled = ?, cache_ttl_secs = ?, cache_public = ?,
			   compress_disabled = ?,
			   lb_policy = ?, lb_header_field = ?, lb_cookie_name = ?, lb_cookie_secret = ?,
			   health_active_uri = ?, health_active_interval = ?, health_active_timeout = ?,
			   health_active_status = ?, health_active_fails = ?,
			   health_passive_enabled = ?, health_passive_fail_dur = ?, health_passive_max_fail = ?,
			   lb_try_duration_ms = ?, lb_try_interval_ms = ?,
			   dial_timeout_ms = ?, response_header_timeout_ms = ?,
			   rate_enabled = ?, rate_window = ?, rate_max_events = ?, rate_key = ?,
			   waf_enabled = ?, waf_blocking = ?, waf_directives = ?,
			   geo_mode = ?, geo_countries = ?,
			   geo_response_code = ?, geo_fail_closed = ?, geo_allow_cidrs = ?,
			   geo_continents = ?, geo_block_cidrs = ?,
			   require_client_cert = ?, mtls_ca_id = ?, tls_pq_only = ?,
			   wildcard_enabled = ?, wildcard_zone = ?,
			   custom_headers = ?, tag = ?,
			   maintenance_mode = ?, maintenance_message = ?,
			   error_override = ?, error_html = ?, error_logo_url = ?, error_brand = ?, error_bg_color = ?,
			   cache_vary = ?,
			   access_allow = ?, access_deny = ?,
			   access_block_all = ?, maintenance_allow = ?,
			   custom_config = ?,
			   basic_auth_user = ?, basic_auth_bcrypt = ?,
			   sso_provider_url = ?, sso_copy_headers = ?, sso_trusted_proxies = ?,
			   sso_paths = ?, sso_hosts = ?, sso_via_wg_peer_id = ?, sso_strict_mode = ?,
			   portal_public_paths = ?,
			   outbound_ip_mode = ?, outbound_ip = ?,
			   dns_resolver_ip = ?, dns_resolver_via_wg_peer_id = ?, dns_address_family = ?,
			   group_id = NULLIF(?, 0),
			   custom_fields = ?,
			   updated_at = NOW()
			 WHERE id = ?`,
			domain, aliasesVal, aliasesVerifiedVal, pathPrefix, port, upstreamScheme, upstreamSkipTLS,
			external, extHostHeaderVal,
			nullableInt64(viaPeerID),
			kind, redirURLVal, redirCodeVal,
			ssl, forceHTTPS, websocket,
			http2, http3,
			cacheEnabled, cacheTTL, cachePublic,
			compressDisabled,
			lbPolicy, lbHeaderField, lbCookieName, lbCookieSecret,
			healthURI, healthInterval, healthTimeout,
			healthStatus, healthFails,
			healthPassive, healthFailDur, healthMaxFails,
			lbTryDurationMs, lbTryIntervalMs,
			dialTimeoutMs, responseHeaderTimeoutMs,
			rateEnabled, rateWindow, rateMaxEvents, rateKey,
			wafEnabled, wafBlocking, wafDirectives,
			geoMode, geoCountries,
			geoResponseCodeRaw, geoFailClosed, geoAllowCIDRs,
			geoContinents, geoBlockCIDRs,
			requireClientCert, nullableInt64(mtlsCAID), tlsPQOnly,
			wildcardEnabled, wildcardZone,
			headersVal, tagVal,
			maintenanceMode, maintMsgVal,
			errOverride, errHTML, errLogoURL, errBrand, errBgColor,
			cacheVaryVal,
			accessAllowVal, accessDenyVal,
			accessBlockAll, maintAllowVal,
			customCfgVal,
			basicUserUpdate, basicHashUpdate,
			ssoProviderURLVal, ssoCopyHeadersVal, ssoTrustedProxiesVal,
			ssoPathsVal, ssoHostsVal, nullableInt64(ssoViaPeerID), ssoStrictMode,
			portalPublicPathsVal,
			outboundIPMode, nullableString(outboundIP),
			nullableString(dnsResolverIP), nullableInt64(dnsResolverViaWGID), dnsAddressFamily,
			groupID,
			cfVal,
			id)
	}
	if err != nil {
		if strings.Contains(err.Error(), "Duplicate entry") {
			redirectWithFlash(w, r, "/admin/hosts/"+strconv.FormatInt(id, 10)+"/edit", "", "another route already owns this domain+path")
			return
		}
		h.Logger.Warn("host update", "id", id, "err", err)
		redirectWithFlash(w, r, "/admin/hosts/"+strconv.FormatInt(id, 10)+"/edit", "", "update failed")
		return
	}
	// One column, same transaction: cheaper than a third copy of the
	// 60-column UPDATE above just to carry one flag.
	if _, rerr := tx.ExecContext(ctx,
		"UPDATE routes SET backend_resolve_node_side = ? WHERE id = ?", resolveNodeSide, id); rerr != nil {
		h.Logger.Warn("host update: backend resolution flag", "id", id, "err", rerr)
		redirectWithFlash(w, r, "/admin/hosts/"+strconv.FormatInt(id, 10)+"/edit", "", "update failed")
		return
	}
	// The path rewrite belongs to the external origin; it must not follow the
	// route onto an internal backend.
	if !external {
		if _, rerr := tx.ExecContext(ctx,
			"UPDATE routes SET strip_path_prefix = 0, upstream_path = NULL WHERE id = ?", id); rerr != nil {
			h.Logger.Warn("host update: clear path rewrite", "id", id, "err", rerr)
			redirectWithFlash(w, r, "/admin/hosts/"+strconv.FormatInt(id, 10)+"/edit", "", "update failed")
			return
		}
	}
	if resetVerification {
		if _, rerr := tx.ExecContext(ctx,
			`UPDATE routes SET domain_verified=0, verify_token=?, status='pending_dns',
			        ssl_issued_at=NULL, last_error='domain ownership not verified'
			 WHERE id=?`, verifyToken, id); rerr != nil {
			h.Logger.Warn("host update: verification reset", "id", id, "err", rerr)
			redirectWithFlash(w, r, "/admin/hosts/"+strconv.FormatInt(id, 10)+"/edit", "", "update failed")
			return
		}
	}
	if cerr := tx.Commit(); cerr != nil {
		if strings.Contains(cerr.Error(), "Duplicate entry") {
			redirectWithFlash(w, r, "/admin/hosts/"+strconv.FormatInt(id, 10)+"/edit", "", "another route already owns this domain+path")
			return
		}
		h.Logger.Warn("host update: commit", "id", id, "err", cerr)
		redirectWithFlash(w, r, "/admin/hosts/"+strconv.FormatInt(id, 10)+"/edit", "", "update failed")
		return
	}
	// Permissive SSO is a deliberate, named exception: record who chose it,
	// because the gate then covers only document loads.
	if prevSSOStrict && !ssoStrictMode && strings.TrimSpace(ssoProviderURL) != "" {
		audit.Write(ctx, h.DB(), h.Logger, r, audit.Entry{
			UserID: actorUserID(sess), Action: "host.sso_permissive_enabled", Entity: "route",
			EntityID: itoa64(id),
			Meta:     map[string]any{"domain": domain},
		})
	}
	// Audit mTLS enforcement toggle when require_client_cert changed.
	if prevRequireClientCert != requireClientCert {
		audit.Write(ctx, h.DB(), h.Logger, r, audit.Entry{
			UserID: actorUserID(sess), Action: "host.mtls_enforcement_changed", Entity: "route",
			EntityID: itoa64(id),
			Meta:     map[string]any{"enabled": requireClientCert},
		})
	}
	// Rewrite child collections atomically (DELETE+INSERT in a tx) so a partial
	// failure can't leave an empty upstream pool or half-applied location rules.
	if tx, txErr := h.DB().BeginTx(ctx, nil); txErr == nil {
		_, e1 := tx.ExecContext(ctx, `DELETE FROM route_upstreams WHERE route_id = ?`, id)
		var e2 error
		for i, u := range newUpstreams {
			enInt := 0
			if u.Enabled {
				enInt = 1
			}
			// Per-upstream passive health columns are left at their defaults:
			// stock Caddy cannot honor them, so the UI no longer sets them.
			if _, e2 = tx.ExecContext(ctx,
				`INSERT INTO route_upstreams
				 (route_id, host, port, weight, max_requests, enabled, sort_order)
				 VALUES (?, ?, ?, ?, ?, ?, ?)`,
				id, u.Host, u.Port, u.Weight, u.MaxRequests, enInt, i); e2 != nil {
				break
			}
		}
		_, e3 := tx.ExecContext(ctx, `DELETE FROM route_location_rules WHERE route_id = ?`, id)
		var e4 error
		for i, rule := range newLocationRules {
			if _, e4 = tx.ExecContext(ctx,
				`INSERT INTO route_location_rules
				 (route_id, sort_order, path_glob, action, upstream_scheme, upstream_host, upstream_port, redirect_url, redirect_code, rewrite_uri)
				 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
				id, i, rule.Path, rule.Action, rule.UpstreamScheme, nullableString(rule.UpstreamHost), nullableInt(rule.UpstreamPort),
				nullableString(rule.RedirectURL), rule.RedirectCode, nullableString(rule.RewriteURI)); e4 != nil {
				break
			}
		}
		if e1 != nil || e2 != nil || e3 != nil || e4 != nil {
			_ = tx.Rollback()
			h.Logger.Warn("host child rules rewrite failed", "id", id, "err", firstErr(e1, e2, e3, e4))
		} else {
			_ = tx.Commit()
		}
	}
	// DNS steering: additive UPDATE (like portal_protect below) so a failure
	// here can't roll back the rest of the host edit.
	dnsSteeringEnabled := r.FormValue("dns_steering_enabled") == "1"
	dnsProviderID, _ := strconv.ParseInt(r.FormValue("dns_provider_id"), 10, 64)
	dnsSteeringTTL, _ := strconv.Atoi(r.FormValue("dns_steering_ttl"))
	if dnsSteeringTTL <= 0 {
		dnsSteeringTTL = 60
	}
	var dnsProviderIDVal sql.NullInt64
	if dnsProviderID > 0 {
		dnsProviderIDVal = sql.NullInt64{Int64: dnsProviderID, Valid: true}
	} else {
		dnsSteeringEnabled = false // can't steer without a provider
	}
	if _, derr := h.DB().ExecContext(ctx,
		`UPDATE routes SET dns_steering_enabled=?, dns_provider_id=?, dns_steering_ttl=? WHERE id=?`,
		dnsSteeringEnabled, dnsProviderIDVal, dnsSteeringTTL, id); derr != nil {
		h.Logger.Warn("dns steering update", "id", id, "err", derr)
	} else if prevDNSSteeringEnabled != dnsSteeringEnabled {
		audit.Write(ctx, h.DB(), h.Logger, r, audit.Entry{
			UserID: actorUserID(sess), Action: "host.dns_steering_toggled", Entity: "route",
			EntityID: itoa64(id),
			Meta:     map[string]any{"enabled": dnsSteeringEnabled, "provider_id": dnsProviderID, "ttl": dnsSteeringTTL},
		})
	}

	// Built-in portal: persist the toggle + replace grants. Scope-safe -
	// SetRouteGrants only writes group IDs the caller is allowed to reference
	// (groups owned by the route's client, plus globals for super_admin), so a
	// scoped admin cannot grant another tenant's group via a forged form post.
	if h.Portal != nil {
		var portalClientID int64
		if cerr := h.DB().QueryRowContext(ctx,
			`SELECT client_id FROM services WHERE id = ?`, serviceID).Scan(&portalClientID); cerr != nil {
			redirectWithFlash(w, r, editPath, "", "portal: owner lookup failed")
			return
		}
		includeGlobal := sess != nil && sess.Role == "super_admin"
		// A failed read must not leave `visible` empty: that silently drops every
		// grant and turns a protected route into one nobody can reach.
		grps, gerr := h.Portal.GroupsForGrant(ctx, portalClientID, includeGlobal)
		if gerr != nil {
			redirectWithFlash(w, r, editPath, "", "portal: group lookup failed, protection left unchanged")
			return
		}
		visible := map[int64]bool{}
		for _, g := range grps {
			visible[g.ID] = true
		}
		// Toggle and grants in one transaction (WP2): a half-applied portal write
		// is either an open protected route or a locked-out one.
		if perr := h.Portal.SetRouteProtection(ctx, id, portalProtect, portalGroupIDs, visible, false); perr != nil {
			h.Logger.Warn("portal protection update", "id", id, "err", perr)
			redirectWithFlash(w, r, editPath, "", "portal: saving protection failed")
			return
		}
		audit.Write(ctx, h.DB(), h.Logger, r, audit.Entry{
			UserID: actorUserID(sess), Action: "portal.route.grants", Entity: "route", EntityID: itoa64(id),
			Meta: map[string]any{"protect": portalProtect, "groups": portalGroupIDs},
		})
	}

	// Node-level settings - TLS connection policies above all - are rebuilt per
	// node, so pushing only the anchor leaves every route_node_assignments peer
	// on the previous policy while the UI reports the new one as enforced.
	//
	// Queueing comes first and on its own context: it is pure DB work, while
	// Resync does network I/O to a node that may be hung. Sharing one deadline
	// would let a single unreachable anchor eat the whole window and silently
	// drop the healthy peers on the floor.
	go func() {
		defer recoverBg(h.Logger, "resync")
		qctx, qcancel := context.WithTimeout(h.Routes.BackgroundCtx(), 10*time.Second)
		h.Routes.SchedulePushForRoute(qctx, id)
		qcancel()

		ctx, cancel := context.WithTimeout(h.Routes.BackgroundCtx(), 30*time.Second)
		defer cancel()
		_ = h.Routes.Resync(ctx, nodeID)
	}()

	audit.Write(ctx, h.DB(), h.Logger, r, audit.Entry{
		UserID: actorUserID(sess), Action: "admin.host.update", Entity: "route",
		EntityID: itoa64(id),
		Meta: map[string]any{
			"domain": domain, "kind": kind, "tag": tag,
			"ssl": ssl, "force_https": forceHTTPS, "websocket": websocket,
			"cache_enabled":    cacheEnabled,
			"cache_public":     cachePublic,
			"maintenance_mode": maintenanceMode,
			"location_rules":   len(newLocationRules),
			"tls_pq_only":      tlsPQOnly,
		},
	})
	// Stay on the edit page (preserving the active tab via #fragment so the
	// admin doesn't lose context after every save).
	dest := "/admin/hosts/" + strconv.FormatInt(id, 10) + "/edit"
	if tab := strings.TrimSpace(r.FormValue("active_tab")); isTabSlug(tab) {
		dest += "#tab=" + tab
	}
	redirectWithFlash(w, r, dest, "Host updated", "")
}
