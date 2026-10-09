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
	"github.com/host-yt/caddy-proxy-manager/internal/customfields"
	"github.com/host-yt/caddy-proxy-manager/internal/domain/routes"
	"github.com/host-yt/caddy-proxy-manager/internal/httpserver/middleware"
)

type hostsNewData struct {
	baseAdminData
	NodeGroups []hostsNewNodeGroup
	Groups     []hostGroupOption
	Form       hostsNewForm
	CFViews    []customfields.View
	// ClientTunnels: admin-self client's WG peers for the "Backend via" picker.
	ClientTunnels []tunnelOption
	// MTLSCAs feeds the trust-anchor dropdown. Empty = the mTLS block is not
	// rendered at all, so the form can never offer a control that cannot work.
	MTLSCAs []mtlsCAOption
}

type hostsNewNode struct {
	ID       int64
	Name     string
	Hostname string
	Group    string
	IP       string
}

// hostsNewNodeGroup is a node group option on the add-host form. Placement is
// group-scoped (see routes.nodePlacement), so the form picks a group, not a node.
type hostsNewNodeGroup struct {
	ID    int64
	Name  string
	Mode  string // single | active_active | failover
	Nodes []hostsNewNode
}

type hostsNewForm struct {
	Domain         string
	BackendIP      string
	Port           string
	UpstreamScheme string
	NodeGroupID    string
	NodeID         string // legacy fallback: pre-group forms/scripts POST node_id
	SSL            bool
	WebSocket      bool
	Kind           string
	RedirectURL    string
	RedirectCode   string
	Tag            string
	// External-HTTPS-upstream route: proxy to an allowlisted public FQDN.
	External           bool
	ExternalHost       string
	UpstreamHostHeader string
	// Wildcard DNS-01: domain served by a *.zone cert (gated by DNS01_AVAILABLE).
	WildcardEnabled bool
	WildcardZone    string
	GroupID         int64
	ViaWGPeerID     string
	// ResolveNodeSide: operator accepts that only the node can resolve this
	// backend name. Without it an unresolvable name is refused, because a
	// failed panel lookup says nothing about where the name points.
	ResolveNodeSide bool
	// mTLS client-cert enforcement, set at create so a host meant to be
	// locked is never served open in the window before the first edit.
	RequireClientCert bool
	MTLSCAID          int64
}

// HostsNew renders /admin/hosts/new (GET).
func (h *AdminHandlers) HostsNew(w http.ResponseWriter, r *http.Request) {
	d := hostsNewData{
		baseAdminData: h.base(r, "Add host"),
		Form:          hostsNewForm{SSL: true, WebSocket: true, Kind: "proxy", RedirectCode: "308", UpstreamScheme: "http"},
	}
	d.NodeGroups = h.loadNodeGroupOptions(r.Context())
	db := h.DB()
	if db != nil {
		ctx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
		defer cancel()
		d.Groups = loadHostGroups(ctx, db)
		d.MTLSCAs = loadMTLSCAOptions(ctx, db)
		if defs, err := customfields.LoadDefs(ctx, db, "host"); err == nil {
			d.CFViews = customfields.Merge(defs, nil)
		}
		// Tunnel picker: admin-self client's peers (route lands under that client).
		if sess := middleware.SessionFromContext(r.Context()); sess != nil {
			var cid int64
			_ = db.QueryRowContext(ctx, "SELECT id FROM clients WHERE user_id = ?", sess.UserID).Scan(&cid)
			d.ClientTunnels = loadClientTunnels(ctx, db, cid)
		}
	}
	h.render(w, "hosts_new", d)
}

// HostsCreate handles /admin/hosts/new (POST). It atomically:
//  1. Ensures the super-admin has a clients row (1:1 with their user).
//  2. Ensures the "_admin-self" plan exists (kind=npm, uncapped).
//  3. Finds or creates a services row for (admin client, backend_ip).
//     Range is 1-65535 so the admin can map any port without re-editing
//     the service.
//  4. Calls Routes.Create which performs the placement, INSERT, and
//     Caddy push in one transaction.
func (h *AdminHandlers) HostsCreate(w http.ResponseWriter, r *http.Request) {
	db := h.DB()
	if db == nil {
		http.Error(w, "no db", http.StatusServiceUnavailable)
		return
	}
	if h.Routes == nil {
		http.Error(w, "routes service not wired", http.StatusInternalServerError)
		return
	}
	sess := middleware.SessionFromContext(r.Context())
	if sess == nil {
		http.Error(w, "no session", http.StatusUnauthorized)
		return
	}
	_ = r.ParseForm()
	form := hostsNewForm{
		Domain:         strings.TrimSpace(strings.ToLower(r.FormValue("domain"))),
		BackendIP:      strings.TrimSpace(r.FormValue("backend_ip")),
		Port:           strings.TrimSpace(r.FormValue("port")),
		UpstreamScheme: strings.TrimSpace(r.FormValue("upstream_scheme")),
		NodeGroupID:    strings.TrimSpace(r.FormValue("node_group_id")),
		NodeID:         strings.TrimSpace(r.FormValue("node_id")),
		SSL:            r.FormValue("ssl") == "1",
		WebSocket:      r.FormValue("websocket") == "1",
		Kind:           strings.TrimSpace(r.FormValue("kind")),
		RedirectURL:    strings.TrimSpace(r.FormValue("redirect_url")),
		RedirectCode:   strings.TrimSpace(r.FormValue("redirect_code")),
		Tag:            strings.TrimSpace(r.FormValue("tag")),

		External:           r.FormValue("upstream_external") == "1",
		ExternalHost:       strings.ToLower(strings.TrimSpace(r.FormValue("external_host"))),
		UpstreamHostHeader: strings.TrimSpace(r.FormValue("upstream_host_header")),
		WildcardEnabled:    r.FormValue("wildcard_enabled") == "1",
		WildcardZone:       strings.ToLower(strings.TrimSpace(r.FormValue("wildcard_zone"))),
		ViaWGPeerID:        strings.TrimSpace(r.FormValue("via_wg_peer_id")),
		ResolveNodeSide:    r.FormValue("backend_resolve_node_side") == "1",
		RequireClientCert:  r.FormValue("require_client_cert") == "1",
	}
	// Waiving panel-side resolution means the target is never screened against
	// a resolved address, so it stays with the unrestricted role.
	if err := checkNodeSideResolve(sess, form.ResolveNodeSide); err != nil {
		form.ResolveNodeSide = false
		h.renderHostsNewErr(w, r, form, err.Error())
		return
	}
	// Same placeholder policy as the edit path; routes.Create re-checks, this
	// only keeps the form error next to the submitted values.
	if err := screenTenantURLFields(form.RedirectURL, form.UpstreamHostHeader); err != nil {
		h.renderHostsNewErr(w, r, form, err.Error())
		return
	}
	form.MTLSCAID, _ = strconv.ParseInt(r.FormValue("mtls_ca_id"), 10, 64)
	if !form.RequireClientCert {
		form.MTLSCAID = 0 // no enforcement, no anchor - mirrors the edit path
	}
	viaWGPeerID, _ := strconv.ParseInt(form.ViaWGPeerID, 10, 64)
	if form.External {
		viaWGPeerID = 0 // mutual exclusion, same as edit
	}
	if form.UpstreamScheme != "https" {
		form.UpstreamScheme = "http"
	}
	if form.Kind != "redirect" {
		form.Kind = "proxy"
	}
	if form.External {
		// External routes are always an https proxy; the customer port range
		// and backend-IP field do not apply.
		form.Kind = "proxy"
		form.UpstreamScheme = "https"
	}
	port, _ := strconv.Atoi(form.Port)
	redirectCode, _ := strconv.Atoi(form.RedirectCode)
	nodeGroupID, _ := strconv.ParseInt(form.NodeGroupID, 10, 64)
	nodeID, _ := strconv.ParseInt(form.NodeID, 10, 64)
	groupID, _ := strconv.ParseInt(r.FormValue("group_id"), 10, 64)

	if form.Domain == "" || (nodeGroupID == 0 && nodeID == 0) {
		h.renderHostsNewErr(w, r, form, "domain and node group are required")
		return
	}
	if form.External {
		// External upstream: validate the FQDN (allowlist is enforced in
		// Create). Default the port to 443. Service bookkeeping is keyed on
		// backend_ip, so reuse the external host there.
		if form.ExternalHost == "" || !isValidUpstreamHost(form.ExternalHost) {
			h.renderHostsNewErr(w, r, form, "external host must be a valid FQDN")
			return
		}
		if port == 0 {
			port = 443
		}
		form.BackendIP = form.ExternalHost
	} else if form.Kind == "proxy" {
		// With a tunnel the backend may stay empty (dial peer IP).
		if (form.BackendIP == "" && viaWGPeerID == 0) || port <= 0 || port > 65535 {
			h.renderHostsNewErr(w, r, form, "backend IP and port are required for proxy routes")
			return
		}
		if form.BackendIP != "" && !isValidUpstreamHost(form.BackendIP) {
			h.renderHostsNewErr(w, r, form, "backend must be a valid IP or hostname")
			return
		}
	} else {
		// Redirect: backend isn't called, but admin service is keyed on
		// (client, backend_ip). Use a stable sentinel so all redirect
		// routes share one bookkeeping service per admin.
		form.BackendIP = "0.0.0.0"
		port = 0
		if form.RedirectURL == "" {
			h.renderHostsNewErr(w, r, form, "redirect URL is required for redirect routes")
			return
		}
		switch redirectCode {
		case 0:
			redirectCode = 308
		case 301, 302, 307, 308:
		default:
			h.renderHostsNewErr(w, r, form, "redirect code must be 301/302/307/308")
			return
		}
	}

	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()

	// The hosts form provisions under the caller's OWN client, so a client-scoped
	// admin must not reach it: the route would land outside its assigned clients.
	tenantScoped, provOK := h.selfProvisionScope(ctx, sess)
	if !provOK {
		h.renderHostsNewErr(w, r, form, "forbidden: your account is scoped to assigned clients")
		return
	}

	// SSRF screen: proxy backends and external upstreams must not target
	// loopback/link-local/metadata or the control plane. Redirect routes use a
	// sentinel backend (0.0.0.0) that is never dialed, so skip them.
	// Only an explicit node-side-resolution opt-in waives the resolving step,
	// and never the deny set.
	if form.Kind == "proxy" || form.External {
		infra, ierr := loadInfraOrFail(ctx, db, h.Logger)
		if ierr != nil {
			h.renderHostsNewErr(w, r, form, ierr.Error())
			return
		}
		if err := screenBackendWith(ctx, infra, form.BackendIP, port, form.ResolveNodeSide); err != nil {
			h.Logger.Warn("backend host screen failed", "err", err)
			h.renderHostsNewErr(w, r, form, unresolvedHint(err, "backend host is not reachable or not allowed"))
			return
		}
	}

	// The form picks a node group; placement inside it is mode-driven
	// (routes.nodePlacement). Legacy POSTs that still send node_id get the
	// node's group resolved for them.
	if nodeGroupID == 0 {
		if err := db.QueryRowContext(ctx,
			"SELECT node_group_id FROM caddy_nodes WHERE id = ? AND approved_at IS NOT NULL AND is_enabled = 1",
			nodeID).Scan(&nodeGroupID); err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				h.renderHostsNewErr(w, r, form, "node not found or not approved")
				return
			}
			h.Logger.Error("admin hosts: node lookup", "err", err)
			h.renderHostsNewErr(w, r, form, "node lookup failed")
			return
		}
	} else {
		var eligible int
		if err := db.QueryRowContext(ctx,
			"SELECT COUNT(*) FROM caddy_nodes WHERE node_group_id = ? AND approved_at IS NOT NULL AND is_enabled = 1",
			nodeGroupID).Scan(&eligible); err != nil {
			h.Logger.Error("admin hosts: group lookup", "err", err)
			h.renderHostsNewErr(w, r, form, "node group lookup failed")
			return
		}
		if eligible == 0 {
			h.renderHostsNewErr(w, r, form, "node group has no approved + enabled nodes")
			return
		}
	}

	clientID, err := ensureAdminClient(ctx, db, sess.UserID, sess.ResellerID)
	if err != nil {
		h.Logger.Error("admin hosts: ensure client", "err", err)
		h.renderHostsNewErr(w, r, form, "could not provision admin client")
		return
	}
	planID, err := ensureAdminPlan(ctx, db, nodeGroupID)
	if err != nil {
		h.Logger.Error("admin hosts: ensure plan", "err", err)
		h.renderHostsNewErr(w, r, form, "could not provision admin plan")
		return
	}
	// Tunnel with empty backend: key the bookkeeping service on peer IP.
	if form.BackendIP == "" && viaWGPeerID > 0 {
		var peerIP string
		_ = db.QueryRowContext(ctx,
			"SELECT COALESCE(assigned_ip,'') FROM customer_wg_peer WHERE id = ? AND client_id = ? AND status <> 'revoked'",
			viaWGPeerID, clientID).Scan(&peerIP)
		if peerIP == "" {
			h.renderHostsNewErr(w, r, form, "selected tunnel not found or not yours")
			return
		}
		form.BackendIP = peerIP
	}
	serviceID, err := ensureAdminService(ctx, db, clientID, form.BackendIP, planID, nodeGroupID)
	if err != nil {
		h.Logger.Error("admin hosts: ensure service", "err", err)
		h.renderHostsNewErr(w, r, form, "could not provision admin service")
		return
	}

	// Validate the mTLS CA up front for a readable error; Create re-checks it
	// (it is the choke point for every create path) and refuses otherwise.
	if form.RequireClientCert {
		// External routes always get their own cert, so SSL is forced on there.
		if !form.SSL && !form.External {
			h.renderHostsNewErr(w, r, form, "client certificates require SSL - enable SSL for this host first")
			return
		}
		if form.MTLSCAID <= 0 {
			h.renderHostsNewErr(w, r, form, "require_client_cert needs an mTLS CA assigned")
			return
		}
		// Reject if CA has no uploaded certificate or is not active.
		var caCount int
		_ = db.QueryRowContext(ctx,
			"SELECT COUNT(*) FROM mtls_cas WHERE id=? AND status='active' AND cert_pem IS NOT NULL AND cert_pem != ''",
			form.MTLSCAID).Scan(&caCount)
		if caCount == 0 {
			h.renderHostsNewErr(w, r, form, "selected mTLS CA is not active - upload a certificate first")
			return
		}
	}

	// Generate the one-time inbound bearer for external routes (Create
	// encrypts it at rest; we show the plaintext once below).
	var proxySecret string
	if form.External {
		s, gerr := genProxySecret()
		if gerr != nil {
			h.renderHostsNewErr(w, r, form, "could not generate proxy secret")
			return
		}
		proxySecret = s
	}

	// Load host custom field defs and encode submitted values before create.
	cfDefs, cfDefsErr := customfields.LoadDefs(ctx, db, "host")
	if cfDefsErr != nil {
		h.Logger.Warn("admin hosts: load cf defs", "err", cfDefsErr)
	}
	cfJSON, cfErr := customfields.EncodeFromForm(cfDefs, r.Form)
	if cfErr != nil {
		h.renderHostsNewErr(w, r, form, cfErr.Error())
		return
	}

	// A limited admin is a tenant, not the operator: pass their clientID so the
	// route must prove DNS ownership. Only a platform admin stays trusted.
	ownerScope := int64(0)
	if tenantScoped {
		ownerScope = clientID
	}
	routeID, err := h.Routes.Create(ctx, ownerScope, routes.CreateInput{
		ServiceID:      serviceID,
		UpstreamPort:   port,
		UpstreamScheme: form.UpstreamScheme,
		Domain:         form.Domain,
		SSL:            form.SSL,
		WebSocket:      form.WebSocket,
		ForceHTTPS:     form.SSL,
		Kind:           form.Kind,
		RedirectURL:    form.RedirectURL,
		RedirectCode:   redirectCode,
		Tag:            form.Tag,

		External:           form.External,
		ExternalHost:       form.ExternalHost,
		UpstreamHostHeader: form.UpstreamHostHeader,
		ProxySecretPlain:   proxySecret,
		WildcardEnabled:    form.WildcardEnabled,
		WildcardZone:       form.WildcardZone,
		// Persisted in the same INSERT so host metadata is atomic with the route.
		GroupID:      groupID,
		CustomFields: cfJSON,
		ViaWGPeerID:  viaWGPeerID,

		BackendResolveNodeSide: form.ResolveNodeSide,

		RequireClientCert: form.RequireClientCert,
		MTLSCAID:          form.MTLSCAID,
	})
	if err != nil {
		h.Logger.Warn("admin hosts: route create", "err", err)
		h.renderHostsNewErr(w, r, form, "create failed: "+sanitizeErr(err)) // nosemgrep: go.lang.security.injection.tainted-sql-string.tainted-sql-string -- flash text, not SQL
		return
	}

	// Never log the secret in the audit meta.
	audit.Write(ctx, db, h.Logger, r, audit.Entry{
		UserID: actorUserID(sess), Action: "admin.host.create", Entity: "route",
		EntityID: itoa64(routeID),
		Meta: map[string]any{
			"domain": form.Domain, "backend_ip": form.BackendIP, "port": port,
			"node_group_id": nodeGroupID, "kind": form.Kind, "redirect_url": form.RedirectURL,
			"external": form.External, "external_host": form.ExternalHost,
			// Create persists these or fails, so the entry never claims more
			// enforcement than the route actually got.
			"require_client_cert": form.RequireClientCert, "mtls_ca_id": form.MTLSCAID,
		},
	})
	if form.External && proxySecret != "" {
		// Never splice the plaintext bearer into the redirect URL - it would
		// land in browser history / Referer / front-proxy logs. It's
		// recoverable on demand via the edit page's audited Reveal button.
		edit := "/admin/hosts/" + itoa64(routeID) + "/edit"
		redirectWithFlash(w, r, edit,
			"External host added: "+form.Domain+". Click Reveal to copy the inbound bearer.", "")
		return
	}
	// Land on the edit page: WAF, geo, headers and LB all live in its tabs,
	// and the add form intentionally stays minimal.
	redirectWithFlash(w, r, "/admin/hosts/"+itoa64(routeID)+"/edit",
		"Host added: "+form.Domain+". Fine-tune WAF, geo and headers in the tabs below.", "")
}

func (h *AdminHandlers) renderHostsNewErr(w http.ResponseWriter, r *http.Request, form hostsNewForm, msg string) {
	d := hostsNewData{baseAdminData: h.base(r, "Add host"), Form: form}
	d.Error = msg
	d.NodeGroups = h.loadNodeGroupOptions(r.Context())
	db := h.DB()
	if db != nil {
		ctx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
		defer cancel()
		d.Groups = loadHostGroups(ctx, db)
		d.MTLSCAs = loadMTLSCAOptions(ctx, db)
		if defs, err := customfields.LoadDefs(ctx, db, "host"); err == nil {
			// Preserve submitted values on re-render after validation error.
			_ = r.ParseForm()
			vals, _ := customfields.EncodeFromForm(defs, r.Form)
			d.CFViews = customfields.Merge(defs, customfields.Decode(vals))
		}
		if sess := middleware.SessionFromContext(r.Context()); sess != nil {
			var cid int64
			_ = db.QueryRowContext(ctx, "SELECT id FROM clients WHERE user_id = ?", sess.UserID).Scan(&cid)
			d.ClientTunnels = loadClientTunnels(ctx, db, cid)
		}
	}
	h.render(w, "hosts_new", d)
}

// loadNodeOptions lists eligible nodes flat - used by the hosts-list filter
// and the L4 streams form, which really do target a single node.
func (h *AdminHandlers) loadNodeOptions(ctx context.Context) []hostsNewNode {
	db := h.DB()
	if db == nil {
		return nil
	}
	c, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	rows, err := db.QueryContext(c,
		`SELECT n.id, n.name, n.public_hostname, ng.name
		 FROM caddy_nodes n JOIN node_groups ng ON ng.id = n.node_group_id
		 WHERE n.approved_at IS NOT NULL AND n.is_enabled = 1
		 ORDER BY ng.name, n.name`)
	if err != nil {
		return nil
	}
	defer rows.Close()
	var out []hostsNewNode
	for rows.Next() {
		var n hostsNewNode
		if err := rows.Scan(&n.ID, &n.Name, &n.Hostname, &n.Group); err == nil {
			out = append(out, n)
		}
	}
	return out
}

func (h *AdminHandlers) loadNodeGroupOptions(ctx context.Context) []hostsNewNodeGroup {
	db := h.DB()
	if db == nil {
		return nil
	}
	c, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	rows, err := db.QueryContext(c,
		`SELECT ng.id, ng.name, ng.mode, n.id, n.name, n.public_hostname, COALESCE(n.public_ip,'')
		 FROM node_groups ng JOIN caddy_nodes n ON n.node_group_id = ng.id
		 WHERE n.approved_at IS NOT NULL AND n.is_enabled = 1
		 ORDER BY ng.name, n.name`)
	if err != nil {
		return nil
	}
	defer rows.Close()
	var out []hostsNewNodeGroup
	for rows.Next() {
		var (
			gID   int64
			gName string
			gMode string
			n     hostsNewNode
		)
		if err := rows.Scan(&gID, &gName, &gMode, &n.ID, &n.Name, &n.Hostname, &n.IP); err != nil {
			continue
		}
		if len(out) == 0 || out[len(out)-1].ID != gID {
			out = append(out, hostsNewNodeGroup{ID: gID, Name: gName, Mode: gMode})
		}
		g := &out[len(out)-1]
		g.Nodes = append(g.Nodes, n)
	}
	return out
}
