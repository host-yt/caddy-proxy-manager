package handlers

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"strconv"
	"strings"
	"time"

	"github.com/host-yt/caddy-proxy-manager/internal/audit"
	"github.com/host-yt/caddy-proxy-manager/internal/auth"
	"github.com/host-yt/caddy-proxy-manager/internal/httpserver/middleware"
	"github.com/host-yt/caddy-proxy-manager/internal/security"
	"github.com/host-yt/caddy-proxy-manager/internal/store"
	"github.com/host-yt/caddy-proxy-manager/internal/streamguard"
)

// scopeCheckStream verifies the caller may act on a stream by resolving its
// service and deferring to scopeCheckService. True for super_admin / no scope.
func (h *AdminHandlers) scopeCheckStream(ctx context.Context, sess *auth.Session, streamID int64) bool {
	if sess == nil || sess.Role == "super_admin" || h.AdminScope == nil {
		return true
	}
	db := h.DB()
	if db == nil {
		return false
	}
	var svcID int64
	if err := db.QueryRowContext(ctx, "SELECT service_id FROM stream_routes WHERE id = ?", streamID).Scan(&svcID); err != nil {
		return false
	}
	return h.scopeCheckService(ctx, sess, svcID)
}

// Streams admin: CRUD on stream_routes (TCP/UDP L4 forwards via the
// caddy-l4 module embedded in the custom Caddy build). Admin-only;
// customers don't get a stream-proxy surface in the client portal MVP.

// ---- data types ----

type streamRow struct {
	ID               int64
	Protocol         string
	ListenPort       int
	UpstreamPort     int
	BackendIP        string
	NodeName         string
	NodeHostname     string
	Status           string
	QuarantineReason string // why the emission screen parked this row; empty when healthy
	Tag              string
	CreatedAt        string
	MatchMode        string
	MatchValues      string // CSV of SNI/host values; preserved on edit to avoid silent data loss
	LBPolicy         string
	ProxyProtoIn     string
	ProxyProtoOut    string
}

// Quarantined reports whether the row is parked by the destination screen.
func (s streamRow) Quarantined() bool { return s.Status == "quarantined" }

type streamUpstreamRow struct {
	ID      int64
	Address string
	Weight  int
}

// streamEditData backs the streams edit page (GET /admin/streams/{id}/edit).
type streamEditData struct {
	baseAdminData
	Stream    streamRow
	Upstreams []streamUpstreamRow
	Nodes     []hostsNewNode
}

type streamsData struct {
	baseAdminData
	Streams         []streamRow
	Nodes           []hostsNewNode
	ModuleAvailable bool
	Form            streamForm
}

type streamForm struct {
	Protocol      string
	ListenPort    string
	UpstreamPort  string
	BackendIP     string
	NodeID        string
	Tag           string
	MatchMode     string
	MatchValues   string // newline or comma-separated
	LBPolicy      string
	ProxyProtoIn  string
	ProxyProtoOut string
	CIDRAllow     string // newline or comma-separated
	CIDRDeny      string
	// Upstreams for multi-upstream form (address:weight pairs, one per line)
	UpstreamsRaw string
}

// ---- validation helpers ----

// validMatchMode checks the match_mode enum.
func validMatchMode(s string) bool {
	return s == "any" || s == "sni" || s == "http_host"
}

// validLBPolicy checks the lb_policy enum.
func validLBPolicy(s string) bool {
	return s == "round_robin" || s == "random" || s == "least_conn" || s == "first"
}

// validProxyProto checks proxy_proto_in/out enum.
func validProxyProto(s string) bool {
	return s == "none" || s == "v1" || s == "v2"
}

// parseCIDRList validates each CIDR in a CSV/newline list and returns the
// trimmed valid entries. Returns an error string on first invalid entry.
func parseCIDRList(raw string) ([]string, error) {
	if raw == "" {
		return nil, nil
	}
	raw = strings.ReplaceAll(raw, "\n", ",")
	parts := strings.Split(raw, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		if _, err := netip.ParsePrefix(p); err != nil {
			// Fall back to net.ParseCIDR for IPv4 with host bits set.
			if _, _, err2 := net.ParseCIDR(p); err2 != nil {
				return nil, fmt.Errorf("invalid CIDR %q", p)
			}
		}
		out = append(out, p)
	}
	return out, nil
}

// parseCSVList splits comma or newline-separated strings into trimmed tokens.
func parseCSVList(raw string) []string {
	raw = strings.ReplaceAll(raw, "\n", ",")
	parts := strings.Split(raw, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if t := strings.TrimSpace(p); t != "" {
			out = append(out, t)
		}
	}
	return out
}

// joinCSV joins a slice for DB storage.
func joinCSV(ss []string) string { return strings.Join(ss, ",") }

// ---- handlers ----

// StreamsList renders /admin/streams.
func (h *AdminHandlers) StreamsList(w http.ResponseWriter, r *http.Request) {
	d := streamsData{
		baseAdminData:   h.base(r, "Stream proxy (TCP/UDP)"),
		ModuleAvailable: h.Routes != nil && h.Routes.Layer4ModuleAvailable,
		Form:            streamForm{Protocol: "tcp", MatchMode: "any", LBPolicy: "round_robin", ProxyProtoIn: "none", ProxyProtoOut: "none"},
	}
	db := h.DB()
	if db == nil {
		h.render(w, "streams", d)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 3*time.Second)
	defer cancel()

	d.Nodes = h.loadNodeOptions(ctx)
	// Scope: non-super_admins see only streams whose service belongs to an
	// assigned client (streams are self-provisioned per client like hosts).
	streamWhere := ""
	var streamArgs []any
	if allowed, all, ok := h.adminClientScope(ctx, middleware.SessionFromContext(r.Context())); ok && !all {
		if len(allowed) == 0 {
			streamWhere = " WHERE 1=0"
		} else {
			ids := make([]int64, 0, len(allowed))
			for id := range allowed {
				ids = append(ids, id)
			}
			streamWhere = " WHERE sv.client_id IN (" + placeholders(len(ids)) + ")"
			for _, id := range ids {
				streamArgs = append(streamArgs, id)
			}
		}
	}
	rows, err := db.QueryContext(ctx,
		`SELECT sr.id, sr.protocol, sr.listen_port, sr.upstream_port,
		        COALESCE(NULLIF(sr.backend_ip_override,''), sv.backend_ip), n.name, n.public_hostname,
		        CASE WHEN sr.quarantined_at IS NOT NULL THEN 'quarantined' ELSE sr.status END,
		        COALESCE(sr.quarantine_reason,''),
		        COALESCE(sr.tag,''),
		        DATE_FORMAT(sr.created_at, '%Y-%m-%d %H:%i'),
		        COALESCE(sr.match_mode,'any'),
		        COALESCE(sr.lb_policy,'round_robin'),
		        COALESCE(sr.proxy_proto_in,'none'),
		        COALESCE(sr.proxy_proto_out,'none')
		 FROM stream_routes sr
		 JOIN services sv     ON sv.id = sr.service_id
		 JOIN caddy_nodes n   ON n.id = sr.caddy_node_id`+streamWhere+`
		 ORDER BY sr.listen_port ASC, sr.id ASC`, streamArgs...)
	if err != nil {
		h.Logger.Warn("streams list", "err", err)
		d.Error = "Could not load L4 streams. Refresh to retry; if it persists, check the panel logs for 'streams list'."
		h.render(w, "streams", d)
		return
	}
	defer rows.Close()
	for rows.Next() {
		var s streamRow
		if err := rows.Scan(&s.ID, &s.Protocol, &s.ListenPort, &s.UpstreamPort,
			&s.BackendIP, &s.NodeName, &s.NodeHostname, &s.Status, &s.QuarantineReason,
			&s.Tag, &s.CreatedAt,
			&s.MatchMode, &s.LBPolicy, &s.ProxyProtoIn, &s.ProxyProtoOut); err == nil {
			d.Streams = append(d.Streams, s)
		}
	}
	h.render(w, "streams", d)
}

// StreamsCreate handles POST /admin/streams/new. Same admin-self
// provisioning pattern as HostsCreate: any backend_ip auto-creates a
// services row under the admin's _admin-self plan.
func (h *AdminHandlers) StreamsCreate(w http.ResponseWriter, r *http.Request) {
	db := h.DB()
	if db == nil {
		http.Error(w, "no db", http.StatusServiceUnavailable)
		return
	}
	if h.Routes == nil || !h.Routes.Layer4ModuleAvailable {
		redirectWithFlash(w, r, "/admin/streams", "", "L4 module not enabled (set LAYER4_AVAILABLE=1 and rebuild the Caddy image)")
		return
	}
	sess := middleware.SessionFromContext(r.Context())
	if sess == nil {
		http.Error(w, "no session", http.StatusUnauthorized)
		return
	}
	_ = r.ParseForm()
	form := streamForm{
		Protocol:      strings.TrimSpace(r.FormValue("protocol")),
		ListenPort:    strings.TrimSpace(r.FormValue("listen_port")),
		UpstreamPort:  strings.TrimSpace(r.FormValue("upstream_port")),
		BackendIP:     strings.TrimSpace(r.FormValue("backend_ip")),
		NodeID:        strings.TrimSpace(r.FormValue("node_id")),
		Tag:           strings.TrimSpace(r.FormValue("tag")),
		MatchMode:     strings.TrimSpace(r.FormValue("match_mode")),
		MatchValues:   strings.TrimSpace(r.FormValue("match_values")),
		LBPolicy:      strings.TrimSpace(r.FormValue("lb_policy")),
		ProxyProtoIn:  strings.TrimSpace(r.FormValue("proxy_proto_in")),
		ProxyProtoOut: strings.TrimSpace(r.FormValue("proxy_proto_out")),
		CIDRAllow:     strings.TrimSpace(r.FormValue("cidr_allow")),
		CIDRDeny:      strings.TrimSpace(r.FormValue("cidr_deny")),
		UpstreamsRaw:  strings.TrimSpace(r.FormValue("upstreams_raw")),
	}

	// Validate and normalise enum fields.
	switch form.Protocol {
	case "tcp", "udp", "both":
	default:
		form.Protocol = "tcp"
	}
	if !validMatchMode(form.MatchMode) {
		form.MatchMode = "any"
	}
	if !validLBPolicy(form.LBPolicy) {
		form.LBPolicy = "round_robin"
	}
	if !validProxyProto(form.ProxyProtoIn) {
		form.ProxyProtoIn = "none"
	}
	if !validProxyProto(form.ProxyProtoOut) {
		form.ProxyProtoOut = "none"
	}

	listenPort, _ := strconv.Atoi(form.ListenPort)
	upstreamPort, _ := strconv.Atoi(form.UpstreamPort)
	nodeID, _ := strconv.ParseInt(form.NodeID, 10, 64)
	if listenPort <= 0 || listenPort > 65535 || upstreamPort <= 0 || upstreamPort > 65535 {
		redirectWithFlash(w, r, "/admin/streams", "", "ports must be 1..65535")
		return
	}
	if nodeID == 0 || form.BackendIP == "" {
		redirectWithFlash(w, r, "/admin/streams", "", "node and backend IP are required")
		return
	}
	if ip := net.ParseIP(form.BackendIP); ip == nil {
		redirectWithFlash(w, r, "/admin/streams", "", "backend IP is not a valid address")
		return
	} else if security.IsDangerousProxyBackend(ip) {
		// SSRF: block loopback/link-local/metadata backends (RFC1918 stays allowed).
		redirectWithFlash(w, r, "/admin/streams", "", "backend address is not allowed")
		return
	}
	// Block listen ports that would clash with Caddy's HTTPS listeners on
	// the panel itself.
	if listenPort == 80 || listenPort == 443 || listenPort == 2019 {
		redirectWithFlash(w, r, "/admin/streams", "", "listen_port "+itoa64(int64(listenPort))+" is reserved (HTTP/HTTPS/admin)")
		return
	}

	cidrAllow, err := parseCIDRList(form.CIDRAllow)
	if err != nil {
		redirectWithFlash(w, r, "/admin/streams", "", "cidr_allow: invalid CIDR")
		return
	}
	cidrDeny, err := parseCIDRList(form.CIDRDeny)
	if err != nil {
		redirectWithFlash(w, r, "/admin/streams", "", "cidr_deny: invalid CIDR")
		return
	}
	matchValues := parseCSVList(form.MatchValues)
	// sni/http_host matchers with no values produce null JSON (Caddy rejects them).
	if form.MatchMode != "any" && len(matchValues) == 0 {
		redirectWithFlash(w, r, "/admin/streams", "", "match_values required when match_mode is "+form.MatchMode)
		return
	}
	extraUpstreams, badAddr := parseUpstreamsRaw(form.UpstreamsRaw)
	if badAddr != "" {
		redirectWithFlash(w, r, "/admin/streams", "", "invalid upstream address: "+badAddr)
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()

	// Streams bind a port on a shared node under the caller's own client - a
	// client-scoped admin has no such surface and must not create one.
	if _, ok := h.selfProvisionScope(ctx, sess); !ok {
		redirectWithFlash(w, r, "/admin/streams", "", "forbidden: your account is scoped to assigned clients")
		return
	}

	// Infra deny list is independent of the permissive RFC1918 policy: a node's
	// own WG/private address hosts an unauthenticated Caddy admin API.
	infra, infraErr := streamguard.LoadInfraTargets(ctx, db)
	if infraErr != nil {
		h.Logger.Warn("stream create: infra deny list unavailable", "err", infraErr)
		redirectWithFlash(w, r, "/admin/streams", "", "backend screening unavailable, try again")
		return
	}
	if err := infra.ScreenTarget(upstreamPort, form.BackendIP); err != nil {
		redirectWithFlash(w, r, "/admin/streams", "", "backend "+err.Error())
		return
	}
	screened, err := screenStreamUpstreamsWith(ctx, infra, h.Logger, extraUpstreams)
	if err != nil {
		redirectWithFlash(w, r, "/admin/streams", "", err.Error())
		return
	}
	extraUpstreams = screened

	var nodeGroupID int64
	if err := db.QueryRowContext(ctx,
		"SELECT node_group_id FROM caddy_nodes WHERE id = ? AND approved_at IS NOT NULL AND is_enabled = 1",
		nodeID).Scan(&nodeGroupID); err != nil {
		redirectWithFlash(w, r, "/admin/streams", "", "node not found or not approved")
		return
	}
	clientID, err := ensureAdminClient(ctx, db, sess.UserID, sess.ResellerID)
	if err != nil {
		redirectWithFlash(w, r, "/admin/streams", "", "could not provision admin client")
		return
	}
	planID, err := ensureAdminPlan(ctx, db, nodeGroupID)
	if err != nil {
		redirectWithFlash(w, r, "/admin/streams", "", "could not provision admin plan")
		return
	}
	serviceID, err := ensureAdminService(ctx, db, clientID, form.BackendIP, planID, nodeGroupID)
	if err != nil {
		redirectWithFlash(w, r, "/admin/streams", "", "could not provision admin service")
		return
	}

	var tagVal sql.NullString
	if form.Tag != "" {
		if len(form.Tag) > 64 {
			form.Tag = form.Tag[:64]
		}
		tagVal = sql.NullString{String: form.Tag, Valid: true}
	}
	res, err := db.ExecContext(ctx,
		`INSERT INTO stream_routes
		   (service_id, caddy_node_id, protocol, listen_port, upstream_port, status, tag,
		    match_mode, match_values, lb_policy, proxy_proto_in, proxy_proto_out,
		    cidr_allow, cidr_deny)
		 VALUES (?, ?, ?, ?, ?, 'active', ?,
		         ?, ?, ?, ?, ?,
		         ?, ?)`,
		serviceID, nodeID, form.Protocol, listenPort, upstreamPort, tagVal,
		form.MatchMode, joinCSV(matchValues), form.LBPolicy, form.ProxyProtoIn, form.ProxyProtoOut,
		joinCSV(cidrAllow), joinCSV(cidrDeny))
	if err != nil {
		if strings.Contains(err.Error(), "Duplicate entry") {
			redirectWithFlash(w, r, "/admin/streams", "", fmt.Sprintf("port %d/%s already mapped on this node", listenPort, form.Protocol))
			return
		}
		h.Logger.Warn("stream insert", "err", err)
		redirectWithFlash(w, r, "/admin/streams", "", "create failed: "+sanitizeErr(err))
		return
	}
	streamID, _ := res.LastInsertId()

	// Insert additional upstreams when provided.
	if err := insertStreamUpstreams(ctx, db, streamID, extraUpstreams); err != nil {
		h.Logger.Warn("stream_upstreams insert", "err", err)
	}

	go func() {
		defer recoverBg(h.Logger, "resync")
		ctx2, cancel2 := context.WithTimeout(h.Routes.BackgroundCtx(), 30*time.Second)
		defer cancel2()
		_ = h.Routes.Resync(ctx2, nodeID)
	}()

	audit.Write(ctx, db, h.Logger, r, audit.Entry{
		UserID: actorUserID(sess), Action: "admin.stream.create", Entity: "stream_route",
		EntityID: itoa64(streamID),
		Meta: map[string]any{
			"protocol": form.Protocol, "listen_port": listenPort,
			"upstream_port": upstreamPort, "backend_ip": form.BackendIP, "node_id": nodeID,
			"match_mode": form.MatchMode, "lb_policy": form.LBPolicy,
		},
	})
	redirectWithFlash(w, r, "/admin/streams", fmt.Sprintf("Stream %s :%d → %s:%d created", form.Protocol, listenPort, form.BackendIP, upstreamPort), "")
}

// StreamsEdit renders GET /admin/streams/{id}/edit.
func (h *AdminHandlers) StreamsEdit(w http.ResponseWriter, r *http.Request) {
	db := h.DB()
	if db == nil {
		http.Error(w, "no db", http.StatusServiceUnavailable)
		return
	}
	id, _ := strconv.ParseInt(chiURLParamHosts(r, "id"), 10, 64)
	if id == 0 {
		http.Redirect(w, r, "/admin/streams", http.StatusSeeOther)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 3*time.Second)
	defer cancel()
	if !h.scopeCheckStream(ctx, middleware.SessionFromContext(r.Context()), id) {
		redirectWithFlash(w, r, "/admin/streams", "", "stream not found")
		return
	}

	d := streamEditData{baseAdminData: h.base(r, "Edit stream")}
	if err := db.QueryRowContext(ctx,
		`SELECT sr.id, sr.protocol, sr.listen_port, sr.upstream_port,
		        COALESCE(NULLIF(sr.backend_ip_override,''), sv.backend_ip), n.name, n.public_hostname,
		        CASE WHEN sr.quarantined_at IS NOT NULL THEN 'quarantined' ELSE sr.status END,
		        COALESCE(sr.quarantine_reason,''),
		        COALESCE(sr.tag,''),
		        DATE_FORMAT(sr.created_at, '%Y-%m-%d %H:%i'),
		        COALESCE(sr.match_mode,'any'),
		        COALESCE(sr.match_values,''),
		        COALESCE(sr.lb_policy,'round_robin'),
		        COALESCE(sr.proxy_proto_in,'none'),
		        COALESCE(sr.proxy_proto_out,'none')
		 FROM stream_routes sr
		 JOIN services sv ON sv.id = sr.service_id
		 JOIN caddy_nodes n ON n.id = sr.caddy_node_id
		 WHERE sr.id = ?`, id).Scan(
		&d.Stream.ID, &d.Stream.Protocol, &d.Stream.ListenPort, &d.Stream.UpstreamPort,
		&d.Stream.BackendIP, &d.Stream.NodeName, &d.Stream.NodeHostname, &d.Stream.Status,
		&d.Stream.QuarantineReason, &d.Stream.Tag, &d.Stream.CreatedAt,
		&d.Stream.MatchMode, &d.Stream.MatchValues, &d.Stream.LBPolicy, &d.Stream.ProxyProtoIn, &d.Stream.ProxyProtoOut,
	); err != nil {
		redirectWithFlash(w, r, "/admin/streams", "", "stream not found")
		return
	}
	// Load additional upstreams.
	urows, err := db.QueryContext(ctx,
		`SELECT id, address, weight FROM stream_upstreams WHERE stream_route_id = ?
		 ORDER BY sort_order ASC, id ASC`, id)
	if err == nil {
		defer urows.Close()
		for urows.Next() {
			var u streamUpstreamRow
			if err := urows.Scan(&u.ID, &u.Address, &u.Weight); err == nil {
				d.Upstreams = append(d.Upstreams, u)
			}
		}
	}
	d.Nodes = h.loadNodeOptions(ctx)
	h.render(w, "streams_edit", d)
}

// StreamsUpdate handles POST /admin/streams/{id}/edit.
func (h *AdminHandlers) StreamsUpdate(w http.ResponseWriter, r *http.Request) {
	db := h.DB()
	if db == nil {
		http.Error(w, "no db", http.StatusServiceUnavailable)
		return
	}
	if h.Routes == nil || !h.Routes.Layer4ModuleAvailable {
		redirectWithFlash(w, r, "/admin/streams", "", "L4 module not enabled")
		return
	}
	sess := middleware.SessionFromContext(r.Context())
	if sess == nil {
		http.Error(w, "no session", http.StatusUnauthorized)
		return
	}
	id, _ := strconv.ParseInt(chiURLParamHosts(r, "id"), 10, 64)
	if id == 0 {
		http.Redirect(w, r, "/admin/streams", http.StatusSeeOther)
		return
	}
	if !h.scopeCheckStream(r.Context(), sess, id) {
		redirectWithFlash(w, r, "/admin/streams", "", "stream not found")
		return
	}
	_ = r.ParseForm()

	matchMode := strings.TrimSpace(r.FormValue("match_mode"))
	if !validMatchMode(matchMode) {
		matchMode = "any"
	}
	lbPolicy := strings.TrimSpace(r.FormValue("lb_policy"))
	if !validLBPolicy(lbPolicy) {
		lbPolicy = "round_robin"
	}
	ppIn := strings.TrimSpace(r.FormValue("proxy_proto_in"))
	if !validProxyProto(ppIn) {
		ppIn = "none"
	}
	ppOut := strings.TrimSpace(r.FormValue("proxy_proto_out"))
	if !validProxyProto(ppOut) {
		ppOut = "none"
	}

	cidrAllow, err := parseCIDRList(r.FormValue("cidr_allow"))
	if err != nil {
		redirectWithFlash(w, r, "/admin/streams/"+itoa64(id)+"/edit", "", "cidr_allow: invalid CIDR")
		return
	}
	cidrDeny, err := parseCIDRList(r.FormValue("cidr_deny"))
	if err != nil {
		redirectWithFlash(w, r, "/admin/streams/"+itoa64(id)+"/edit", "", "cidr_deny: invalid CIDR")
		return
	}
	matchValues := parseCSVList(r.FormValue("match_values"))
	// sni/http_host matchers with no values produce null JSON (Caddy rejects them).
	if matchMode != "any" && len(matchValues) == 0 {
		redirectWithFlash(w, r, "/admin/streams/"+itoa64(id)+"/edit", "", "match_values required when match_mode is "+matchMode)
		return
	}
	extraUpstreams, badAddr := parseUpstreamsRaw(strings.TrimSpace(r.FormValue("upstreams_raw")))
	if badAddr != "" {
		redirectWithFlash(w, r, "/admin/streams/"+itoa64(id)+"/edit", "", "invalid upstream address: "+badAddr)
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()

	cur, err := loadStreamDestination(ctx, db, id)
	if err != nil {
		redirectWithFlash(w, r, "/admin/streams", "", "stream not found")
		return
	}
	// Destination fields are optional in the form: absent means "keep as stored".
	dest := cur.dest
	if v := strings.TrimSpace(r.FormValue("backend_ip")); v != "" {
		dest.BackendIP = v
	}
	if v := strings.TrimSpace(r.FormValue("upstream_port")); v != "" {
		p, convErr := strconv.Atoi(v)
		if convErr != nil {
			redirectWithFlash(w, r, "/admin/streams/"+itoa64(id)+"/edit", "", "upstream port must be a number")
			return
		}
		dest.UpstreamPort = p
	}
	dest.Upstreams = extraUpstreams

	upd := streamUpdate{
		MatchMode: matchMode, MatchValues: joinCSV(matchValues), LBPolicy: lbPolicy,
		ProxyProtoIn: ppIn, ProxyProtoOut: ppOut,
		CIDRAllow: joinCSV(cidrAllow), CIDRDeny: joinCSV(cidrDeny),
		Dest: dest, ServiceBackendIP: cur.serviceBackendIP,
	}
	// Screening runs inside the save, so a quarantine can only lift together
	// with a destination that actually passes it.
	if err := saveStreamUpdate(ctx, db, h.Logger, id, upd); err != nil {
		redirectWithFlash(w, r, "/admin/streams/"+itoa64(id)+"/edit", "", err.Error())
		return
	}
	nodeID := cur.nodeID

	go func() {
		defer recoverBg(h.Logger, "resync")
		ctx2, cancel2 := context.WithTimeout(h.Routes.BackgroundCtx(), 30*time.Second)
		defer cancel2()
		_ = h.Routes.Resync(ctx2, nodeID)
	}()

	audit.Write(ctx, db, h.Logger, r, audit.Entry{
		UserID: actorUserID(sess), Action: "admin.stream.update", Entity: "stream_route",
		EntityID: itoa64(id),
		Meta: map[string]any{
			"match_mode": matchMode, "lb_policy": lbPolicy,
			"proxy_proto_in": ppIn, "proxy_proto_out": ppOut,
			"backend_ip": dest.BackendIP, "upstream_port": dest.UpstreamPort,
			"quarantine_cleared": cur.quarantined,
		},
	})
	msg := "Stream updated"
	if cur.quarantined {
		msg = "Stream updated - destination passed screening, quarantine cleared"
	}
	redirectWithFlash(w, r, "/admin/streams", msg, "")
}

// StreamsRecheck handles POST /admin/streams/{id}/recheck: re-runs the real
// destination screen so a stream parked against infrastructure that no longer
// exists (decommissioned node) can return to service without being recreated.
func (h *AdminHandlers) StreamsRecheck(w http.ResponseWriter, r *http.Request) {
	db := h.DB()
	if db == nil {
		http.Error(w, "no db", http.StatusServiceUnavailable)
		return
	}
	id, _ := strconv.ParseInt(chiURLParamHosts(r, "id"), 10, 64)
	if id == 0 {
		http.Redirect(w, r, "/admin/streams", http.StatusSeeOther)
		return
	}
	sess := middleware.SessionFromContext(r.Context())
	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()
	if !h.scopeCheckStream(ctx, sess, id) {
		redirectWithFlash(w, r, "/admin/streams", "", "stream not found")
		return
	}
	cur, err := loadStreamDestination(ctx, db, id)
	if err != nil {
		redirectWithFlash(w, r, "/admin/streams", "", "stream not found")
		return
	}
	cleared, reason, err := recheckStreamQuarantine(ctx, db, h.Logger, id)
	if err != nil {
		redirectWithFlash(w, r, "/admin/streams/"+itoa64(id)+"/edit", "", err.Error())
		return
	}
	audit.Write(ctx, db, h.Logger, r, audit.Entry{
		UserID: actorUserID(sess), Action: "admin.stream.recheck", Entity: "stream_route",
		EntityID: itoa64(id),
		Meta:     map[string]any{"cleared": cleared, "reason": reason},
	})
	if !cleared {
		redirectWithFlash(w, r, "/admin/streams/"+itoa64(id)+"/edit", "", "Still quarantined: "+reason)
		return
	}
	if h.Routes != nil {
		go func() {
			defer recoverBg(h.Logger, "resync")
			ctx2, cancel2 := context.WithTimeout(h.Routes.BackgroundCtx(), 30*time.Second)
			defer cancel2()
			_ = h.Routes.Resync(ctx2, cur.nodeID)
		}()
	}
	redirectWithFlash(w, r, "/admin/streams", "Destination passed screening - quarantine cleared", "")
}

// StreamsDelete handles POST /admin/streams/{id}/delete.
func (h *AdminHandlers) StreamsDelete(w http.ResponseWriter, r *http.Request) {
	db := h.DB()
	if db == nil {
		http.Error(w, "no db", http.StatusServiceUnavailable)
		return
	}
	id, _ := strconv.ParseInt(chiURLParamHosts(r, "id"), 10, 64)
	if id == 0 {
		http.Redirect(w, r, "/admin/streams", http.StatusSeeOther)
		return
	}
	sess := middleware.SessionFromContext(r.Context())
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()
	if !h.scopeCheckStream(ctx, sess, id) {
		redirectWithFlash(w, r, "/admin/streams", "", "stream not found")
		return
	}
	var nodeID int64
	if err := db.QueryRowContext(ctx, "SELECT caddy_node_id FROM stream_routes WHERE id = ?", id).Scan(&nodeID); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			redirectWithFlash(w, r, "/admin/streams", "", "stream not found")
			return
		}
		redirectWithFlash(w, r, "/admin/streams", "", "lookup failed")
		return
	}
	if _, err := db.ExecContext(ctx, "DELETE FROM stream_routes WHERE id = ?", id); err != nil {
		redirectWithFlash(w, r, "/admin/streams", "", "delete failed: "+sanitizeErr(err))
		return
	}
	go func() {
		defer recoverBg(h.Logger, "resync")
		ctx2, cancel2 := context.WithTimeout(h.Routes.BackgroundCtx(), 30*time.Second)
		defer cancel2()
		_ = h.Routes.Resync(ctx2, nodeID)
	}()
	audit.Write(ctx, db, h.Logger, r, audit.Entry{
		UserID: actorUserID(sess), Action: "admin.stream.delete", Entity: "stream_route",
		EntityID: itoa64(id),
	})
	redirectWithFlash(w, r, "/admin/streams", "Stream deleted", "")
}

// ---- internal helpers ----

// upstreamEntry represents one parsed upstream address + weight.
type upstreamEntry struct {
	Address string
	Weight  int
}

// streamDestination is everything one stream dials: the primary backend plus
// any extra upstreams. Screening treats it as a unit.
type streamDestination struct {
	BackendIP    string
	UpstreamPort int
	Upstreams    []upstreamEntry
}

// streamUpdate carries every column the edit path writes.
type streamUpdate struct {
	MatchMode     string
	MatchValues   string
	LBPolicy      string
	ProxyProtoIn  string
	ProxyProtoOut string
	CIDRAllow     string
	CIDRDeny      string
	Dest          streamDestination
	// ServiceBackendIP is services.backend_ip; the per-stream override is only
	// stored when the destination differs, so shared services stay untouched.
	ServiceBackendIP string
}

// streamCurrent is the stored state the edit and re-check paths start from.
type streamCurrent struct {
	nodeID           int64
	serviceBackendIP string
	quarantined      bool
	reason           string
	dest             streamDestination
}

// loadInfraOrFail builds the deny set, turning a lookup failure into a
// user-facing error: screening must fail closed, never be skipped.
func loadInfraOrFail(ctx context.Context, db *sql.DB, logger *slog.Logger) (*streamguard.InfraTargets, error) {
	infra, err := streamguard.LoadInfraTargets(ctx, db)
	if err != nil {
		if logger != nil {
			logger.Warn("stream screen: infra deny list unavailable", "err", err)
		}
		return nil, errors.New("destination screening unavailable, try again")
	}
	return infra, nil
}

// screenStreamDestination is the single write-path policy for a whole stream
// destination. Nothing may clear a quarantine without this returning nil.
func screenStreamDestination(ctx context.Context, infra *streamguard.InfraTargets, logger *slog.Logger, d streamDestination) ([]upstreamEntry, error) {
	if d.UpstreamPort <= 0 || d.UpstreamPort > 65535 {
		return nil, fmt.Errorf("upstream port %d is out of range", d.UpstreamPort)
	}
	ip := net.ParseIP(d.BackendIP)
	if ip == nil {
		return nil, fmt.Errorf("backend %q is not a valid IP address", d.BackendIP)
	}
	if security.IsDangerousProxyBackend(ip) {
		return nil, errors.New("backend address is not allowed")
	}
	if err := infra.ScreenTarget(d.UpstreamPort, d.BackendIP); err != nil {
		return nil, fmt.Errorf("backend %v", err)
	}
	return screenStreamUpstreamsWith(ctx, infra, logger, d.Upstreams)
}

// loadStreamDestination reads the stored destination plus quarantine state.
func loadStreamDestination(ctx context.Context, db *sql.DB, id int64) (streamCurrent, error) {
	var c streamCurrent
	var override string
	var quarantined int
	err := db.QueryRowContext(ctx,
		`SELECT sr.caddy_node_id, sr.upstream_port, sv.backend_ip,
		        COALESCE(sr.backend_ip_override,''),
		        CASE WHEN sr.quarantined_at IS NOT NULL THEN 1 ELSE 0 END,
		        COALESCE(sr.quarantine_reason,'')
		   FROM stream_routes sr JOIN services sv ON sv.id = sr.service_id
		  WHERE sr.id = ?`, id).Scan(
		&c.nodeID, &c.dest.UpstreamPort, &c.serviceBackendIP, &override, &quarantined, &c.reason)
	if err != nil {
		return c, err
	}
	c.quarantined = quarantined != 0
	c.dest.BackendIP = c.serviceBackendIP
	if override != "" {
		c.dest.BackendIP = override
	}
	rows, err := db.QueryContext(ctx,
		`SELECT address, weight FROM stream_upstreams WHERE stream_route_id = ?
		 ORDER BY sort_order ASC, id ASC`, id)
	if err != nil {
		return c, err
	}
	defer rows.Close()
	for rows.Next() {
		var u upstreamEntry
		if err := rows.Scan(&u.Address, &u.Weight); err == nil {
			c.dest.Upstreams = append(c.dest.Upstreams, u)
		}
	}
	return c, rows.Err()
}

// saveStreamUpdate screens the destination and writes the whole edit in one
// transaction. The quarantine columns clear only here, so an operator (or a
// tenant) cannot release a stream without a destination that passes screening.
func saveStreamUpdate(ctx context.Context, db *sql.DB, logger *slog.Logger, id int64, u streamUpdate) error {
	infra, err := loadInfraOrFail(ctx, db, logger)
	if err != nil {
		return err
	}
	upstreams, err := screenStreamDestination(ctx, infra, logger, u.Dest)
	if err != nil {
		return err
	}
	override := u.Dest.BackendIP
	if override == u.ServiceBackendIP {
		override = ""
	}
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin tx: %s", sanitizeErr(err))
	}
	defer func() { _ = tx.Rollback() }()
	if _, err := tx.ExecContext(ctx,
		`UPDATE stream_routes
		 SET match_mode=?, match_values=?, lb_policy=?,
		     proxy_proto_in=?, proxy_proto_out=?,
		     cidr_allow=?, cidr_deny=?,
		     backend_ip_override=?, upstream_port=?,
		     quarantined_at=NULL, quarantine_reason=NULL,
		     updated_at=`+store.Now()+`
		 WHERE id=?`,
		u.MatchMode, u.MatchValues, u.LBPolicy,
		u.ProxyProtoIn, u.ProxyProtoOut,
		u.CIDRAllow, u.CIDRDeny,
		override, u.Dest.UpstreamPort, id); err != nil {
		return fmt.Errorf("update failed: %s", sanitizeErr(err))
	}
	if _, err := tx.ExecContext(ctx, "DELETE FROM stream_upstreams WHERE stream_route_id = ?", id); err != nil {
		return fmt.Errorf("upstream delete: %s", sanitizeErr(err))
	}
	if err := insertStreamUpstreams(ctx, tx, id, upstreams); err != nil {
		return fmt.Errorf("upstream insert: %s", sanitizeErr(err))
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit: %s", sanitizeErr(err))
	}
	return nil
}

// recheckStreamQuarantine re-runs the real screen over the stored destination.
// It never just drops the flag: a still-unsafe row keeps it and gets a fresh
// reason so the panel explains what is wrong now.
func recheckStreamQuarantine(ctx context.Context, db *sql.DB, logger *slog.Logger, id int64) (bool, string, error) {
	cur, err := loadStreamDestination(ctx, db, id)
	if err != nil {
		return false, "", errors.New("stream not found")
	}
	infra, err := loadInfraOrFail(ctx, db, logger)
	if err != nil {
		return false, "", err
	}
	if _, screenErr := screenStreamDestination(ctx, infra, logger, cur.dest); screenErr != nil {
		reason := screenErr.Error()
		if len(reason) > 255 {
			reason = reason[:255]
		}
		if _, err := db.ExecContext(ctx,
			`UPDATE stream_routes SET quarantined_at = COALESCE(quarantined_at, `+store.Now()+`),
			        quarantine_reason = ? WHERE id = ?`, reason, id); err != nil {
			return false, reason, fmt.Errorf("recheck failed: %s", sanitizeErr(err))
		}
		return false, reason, nil
	}
	if _, err := db.ExecContext(ctx,
		"UPDATE stream_routes SET quarantined_at = NULL, quarantine_reason = NULL WHERE id = ?", id); err != nil {
		return false, "", fmt.Errorf("recheck failed: %s", sanitizeErr(err))
	}
	return true, "", nil
}

// screenStreamUpstreamsWith screens against an already-built deny set and
// returns the upstreams with hostnames pinned to a validated literal address.
func screenStreamUpstreamsWith(ctx context.Context, infra *streamguard.InfraTargets, logger *slog.Logger, upstreams []upstreamEntry) ([]upstreamEntry, error) {
	out := make([]upstreamEntry, 0, len(upstreams))
	for _, u := range upstreams {
		pinned, err := infra.ScreenAndPinAddress(ctx, u.Address)
		if err != nil {
			logger.Warn("stream upstream screen failed", "addr", u.Address, "err", err)
			return nil, fmt.Errorf("upstream %s: %v", u.Address, err)
		}
		u.Address = pinned
		out = append(out, u)
	}
	return out, nil
}

// parseUpstreamsRaw parses the multi-upstream textarea: each non-empty line is
// "host:port" or "host:port weight". Lines with invalid weight default to 1.
// Returns (entries, "") on success or (nil, badLine) on the first invalid address.
func parseUpstreamsRaw(raw string) ([]upstreamEntry, string) {
	if raw == "" {
		return nil, ""
	}
	lines := strings.Split(raw, "\n")
	out := make([]upstreamEntry, 0, len(lines))
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		// Optional trailing weight field after whitespace.
		var addr string
		weight := 1
		if i := strings.LastIndexAny(line, " \t"); i >= 0 {
			addr = strings.TrimSpace(line[:i])
			w, err := strconv.Atoi(strings.TrimSpace(line[i+1:]))
			if err == nil && w > 0 {
				weight = w
			} else {
				// If the part after whitespace is not a number treat whole line as addr.
				addr = line
			}
		} else {
			addr = line
		}
		if addr == "" {
			continue
		}
		// Validate host:port so malformed dial addresses never reach the Caddy builder.
		host, port, splitErr := net.SplitHostPort(addr)
		if splitErr != nil || host == "" || port == "" {
			return nil, addr
		}
		if _, err := strconv.Atoi(port); err != nil {
			return nil, addr
		}
		out = append(out, upstreamEntry{Address: addr, Weight: weight})
	}
	return out, ""
}

// insertStreamUpstreams bulk-inserts upstream entries for a stream route.
func insertStreamUpstreams(ctx context.Context, db interface {
	ExecContext(ctx context.Context, query string, args ...any) (sql.Result, error)
}, streamID int64, entries []upstreamEntry) error {
	for i, e := range entries {
		if _, err := db.ExecContext(ctx,
			`INSERT INTO stream_upstreams (stream_route_id, address, weight, sort_order)
			 VALUES (?, ?, ?, ?)`,
			streamID, e.Address, e.Weight, i); err != nil {
			return err
		}
	}
	return nil
}
