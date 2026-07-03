package handlers

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
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
	ID            int64
	Protocol      string
	ListenPort    int
	UpstreamPort  int
	BackendIP     string
	NodeName      string
	NodeHostname  string
	Status        string
	Tag           string
	CreatedAt     string
	MatchMode     string
	MatchValues   string // CSV of SNI/host values; preserved on edit to avoid silent data loss
	LBPolicy      string
	ProxyProtoIn  string
	ProxyProtoOut string
}

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
		        sv.backend_ip, n.name, n.public_hostname, sr.status,
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
		d.Error = "query failed"
		h.render(w, "streams", d)
		return
	}
	defer rows.Close()
	for rows.Next() {
		var s streamRow
		if err := rows.Scan(&s.ID, &s.Protocol, &s.ListenPort, &s.UpstreamPort,
			&s.BackendIP, &s.NodeName, &s.NodeHostname, &s.Status,
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

	// SSRF: screen every extra upstream (host:port) - IPs go through the
	// dangerous-backend check, hostnames resolve and each result is screened.
	for _, u := range extraUpstreams {
		host, _, _ := net.SplitHostPort(u.Address)
		if err := screenBackendHost(ctx, host); err != nil {
			h.Logger.Warn("stream upstream screen failed", "addr", u.Address, "err", err)
			redirectWithFlash(w, r, "/admin/streams", "", "upstream "+u.Address+": blocked or unresolvable")
			return
		}
	}

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
		        sv.backend_ip, n.name, n.public_hostname, sr.status,
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
		&d.Stream.Tag, &d.Stream.CreatedAt,
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

	// Confirm the stream exists and get the node ID for resync.
	var nodeID int64
	if err := db.QueryRowContext(ctx, "SELECT caddy_node_id FROM stream_routes WHERE id = ?", id).Scan(&nodeID); err != nil {
		redirectWithFlash(w, r, "/admin/streams", "", "stream not found")
		return
	}

	if _, err := db.ExecContext(ctx,
		`UPDATE stream_routes
		 SET match_mode=?, match_values=?, lb_policy=?,
		     proxy_proto_in=?, proxy_proto_out=?,
		     cidr_allow=?, cidr_deny=?,
		     updated_at=NOW()
		 WHERE id=?`,
		matchMode, joinCSV(matchValues), lbPolicy,
		ppIn, ppOut,
		joinCSV(cidrAllow), joinCSV(cidrDeny),
		id); err != nil {
		redirectWithFlash(w, r, "/admin/streams/"+itoa64(id)+"/edit", "", "update failed: "+sanitizeErr(err))
		return
	}

	// Replace upstreams atomically so a partial failure leaves no orphaned rows.
	tx, txErr := db.BeginTx(ctx, nil)
	if txErr != nil {
		redirectWithFlash(w, r, "/admin/streams/"+itoa64(id)+"/edit", "", "begin tx: "+sanitizeErr(txErr))
		return
	}
	if _, txErr = tx.ExecContext(ctx, "DELETE FROM stream_upstreams WHERE stream_route_id = ?", id); txErr != nil {
		_ = tx.Rollback()
		redirectWithFlash(w, r, "/admin/streams/"+itoa64(id)+"/edit", "", "upstream delete: "+sanitizeErr(txErr))
		return
	}
	if txErr = insertStreamUpstreams(ctx, tx, id, extraUpstreams); txErr != nil {
		_ = tx.Rollback()
		redirectWithFlash(w, r, "/admin/streams/"+itoa64(id)+"/edit", "", "upstream insert: "+sanitizeErr(txErr))
		return
	}
	if txErr = tx.Commit(); txErr != nil {
		redirectWithFlash(w, r, "/admin/streams/"+itoa64(id)+"/edit", "", "commit: "+sanitizeErr(txErr))
		return
	}

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
		},
	})
	redirectWithFlash(w, r, "/admin/streams", "Stream updated", "")
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
