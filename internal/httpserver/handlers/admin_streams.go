package handlers

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/host-yt/caddy-proxy-manager/internal/audit"
	"github.com/host-yt/caddy-proxy-manager/internal/httpserver/middleware"
)

// Streams admin: minimal CRUD on stream_routes (TCP/UDP L4 forwards via
// the caddy-l4 module embedded in the custom Caddy build). Admin-only;
// customers don't get a stream-proxy surface in the client portal MVP.

type streamRow struct {
	ID           int64
	Protocol     string
	ListenPort   int
	UpstreamPort int
	BackendIP    string
	NodeName     string
	NodeHostname string
	Status       string
	Tag          string
	CreatedAt    string
}

type streamsData struct {
	baseAdminData
	Streams         []streamRow
	Nodes           []hostsNewNode
	ModuleAvailable bool
	Form            streamForm
}

type streamForm struct {
	Protocol     string
	ListenPort   string
	UpstreamPort string
	BackendIP    string
	NodeID       string
	Tag          string
}

// StreamsList renders /admin/streams.
func (h *AdminHandlers) StreamsList(w http.ResponseWriter, r *http.Request) {
	d := streamsData{
		baseAdminData:   h.base(r, "Stream proxy (TCP/UDP)"),
		ModuleAvailable: h.Routes != nil && h.Routes.Layer4ModuleAvailable,
		Form:            streamForm{Protocol: "tcp"},
	}
	db := h.DB()
	if db == nil {
		h.render(w, "streams", d)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 3*time.Second)
	defer cancel()

	d.Nodes = h.loadNodeOptions(ctx)
	rows, err := db.QueryContext(ctx,
		`SELECT sr.id, sr.protocol, sr.listen_port, sr.upstream_port,
		        sv.backend_ip, n.name, n.public_hostname, sr.status,
		        COALESCE(sr.tag,''),
		        DATE_FORMAT(sr.created_at, '%Y-%m-%d %H:%i')
		 FROM stream_routes sr
		 JOIN services sv     ON sv.id = sr.service_id
		 JOIN caddy_nodes n   ON n.id = sr.caddy_node_id
		 ORDER BY sr.listen_port ASC, sr.id ASC`)
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
			&s.Tag, &s.CreatedAt); err == nil {
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
		Protocol:     strings.TrimSpace(r.FormValue("protocol")),
		ListenPort:   strings.TrimSpace(r.FormValue("listen_port")),
		UpstreamPort: strings.TrimSpace(r.FormValue("upstream_port")),
		BackendIP:    strings.TrimSpace(r.FormValue("backend_ip")),
		NodeID:       strings.TrimSpace(r.FormValue("node_id")),
		Tag:          strings.TrimSpace(r.FormValue("tag")),
	}
	switch form.Protocol {
	case "tcp", "udp", "both":
	default:
		form.Protocol = "tcp"
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
	if net.ParseIP(form.BackendIP) == nil {
		redirectWithFlash(w, r, "/admin/streams", "", "backend IP is not a valid address")
		return
	}
	// Block listen ports that would clash with Caddy's HTTPS listeners on
	// the panel itself. Operator can still bind 80/443 explicitly via the
	// node config if they truly know what they're doing, but the UI says no.
	if listenPort == 80 || listenPort == 443 || listenPort == 2019 {
		redirectWithFlash(w, r, "/admin/streams", "", "listen_port "+itoa64(int64(listenPort))+" is reserved (HTTP/HTTPS/admin)")
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()

	var nodeGroupID int64
	if err := db.QueryRowContext(ctx,
		"SELECT node_group_id FROM caddy_nodes WHERE id = ? AND approved_at IS NOT NULL AND is_enabled = 1",
		nodeID).Scan(&nodeGroupID); err != nil {
		redirectWithFlash(w, r, "/admin/streams", "", "node not found or not approved")
		return
	}
	clientID, err := ensureAdminClient(ctx, db, sess.UserID)
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
		`INSERT INTO stream_routes (service_id, caddy_node_id, protocol, listen_port, upstream_port, status, tag)
		 VALUES (?, ?, ?, ?, ?, 'active', ?)`,
		serviceID, nodeID, form.Protocol, listenPort, upstreamPort, tagVal)
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

	go func() {
		defer recoverBg(h.Logger, "resync")
		ctx, cancel := context.WithTimeout(h.Routes.BackgroundCtx(), 30*time.Second)
		defer cancel()
		_ = h.Routes.Resync(ctx, nodeID)
	}()

	audit.Write(ctx, db, h.Logger, r, audit.Entry{
		UserID: actorUserID(sess), Action: "admin.stream.create", Entity: "stream_route",
		EntityID: itoa64(streamID),
		Meta: map[string]any{
			"protocol": form.Protocol, "listen_port": listenPort,
			"upstream_port": upstreamPort, "backend_ip": form.BackendIP, "node_id": nodeID,
		},
	})
	redirectWithFlash(w, r, "/admin/streams", fmt.Sprintf("Stream %s :%d → %s:%d created", form.Protocol, listenPort, form.BackendIP, upstreamPort), "")
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
		ctx, cancel := context.WithTimeout(h.Routes.BackgroundCtx(), 30*time.Second)
		defer cancel()
		_ = h.Routes.Resync(ctx, nodeID)
	}()
	audit.Write(ctx, db, h.Logger, r, audit.Entry{
		UserID: actorUserID(sess), Action: "admin.stream.delete", Entity: "stream_route",
		EntityID: itoa64(id),
	})
	redirectWithFlash(w, r, "/admin/streams", "Stream deleted", "")
}
