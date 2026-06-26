package handlers

import (
	"context"
	"database/sql"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/host-yt/caddy-proxy-manager/internal/httpserver/middleware"
)

// mapStaleAfter mirrors wgStaleAfter from admin_tunnels for map health badges.
const mapStaleAfter = 180 * time.Second

const (
	adminMapClientLimit  = 40
	adminMapServiceLimit = 160
	adminMapRouteLimit   = 400
	adminMapNodeLimit    = 80
	adminMapTunnelLimit  = 300
)

type adminMapData struct {
	baseAdminData
	Counts        adminMapCounts
	Clients       []*adminMapClient
	Nodes         []*adminMapNode
	ScopeLimited  bool
	DBUnavailable bool
	Limits        adminMapLimits
}

type adminMapLimits struct {
	Clients  int
	Services int
	Routes   int
	Nodes    int
	Tunnels  int
}

type adminMapCounts struct {
	Clients       int
	Services      int
	Routes        int
	ActiveRoutes  int
	Nodes         int
	HealthyNodes  int
	Tunnels       int
	ActiveTunnels int
}

type adminMapClient struct {
	ID           int64
	Name         string
	Email        string
	ServiceCount int
	RouteCount   int
	TunnelCount  int
	Services     []*adminMapService
	Tunnels      []*adminMapTunnel
}

type adminMapService struct {
	ID        int64
	ClientID  int64
	Name      string
	BackendIP string
	PortStart int
	PortEnd   int
	Status    string
	Routes    []*adminMapRoute
}

type adminMapRoute struct {
	ID           int64
	ServiceID    int64
	Domain       string
	PathPrefix   string
	UpstreamPort int
	Status       string
	NodeID       int64
	NodeName     string
	NodeHealth   string
	NodeEnabled  bool
	WGPeerID     int64
	WGPeerName   string
	WGPeerStatus string
	WGPeerIP     string
}

type adminMapNode struct {
	ID             int64
	Name           string
	PublicHostname string
	PublicIP       string
	WGIP           string
	HealthStatus   string
	Enabled        bool
	TunnelEnabled  bool
	TunnelEndpoint string
	TunnelSubnet   string
	TunnelMTU      sql.NullInt32 // fwd_mtu: live probed MTU; NULL when never measured
	CurrentRoutes  int
	MaxRoutes      int
	RoutesShown    int
	TunnelsShown   int
	Tunnels        []*adminMapTunnel
}

type adminMapTunnel struct {
	ID              int64
	ClientID        int64
	NodeID          int64
	NodeName        string
	Name            string
	AssignedIP      string
	Status          string
	LastHandshake   string
	PeerGroupID     string
	Healthy         bool   // true when last handshake is within mapStaleAfter
	KeyAgeHuman     string // "3d ago" or "never rotated"
	LastHandshakeAt string // formatted date string for display
}

// AdminMap renders the read-only admin infrastructure topology page.
func (h *AdminHandlers) AdminMap(w http.ResponseWriter, r *http.Request) {
	d := adminMapData{
		baseAdminData: h.base(r, "Infrastructure map"),
		Limits: adminMapLimits{
			Clients:  adminMapClientLimit,
			Services: adminMapServiceLimit,
			Routes:   adminMapRouteLimit,
			Nodes:    adminMapNodeLimit,
			Tunnels:  adminMapTunnelLimit,
		},
	}
	d.PageDesc = "Client, service, host, node, and WireGuard tunnel topology."

	var db *sql.DB
	if h.DB != nil {
		db = h.DB()
	}
	if db == nil {
		d.DBUnavailable = true
		h.render(w, "map", d)
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 3*time.Second)
	defer cancel()

	sess := middleware.SessionFromContext(r.Context())
	allowedClients, allClients, scopeOK := h.adminClientScope(ctx, sess)
	if !scopeOK {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	d.ScopeLimited = !allClients
	scopeIDs := adminMapScopeIDs(allowedClients)
	d.Counts = h.loadAdminMapCounts(ctx, db, allClients, scopeIDs)

	if !allClients && len(scopeIDs) == 0 {
		h.render(w, "map", d)
		return
	}

	clientByID := map[int64]*adminMapClient{}
	for _, c := range h.loadAdminMapClients(ctx, db, allClients, scopeIDs) {
		d.Clients = append(d.Clients, c)
		clientByID[c.ID] = c
	}

	selectedClientIDs := make([]int64, 0, len(d.Clients))
	for _, c := range d.Clients {
		selectedClientIDs = append(selectedClientIDs, c.ID)
	}

	serviceByID := map[int64]*adminMapService{}
	for _, svc := range h.loadAdminMapServices(ctx, db, selectedClientIDs) {
		if c := clientByID[svc.ClientID]; c != nil {
			c.Services = append(c.Services, svc)
			serviceByID[svc.ID] = svc
		}
	}

	selectedServiceIDs := make([]int64, 0, len(serviceByID))
	for id := range serviceByID {
		selectedServiceIDs = append(selectedServiceIDs, id)
	}
	sort.Slice(selectedServiceIDs, func(i, j int) bool { return selectedServiceIDs[i] > selectedServiceIDs[j] })

	nodeIDs := map[int64]bool{}
	routesShownByNode := map[int64]int{}
	for _, rt := range h.loadAdminMapRoutes(ctx, db, selectedServiceIDs) {
		if svc := serviceByID[rt.ServiceID]; svc != nil {
			svc.Routes = append(svc.Routes, rt)
			nodeIDs[rt.NodeID] = true
			routesShownByNode[rt.NodeID]++
		}
	}

	tunnelsShownByNode := map[int64]int{}
	for _, tunnel := range h.loadAdminMapTunnels(ctx, db, selectedClientIDs) {
		if c := clientByID[tunnel.ClientID]; c != nil {
			c.Tunnels = append(c.Tunnels, tunnel)
			nodeIDs[tunnel.NodeID] = true
			tunnelsShownByNode[tunnel.NodeID]++
		}
	}

	nodeByID := map[int64]*adminMapNode{}
	for _, node := range h.loadAdminMapNodes(ctx, db, allClients, adminMapBoolIDs(nodeIDs)) {
		node.RoutesShown = routesShownByNode[node.ID]
		node.TunnelsShown = tunnelsShownByNode[node.ID]
		d.Nodes = append(d.Nodes, node)
		nodeByID[node.ID] = node
	}
	for _, c := range d.Clients {
		for _, tunnel := range c.Tunnels {
			if node := nodeByID[tunnel.NodeID]; node != nil {
				node.Tunnels = append(node.Tunnels, tunnel)
			}
		}
	}

	h.render(w, "map", d)
}

func (h *AdminHandlers) loadAdminMapCounts(ctx context.Context, db *sql.DB, allClients bool, scopeIDs []int64) adminMapCounts {
	var c adminMapCounts
	c.Clients = adminMapCount(ctx, db, "SELECT COUNT(*) FROM clients c WHERE 1=1"+adminMapScopedWhere("c.id", allClients, scopeIDs), adminMapArgs(scopeIDs, !allClients)...)
	c.Services = adminMapCount(ctx, db, "SELECT COUNT(*) FROM services s WHERE 1=1"+adminMapScopedWhere("s.client_id", allClients, scopeIDs), adminMapArgs(scopeIDs, !allClients)...)
	c.Routes = adminMapCount(ctx, db, "SELECT COUNT(*) FROM routes r JOIN services s ON s.id = r.service_id WHERE 1=1"+adminMapScopedWhere("s.client_id", allClients, scopeIDs), adminMapArgs(scopeIDs, !allClients)...)
	c.ActiveRoutes = adminMapCount(ctx, db, "SELECT COUNT(*) FROM routes r JOIN services s ON s.id = r.service_id WHERE r.status='active'"+adminMapScopedWhere("s.client_id", allClients, scopeIDs), adminMapArgs(scopeIDs, !allClients)...)
	c.Nodes = adminMapCount(ctx, db, "SELECT COUNT(*) FROM caddy_nodes")
	c.HealthyNodes = adminMapCount(ctx, db, "SELECT COUNT(*) FROM caddy_nodes WHERE health_status='healthy' AND is_enabled=1 AND approved_at IS NOT NULL")
	c.Tunnels = adminMapCount(ctx, db, "SELECT COUNT(*) FROM customer_wg_peer p WHERE 1=1"+adminMapScopedWhere("p.client_id", allClients, scopeIDs), adminMapArgs(scopeIDs, !allClients)...)
	c.ActiveTunnels = adminMapCount(ctx, db, "SELECT COUNT(*) FROM customer_wg_peer p WHERE p.status='active'"+adminMapScopedWhere("p.client_id", allClients, scopeIDs), adminMapArgs(scopeIDs, !allClients)...)
	return c
}

func (h *AdminHandlers) loadAdminMapClients(ctx context.Context, db *sql.DB, allClients bool, scopeIDs []int64) []*adminMapClient {
	q := `SELECT c.id, COALESCE(NULLIF(c.display_name,''), NULLIF(u.full_name,''), u.email), u.email,
		        (SELECT COUNT(*) FROM services s WHERE s.client_id = c.id),
		        (SELECT COUNT(*) FROM routes r JOIN services s ON s.id = r.service_id WHERE s.client_id = c.id),
		        (SELECT COUNT(*) FROM customer_wg_peer p WHERE p.client_id = c.id AND p.status = 'active')
		 FROM clients c
		 JOIN users u ON u.id = c.user_id
		 WHERE 1=1` + adminMapScopedWhere("c.id", allClients, scopeIDs) + `
		 ORDER BY c.id DESC LIMIT ?`
	args := append(adminMapArgs(scopeIDs, !allClients), adminMapClientLimit)
	rows, err := db.QueryContext(ctx, q, args...)
	if err != nil {
		return nil
	}
	defer rows.Close()
	var out []*adminMapClient
	for rows.Next() {
		var c adminMapClient
		if err := rows.Scan(&c.ID, &c.Name, &c.Email, &c.ServiceCount, &c.RouteCount, &c.TunnelCount); err == nil {
			out = append(out, &c)
		}
	}
	return out
}

func (h *AdminHandlers) loadAdminMapServices(ctx context.Context, db *sql.DB, clientIDs []int64) []*adminMapService {
	if len(clientIDs) == 0 {
		return nil
	}
	q := `SELECT s.id, s.client_id, s.name, s.backend_ip, s.allowed_port_start, s.allowed_port_end, s.status
		 FROM services s
		 WHERE s.client_id IN (` + adminMapPlaceholders(len(clientIDs)) + `)
		 ORDER BY s.id DESC LIMIT ?`
	args := append(adminMapArgs(clientIDs, true), adminMapServiceLimit)
	rows, err := db.QueryContext(ctx, q, args...)
	if err != nil {
		return nil
	}
	defer rows.Close()
	var out []*adminMapService
	for rows.Next() {
		var svc adminMapService
		if err := rows.Scan(&svc.ID, &svc.ClientID, &svc.Name, &svc.BackendIP, &svc.PortStart, &svc.PortEnd, &svc.Status); err == nil {
			out = append(out, &svc)
		}
	}
	return out
}

func (h *AdminHandlers) loadAdminMapRoutes(ctx context.Context, db *sql.DB, serviceIDs []int64) []*adminMapRoute {
	if len(serviceIDs) == 0 {
		return nil
	}
	q := `SELECT r.id, r.service_id, r.domain, COALESCE(r.path_prefix,''), r.upstream_port, r.status,
		        r.caddy_node_id, n.name, n.health_status, n.is_enabled,
		        COALESCE(r.via_wg_peer_id,0), COALESCE(p.name,''), COALESCE(p.status,''), COALESCE(p.assigned_ip,'')
		 FROM routes r
		 JOIN caddy_nodes n ON n.id = r.caddy_node_id
		 LEFT JOIN customer_wg_peer p ON p.id = r.via_wg_peer_id
		 WHERE r.service_id IN (` + adminMapPlaceholders(len(serviceIDs)) + `)
		 ORDER BY r.id DESC LIMIT ?`
	args := append(adminMapArgs(serviceIDs, true), adminMapRouteLimit)
	rows, err := db.QueryContext(ctx, q, args...)
	if err != nil {
		return nil
	}
	defer rows.Close()
	var out []*adminMapRoute
	for rows.Next() {
		var rt adminMapRoute
		if err := rows.Scan(&rt.ID, &rt.ServiceID, &rt.Domain, &rt.PathPrefix, &rt.UpstreamPort, &rt.Status,
			&rt.NodeID, &rt.NodeName, &rt.NodeHealth, &rt.NodeEnabled, &rt.WGPeerID, &rt.WGPeerName, &rt.WGPeerStatus, &rt.WGPeerIP); err == nil {
			out = append(out, &rt)
		}
	}
	return out
}

func (h *AdminHandlers) loadAdminMapTunnels(ctx context.Context, db *sql.DB, clientIDs []int64) []*adminMapTunnel {
	if len(clientIDs) == 0 {
		return nil
	}
	q := `SELECT p.id, p.client_id, p.node_id, n.name, p.name, p.assigned_ip, p.status,
		        COALESCE(DATE_FORMAT(p.last_handshake_at,'%Y-%m-%d %H:%i'),''),
		        COALESCE(p.peer_group_id,''),
		        COALESCE(p.last_handshake_epoch,0),
		        p.last_rotated_at, p.last_key_rotation_at
		 FROM customer_wg_peer p
		 JOIN caddy_nodes n ON n.id = p.node_id
		 WHERE p.client_id IN (` + adminMapPlaceholders(len(clientIDs)) + `)
		 ORDER BY p.id DESC LIMIT ?`
	args := append(adminMapArgs(clientIDs, true), adminMapTunnelLimit)
	rows, err := db.QueryContext(ctx, q, args...)
	if err != nil {
		return nil
	}
	defer rows.Close()
	var out []*adminMapTunnel
	for rows.Next() {
		var t adminMapTunnel
		var epoch int64
		var lastRotated, lastKeyRotation sql.NullTime
		if err := rows.Scan(&t.ID, &t.ClientID, &t.NodeID, &t.NodeName, &t.Name, &t.AssignedIP, &t.Status,
			&t.LastHandshakeAt, &t.PeerGroupID, &epoch, &lastRotated, &lastKeyRotation); err == nil {
			if t.LastHandshakeAt == "" {
				t.LastHandshakeAt = "no handshake"
			}
			if epoch > 0 {
				t.Healthy = time.Since(time.Unix(epoch, 0)) < mapStaleAfter
			}
			t.KeyAgeHuman = keyAgeHuman(lastRotated, lastKeyRotation)
			t.LastHandshake = t.LastHandshakeAt
			out = append(out, &t)
		}
	}
	return out
}

func (h *AdminHandlers) loadAdminMapNodes(ctx context.Context, db *sql.DB, allClients bool, nodeIDs []int64) []*adminMapNode {
	if !allClients && len(nodeIDs) == 0 {
		return nil
	}
	where := ""
	args := []any{}
	if !allClients {
		where = " WHERE id IN (" + adminMapPlaceholders(len(nodeIDs)) + ")"
		args = adminMapArgs(nodeIDs, true)
	}
	q := `SELECT id, name, COALESCE(public_hostname,''), COALESCE(public_ip,''), COALESCE(wg_ip,''),
		        health_status, is_enabled, COALESCE(tunnel_enabled,0), COALESCE(tunnel_endpoint,''), COALESCE(tunnel_subnet,''),
		        current_routes, max_routes, fwd_mtu
		 FROM caddy_nodes` + where + `
		 ORDER BY is_enabled DESC, FIELD(health_status,'healthy','degraded','unknown','down'), priority DESC, id DESC LIMIT ?`
	args = append(args, adminMapNodeLimit)
	rows, err := db.QueryContext(ctx, q, args...)
	if err != nil {
		return nil
	}
	defer rows.Close()
	var out []*adminMapNode
	for rows.Next() {
		var n adminMapNode
		if err := rows.Scan(&n.ID, &n.Name, &n.PublicHostname, &n.PublicIP, &n.WGIP, &n.HealthStatus, &n.Enabled,
			&n.TunnelEnabled, &n.TunnelEndpoint, &n.TunnelSubnet, &n.CurrentRoutes, &n.MaxRoutes, &n.TunnelMTU); err != nil {
			h.Logger.Warn("map nodes scan", "err", err)
			continue
		}
		out = append(out, &n)
	}
	return out
}

func adminMapScopeIDs(m map[int64]bool) []int64 {
	ids := make([]int64, 0, len(m))
	for id := range m {
		ids = append(ids, id)
	}
	sort.Slice(ids, func(i, j int) bool { return ids[i] < ids[j] })
	return ids
}

func adminMapBoolIDs(m map[int64]bool) []int64 {
	ids := make([]int64, 0, len(m))
	for id := range m {
		ids = append(ids, id)
	}
	sort.Slice(ids, func(i, j int) bool { return ids[i] < ids[j] })
	return ids
}

func adminMapScopedWhere(column string, all bool, ids []int64) string {
	if all {
		return ""
	}
	if len(ids) == 0 {
		return " AND 1=0"
	}
	return " AND " + column + " IN (" + adminMapPlaceholders(len(ids)) + ")"
}

func adminMapArgs(ids []int64, include bool) []any {
	if !include {
		return nil
	}
	args := make([]any, 0, len(ids))
	for _, id := range ids {
		args = append(args, id)
	}
	return args
}

func adminMapPlaceholders(n int) string {
	if n <= 0 {
		return ""
	}
	return strings.TrimRight(strings.Repeat("?,", n), ",")
}

func adminMapCount(ctx context.Context, db *sql.DB, q string, args ...any) int {
	var n int
	_ = db.QueryRowContext(ctx, q, args...).Scan(&n)
	return n
}
