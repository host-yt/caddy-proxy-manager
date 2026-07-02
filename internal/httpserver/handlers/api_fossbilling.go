package handlers

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/host-yt/caddy-proxy-manager/internal/audit"
	"github.com/host-yt/caddy-proxy-manager/internal/auth"
	"github.com/host-yt/caddy-proxy-manager/internal/domain/routes"
	"github.com/host-yt/caddy-proxy-manager/internal/security"
)

// FOSSBillingHandlers handles provisioning calls from a FOSSBilling instance.
// All endpoints sit behind the shared APIKeyAuth + APIQuota middleware.
type FOSSBillingHandlers struct {
	DB     func() *sql.DB
	Routes *routes.Service
}

// ---- helpers ---------------------------------------------------------------

// fbJSON writes a JSON response; shared with apiJSON but avoids cross-file dep.
func fbJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func fbErr(w http.ResponseWriter, status int, msg string) {
	fbJSON(w, status, map[string]string{"error": msg})
}

// randPassword generates a cryptographically random 24-char hex password
// used when FOSSBilling creates a client without specifying one.
func randPassword() string {
	b := make([]byte, 12)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

// ---- Client ----------------------------------------------------------------

// ProvisionClient creates a user + client row for the FOSSBilling customer.
// FOSSBilling sends: email, name, [plan_id], [external_ref].
// A random password is set; the customer uses the panel's forgot-password flow.
func (h *FOSSBillingHandlers) ProvisionClient(w http.ResponseWriter, r *http.Request) {
	if !requireAdmin(r) {
		fbErr(w, http.StatusForbidden, "admin role required")
		return
	}
	var in struct {
		Email       string `json:"email"`
		Name        string `json:"name"`
		PlanID      int64  `json:"plan_id"`
		ExternalRef string `json:"external_ref"`
	}
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		fbErr(w, http.StatusBadRequest, "invalid json")
		return
	}
	in.Email = strings.ToLower(strings.TrimSpace(in.Email))
	in.Name = strings.TrimSpace(in.Name)
	if in.Email == "" || in.Name == "" {
		fbErr(w, http.StatusBadRequest, "email and name required")
		return
	}

	db := h.DB()
	if db == nil {
		fbErr(w, http.StatusServiceUnavailable, "db not ready")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 8*time.Second)
	defer cancel()

	hash, err := auth.HashPassword(randPassword())
	if err != nil {
		fbErr(w, http.StatusInternalServerError, "hash failed")
		return
	}

	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		fbErr(w, http.StatusInternalServerError, "tx failed")
		return
	}
	defer tx.Rollback() //nolint:errcheck

	res, err := tx.ExecContext(ctx,
		"INSERT INTO users (email, password_hash, password_set, role, full_name, is_active) VALUES (?, ?, 1, 'client', ?, 1)",
		in.Email, hash, in.Name)
	if err != nil {
		if strings.Contains(err.Error(), "Duplicate entry") || strings.Contains(err.Error(), "UNIQUE constraint") {
			fbErr(w, http.StatusConflict, "email already exists")
			return
		}
		fbErr(w, http.StatusInternalServerError, "user insert failed")
		return
	}
	userID, _ := res.LastInsertId()

	var extRef sql.NullString
	if in.ExternalRef != "" {
		extRef = sql.NullString{String: in.ExternalRef, Valid: true}
	}
	cres, err := tx.ExecContext(ctx,
		"INSERT INTO clients (user_id, display_name, external_ref) VALUES (?, ?, ?)",
		userID, in.Name, extRef)
	if err != nil {
		fbErr(w, http.StatusInternalServerError, "client insert failed")
		return
	}
	clientID, _ := cres.LastInsertId()

	if err := tx.Commit(); err != nil {
		fbErr(w, http.StatusInternalServerError, "commit failed")
		return
	}

	uid := apiCallerID(r)
	audit.Write(ctx, db, nil, r, audit.Entry{
		UserID: &uid, ActorType: audit.ActorAPI, Action: "fossbilling.client.create",
		Entity: "client", EntityID: strconv.FormatInt(clientID, 10),
		Meta: map[string]any{"email": in.Email, "ext": in.ExternalRef},
	})
	fbJSON(w, http.StatusCreated, map[string]any{"user_id": userID, "client_id": clientID})
}

// ---- Service ---------------------------------------------------------------

// ProvisionService creates a service record and assigns a plan to a client.
// FOSSBilling sends: client_id, name, backend_ip, plan_id, port_start, port_end, [external_ref].
func (h *FOSSBillingHandlers) ProvisionService(w http.ResponseWriter, r *http.Request) {
	if !requireAdmin(r) {
		fbErr(w, http.StatusForbidden, "admin role required")
		return
	}
	var in struct {
		ClientID    int64  `json:"client_id"`
		Name        string `json:"name"`
		BackendIP   string `json:"backend_ip"`
		PlanID      int64  `json:"plan_id"`
		PortStart   int    `json:"port_start"`
		PortEnd     int    `json:"port_end"`
		ExternalRef string `json:"external_ref"`
	}
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		fbErr(w, http.StatusBadRequest, "invalid json")
		return
	}
	if in.ClientID == 0 || in.Name == "" || in.BackendIP == "" || in.PlanID == 0 {
		fbErr(w, http.StatusBadRequest, "client_id, name, backend_ip, plan_id required")
		return
	}
	backendIP := net.ParseIP(in.BackendIP)
	if backendIP == nil {
		fbErr(w, http.StatusBadRequest, "backend_ip invalid")
		return
	}
	// SSRF screen the backend (loopback/link-local/metadata) - twin of
	// CADDY-02 / API-02.
	if security.IsDangerousProxyBackend(backendIP) {
		fbErr(w, http.StatusBadRequest, "backend_ip not allowed (loopback/link-local/metadata)")
		return
	}
	if in.PortStart < 1 || in.PortEnd > 65535 || in.PortStart > in.PortEnd {
		fbErr(w, http.StatusBadRequest, "port range invalid")
		return
	}

	db := h.DB()
	if db == nil {
		fbErr(w, http.StatusServiceUnavailable, "db not ready")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 8*time.Second)
	defer cancel()

	var nodeGroupID int64
	if err := db.QueryRowContext(ctx,
		"SELECT node_group_id FROM plans WHERE id = ?", in.PlanID,
	).Scan(&nodeGroupID); err != nil {
		fbErr(w, http.StatusBadRequest, "plan not found")
		return
	}

	var extRef sql.NullString
	if in.ExternalRef != "" {
		extRef = sql.NullString{String: in.ExternalRef, Valid: true}
	}
	res, err := db.ExecContext(ctx,
		`INSERT INTO services (client_id, name, backend_ip, allowed_port_start, allowed_port_end,
		   plan_id, node_group_id, status, external_reference)
		 VALUES (?, ?, ?, ?, ?, ?, ?, 'active', ?)`,
		in.ClientID, in.Name, in.BackendIP, in.PortStart, in.PortEnd,
		in.PlanID, nodeGroupID, extRef)
	if err != nil {
		fbErr(w, http.StatusInternalServerError, "service insert failed")
		return
	}
	svcID, _ := res.LastInsertId()

	uid := apiCallerID(r)
	audit.Write(ctx, db, nil, r, audit.Entry{
		UserID: &uid, ActorType: audit.ActorAPI, Action: "fossbilling.service.create",
		Entity: "service", EntityID: strconv.FormatInt(svcID, 10),
		Meta: map[string]any{"name": in.Name, "client_id": in.ClientID, "ext": in.ExternalRef},
	})
	fbJSON(w, http.StatusCreated, map[string]any{"service_id": svcID})
}

// ---- Route -----------------------------------------------------------------

// ProvisionRoute creates a proxy route for a service.
// FOSSBilling sends: service_id, domain, upstream_port, [path_prefix, ssl, websocket, force_https].
func (h *FOSSBillingHandlers) ProvisionRoute(w http.ResponseWriter, r *http.Request) {
	if !requireAdmin(r) {
		fbErr(w, http.StatusForbidden, "admin role required")
		return
	}
	var in struct {
		ServiceID    int64  `json:"service_id"`
		Domain       string `json:"domain"`
		UpstreamPort int    `json:"upstream_port"`
		PathPrefix   string `json:"path_prefix"`
		SSL          bool   `json:"ssl"`
		WebSocket    bool   `json:"websocket"`
		ForceHTTPS   bool   `json:"force_https"`
	}
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		fbErr(w, http.StatusBadRequest, "invalid json")
		return
	}
	if in.ServiceID == 0 || in.Domain == "" || in.UpstreamPort == 0 {
		fbErr(w, http.StatusBadRequest, "service_id, domain, upstream_port required")
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()

	// clientID=0 skips ownership check (admin/api scope).
	id, err := h.Routes.Create(ctx, 0, routes.CreateInput{
		ServiceID:    in.ServiceID,
		UpstreamPort: in.UpstreamPort,
		Domain:       in.Domain,
		PathPrefix:   in.PathPrefix,
		SSL:          in.SSL,
		WebSocket:    in.WebSocket,
		ForceHTTPS:   in.ForceHTTPS,
	})
	if err != nil {
		switch {
		case errors.Is(err, routes.ErrPortOutOfRange):
			fbErr(w, http.StatusBadRequest, "port out of range")
		case errors.Is(err, routes.ErrInvalidDomain):
			fbErr(w, http.StatusBadRequest, "invalid domain")
		case errors.Is(err, routes.ErrDomainTaken):
			fbErr(w, http.StatusConflict, "domain already mapped")
		case errors.Is(err, routes.ErrNoNodeFound):
			fbErr(w, http.StatusConflict, "no node available")
		case errors.Is(err, routes.ErrMaxDomains):
			fbErr(w, http.StatusConflict, "plan domain limit reached")
		default:
			fbErr(w, http.StatusInternalServerError, "route create failed")
		}
		return
	}

	uid := apiCallerID(r)
	audit.Write(ctx, h.DB(), nil, r, audit.Entry{
		UserID: &uid, ActorType: audit.ActorAPI, Action: "fossbilling.route.create",
		Entity: "route", EntityID: strconv.FormatInt(id, 10),
		Meta: map[string]any{"domain": in.Domain, "service_id": in.ServiceID},
	})
	fbJSON(w, http.StatusCreated, map[string]any{"route_id": id})
}

// ---- Suspend ---------------------------------------------------------------

// SuspendService sets service status to 'suspended' and disables all routes.
func (h *FOSSBillingHandlers) SuspendService(w http.ResponseWriter, r *http.Request) {
	if !requireAdmin(r) {
		fbErr(w, http.StatusForbidden, "admin role required")
		return
	}
	svcID, _ := strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)
	if svcID == 0 {
		fbErr(w, http.StatusBadRequest, "invalid id")
		return
	}

	db := h.DB()
	if db == nil {
		fbErr(w, http.StatusServiceUnavailable, "db not ready")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()

	// Fetch all active route IDs for this service so we can delete them from Caddy.
	rows, err := db.QueryContext(ctx, "SELECT id FROM routes WHERE service_id = ?", svcID)
	if err != nil {
		fbErr(w, http.StatusInternalServerError, "query failed")
		return
	}
	var routeIDs []int64
	for rows.Next() {
		var rid int64
		if rows.Scan(&rid) == nil {
			routeIDs = append(routeIDs, rid)
		}
	}
	rows.Close()

	// Mark service suspended.
	if _, err := db.ExecContext(ctx,
		"UPDATE services SET status = 'suspended' WHERE id = ?", svcID,
	); err != nil {
		fbErr(w, http.StatusInternalServerError, "update failed")
		return
	}

	// Remove each route from Caddy nodes; clientID=0 = admin scope.
	for _, rid := range routeIDs {
		_ = h.Routes.Delete(ctx, 0, rid)
	}

	uid := apiCallerID(r)
	audit.Write(ctx, db, nil, r, audit.Entry{
		UserID: &uid, ActorType: audit.ActorAPI, Action: "fossbilling.service.suspend",
		Entity: "service", EntityID: strconv.FormatInt(svcID, 10),
	})
	fbJSON(w, http.StatusOK, map[string]any{"service_id": svcID, "suspended": true})
}

// ---- Delete ----------------------------------------------------------------

// DeleteService deletes all routes then the service record.
func (h *FOSSBillingHandlers) DeleteService(w http.ResponseWriter, r *http.Request) {
	if !requireAdmin(r) {
		fbErr(w, http.StatusForbidden, "admin role required")
		return
	}
	svcID, _ := strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)
	if svcID == 0 {
		fbErr(w, http.StatusBadRequest, "invalid id")
		return
	}

	db := h.DB()
	if db == nil {
		fbErr(w, http.StatusServiceUnavailable, "db not ready")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 15*time.Second)
	defer cancel()

	// Collect route IDs before deleting so we can push Caddy deletions.
	rows, err := db.QueryContext(ctx, "SELECT id FROM routes WHERE service_id = ?", svcID)
	if err != nil {
		fbErr(w, http.StatusInternalServerError, "query failed")
		return
	}
	var routeIDs []int64
	for rows.Next() {
		var rid int64
		if rows.Scan(&rid) == nil {
			routeIDs = append(routeIDs, rid)
		}
	}
	rows.Close()

	// Delete routes via domain service (updates node counters + pushes Caddy).
	for _, rid := range routeIDs {
		if err := h.Routes.Delete(ctx, 0, rid); err != nil {
			fbErr(w, http.StatusInternalServerError, "route delete failed")
			return
		}
	}

	if _, err := db.ExecContext(ctx, "DELETE FROM services WHERE id = ?", svcID); err != nil {
		fbErr(w, http.StatusInternalServerError, "service delete failed")
		return
	}

	uid := apiCallerID(r)
	audit.Write(ctx, db, nil, r, audit.Entry{
		UserID: &uid, ActorType: audit.ActorAPI, Action: "fossbilling.service.delete",
		Entity: "service", EntityID: strconv.FormatInt(svcID, 10),
	})
	fbJSON(w, http.StatusOK, map[string]any{"service_id": svcID, "deleted": true})
}
