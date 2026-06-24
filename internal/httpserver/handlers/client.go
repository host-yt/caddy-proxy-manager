package handlers

import (
	"bytes"
	"context"
	"crypto/subtle"
	"database/sql"
	"encoding/base64"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/hostyt/proxy-gateway/internal/audit"
	"github.com/hostyt/proxy-gateway/internal/auth"
	"github.com/hostyt/proxy-gateway/internal/domain/routes"
	"github.com/hostyt/proxy-gateway/internal/domain/wgpeer"
	"github.com/hostyt/proxy-gateway/internal/httpserver/middleware"
	"github.com/hostyt/proxy-gateway/internal/i18n"
	"github.com/hostyt/proxy-gateway/internal/installstate"
	"github.com/hostyt/proxy-gateway/internal/mail"
	"github.com/hostyt/proxy-gateway/internal/security"
	"github.com/hostyt/proxy-gateway/internal/view"
)

type ClientHandlers struct {
	DB        func() *sql.DB
	Sessions  *auth.Manager
	Templates *view.AppTemplates
	Routes    *routes.Service
	Logger    *slog.Logger
	State     *installstate.Manager // for TOTP secret encryption at rest
	// WGPeers (optional) drives /app/tunnels self-service flow.
	WGPeers *wgpeer.Service
	// SMS (optional) used for SMS OTP enrollment flow.
	SMS interface {
		Send(ctx context.Context, to, body string) error
	}
	// Mailer (optional) used for Email OTP enrollment + login challenges.
	Mailer *mail.Mailer
}

type baseAppData struct {
	Title             string
	Email             string
	Role              string
	CSRF              string
	Flash             string
	Error             string
	CSPNonce          string
	Lang              string
	Theme             string
	ImpersonatorEmail string // non-empty when an admin is viewing as this client
	Brand             Branding
}

func (h *ClientHandlers) base(r *http.Request, title string) baseAppData {
	sess := middleware.SessionFromContext(r.Context())
	d := baseAppData{
		Title:    title,
		CSPNonce: middleware.CSPNonce(r.Context()),
		Lang:     i18n.LangFromRequest(r),
		Theme:    themeFromRequest(r),
		Brand:    LoadBranding(r.Context(), h.DB()),
	}
	if sess != nil {
		d.Email = sess.Email
		d.Role = sess.Role
		d.CSRF = sess.CSRFToken
		d.ImpersonatorEmail = sess.ImpersonatorEmail
	}
	if msg := r.URL.Query().Get("flash"); msg != "" {
		d.Flash = msg
	}
	if msg := r.URL.Query().Get("err"); msg != "" {
		d.Error = msg
	}
	return d
}

func (h *ClientHandlers) render(w http.ResponseWriter, page string, data any) {
	var buf bytes.Buffer
	if err := h.Templates.Render(&buf, page, data); err != nil {
		h.Logger.Error("client render", "page", page, "err", err)
		http.Error(w, "render failed", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(buf.Bytes())
}

func clientIDFor(ctx context.Context, db *sql.DB, userID int64) (int64, error) {
	var id int64
	err := db.QueryRowContext(ctx, "SELECT id FROM clients WHERE user_id = ?", userID).Scan(&id)
	return id, err
}

// ---- Dashboard ----------------------------------------------------------

type clientDashboardData struct {
	baseAppData
	ServiceCount  int
	ActiveRoutes  int
	PendingRoutes int
}

func (h *ClientHandlers) Dashboard(w http.ResponseWriter, r *http.Request) {
	d := clientDashboardData{baseAppData: h.base(r, "Dashboard")}
	sess := middleware.SessionFromContext(r.Context())
	db := h.DB()
	if db == nil || sess == nil {
		h.render(w, "dashboard", d)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 3_000_000_000)
	defer cancel()
	clientID, err := clientIDFor(ctx, db, sess.UserID)
	if err != nil {
		h.render(w, "dashboard", d)
		return
	}
	_ = db.QueryRowContext(ctx, "SELECT COUNT(*) FROM services WHERE client_id = ?", clientID).Scan(&d.ServiceCount)
	_ = db.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM routes r JOIN services s ON s.id=r.service_id
		 WHERE s.client_id = ? AND r.status='active'`, clientID).Scan(&d.ActiveRoutes)
	_ = db.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM routes r JOIN services s ON s.id=r.service_id
		 WHERE s.client_id = ? AND r.status IN ('pending_dns','dns_ok','pending_ssl')`, clientID).Scan(&d.PendingRoutes)
	h.render(w, "dashboard", d)
}

// ---- Services (read-only customer view) --------------------------------

type clientServiceRow struct {
	ID         int64
	Name       string
	BackendIP  string
	PortStart  int
	PortEnd    int
	PlanName   string
	PlanKind   string // 'restricted' | 'npm' - controls whether the client may edit BackendIP / port range
	Status     string
	RouteCount int
}

type clientServicesData struct {
	baseAppData
	Services []clientServiceRow
}

func (h *ClientHandlers) Services(w http.ResponseWriter, r *http.Request) {
	d := clientServicesData{baseAppData: h.base(r, "My VPS")}
	sess := middleware.SessionFromContext(r.Context())
	db := h.DB()
	if db == nil || sess == nil {
		h.render(w, "services", d)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 3_000_000_000)
	defer cancel()
	clientID, err := clientIDFor(ctx, db, sess.UserID)
	if err != nil {
		h.render(w, "services", d)
		return
	}
	rows, err := db.QueryContext(ctx,
		`SELECT s.id, s.name, s.backend_ip, s.allowed_port_start, s.allowed_port_end, p.name, p.kind, s.status,
		        (SELECT COUNT(*) FROM routes r WHERE r.service_id = s.id)
		 FROM services s JOIN plans p ON p.id = s.plan_id
		 WHERE s.client_id = ? ORDER BY s.id DESC`, clientID)
	if err == nil {
		defer rows.Close()
		for rows.Next() {
			var s clientServiceRow
			if err := rows.Scan(&s.ID, &s.Name, &s.BackendIP, &s.PortStart, &s.PortEnd, &s.PlanName, &s.PlanKind, &s.Status, &s.RouteCount); err == nil {
				d.Services = append(d.Services, s)
			}
		}
	}
	h.render(w, "services", d)
}

// ServiceEdit (POST /app/services/{id}/edit) - only valid when the
// owning plan.kind = 'npm'. Restricted plans enforce hard rule #1:
// backend_ip / port range are admin-only.
func (h *ClientHandlers) ServiceEdit(w http.ResponseWriter, r *http.Request) {
	sess := middleware.SessionFromContext(r.Context())
	db := h.DB()
	if db == nil || sess == nil {
		http.Redirect(w, r, "/app/services", http.StatusSeeOther)
		return
	}
	id, _ := strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()
	clientID, err := clientIDFor(ctx, db, sess.UserID)
	if err != nil {
		http.Redirect(w, r, "/app/services", http.StatusSeeOther)
		return
	}
	var (
		ownerID  int64
		planKind string
	)
	if err := db.QueryRowContext(ctx,
		`SELECT s.client_id, p.kind FROM services s JOIN plans p ON p.id = s.plan_id WHERE s.id = ?`, id,
	).Scan(&ownerID, &planKind); err != nil {
		redirectWithFlash(w, r, "/app/services", "", "service not found")
		return
	}
	if ownerID != clientID {
		redirectWithFlash(w, r, "/app/services", "", "not your service")
		return
	}
	if planKind != "npm" {
		redirectWithFlash(w, r, "/app/services", "", "your plan is admin-managed")
		return
	}
	_ = r.ParseForm()
	backendIP := strings.TrimSpace(r.FormValue("backend_ip"))
	ip := net.ParseIP(backendIP)
	if ip == nil {
		redirectWithFlash(w, r, "/app/services", "", "backend IP invalid")
		return
	}
	// Even on self-service npm plans, never let a client point the node at
	// loopback or link-local/cloud-metadata - that would proxy to node-local
	// services or leak the node's cloud credentials.
	if security.IsDangerousProxyBackend(ip) {
		redirectWithFlash(w, r, "/app/services", "", "backend IP not allowed (loopback / link-local / metadata)")
		return
	}
	// Hard rule #2: the allowed port range is the security boundary, NOT
	// client data. A client must never widen it (routes.Create validates the
	// chosen port against this range, so widening it to 1..65535 would let the
	// client proxy to any backend port). Only backend_ip is self-service here;
	// the admin-assigned range is left untouched.
	if _, err := db.ExecContext(ctx,
		"UPDATE services SET backend_ip = ?, updated_at = NOW() WHERE id = ?",
		backendIP, id); err != nil {
		h.Logger.Warn("client service edit", "id", id, "err", err)
		redirectWithFlash(w, r, "/app/services", "", "update failed")
		return
	}
	uid := sess.UserID
	audit.Write(ctx, db, h.Logger, r, audit.Entry{
		UserID: &uid, Action: "service.update.client", Entity: "service",
		EntityID: strconv.FormatInt(id, 10),
		Meta:     map[string]any{"backend_ip": backendIP, "plan_kind": planKind},
	})
	// Re-push affected nodes now so the new backend_ip takes effect within
	// seconds instead of waiting up to ~5 min for ReconcileDrift. Backgrounded
	// on the service's own context so the client response isn't blocked.
	if h.Routes != nil {
		go func(serviceID int64) {
			defer recoverBg(h.Logger, "client-service-edit-resync")
			bg, cancel := context.WithTimeout(h.Routes.BackgroundCtx(), 30*time.Second)
			defer cancel()
			rows, err := db.QueryContext(bg,
				`SELECT DISTINCT caddy_node_id FROM routes WHERE service_id = ? AND caddy_node_id IS NOT NULL`, serviceID)
			if err != nil {
				return
			}
			defer rows.Close()
			var nodeIDs []int64
			for rows.Next() {
				var nid int64
				if rows.Scan(&nid) == nil {
					nodeIDs = append(nodeIDs, nid)
				}
			}
			if rows.Err() != nil {
				return
			}
			for _, nid := range nodeIDs {
				_ = h.Routes.Resync(bg, nid)
			}
		}(id)
	}
	redirectWithFlash(w, r, "/app/services", "Service updated", "")
}

// ---- Routes -------------------------------------------------------------

type clientRouteRow struct {
	ID           int64
	Domain       string
	PathPrefix   string
	UpstreamPort int
	ServiceName  string
	Status       string
	LastError    string
}

type clientRoutesData struct {
	baseAppData
	Routes []clientRouteRow
}

func (h *ClientHandlers) RoutesList(w http.ResponseWriter, r *http.Request) {
	d := clientRoutesData{baseAppData: h.base(r, "Domains")}
	sess := middleware.SessionFromContext(r.Context())
	db := h.DB()
	if db == nil || sess == nil {
		h.render(w, "routes_list", d)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 3_000_000_000)
	defer cancel()
	clientID, err := clientIDFor(ctx, db, sess.UserID)
	if err != nil {
		h.render(w, "routes_list", d)
		return
	}
	rows, err := db.QueryContext(ctx,
		`SELECT r.id, r.domain, COALESCE(r.path_prefix,''), r.upstream_port, s.name, r.status, COALESCE(r.last_error,'')
		 FROM routes r JOIN services s ON s.id = r.service_id
		 WHERE s.client_id = ? ORDER BY r.id DESC`, clientID)
	if err == nil {
		defer rows.Close()
		for rows.Next() {
			var rr clientRouteRow
			if err := rows.Scan(&rr.ID, &rr.Domain, &rr.PathPrefix, &rr.UpstreamPort, &rr.ServiceName, &rr.Status, &rr.LastError); err == nil {
				d.Routes = append(d.Routes, rr)
			}
		}
	}
	h.render(w, "routes_list", d)
}

type clientRouteNewServiceOpt struct {
	ID        int64
	Name      string
	PortStart int
	PortEnd   int
}

type clientRouteNewForm struct {
	UpstreamPort int
	Domain       string
	PathPrefix   string
}

type clientRouteNewData struct {
	baseAppData
	Services          []clientRouteNewServiceOpt
	SelectedServiceID int64
	Form              clientRouteNewForm
	NodeHostname      string
	NodeIP            string
}

func (h *ClientHandlers) RouteNew(w http.ResponseWriter, r *http.Request) {
	d := clientRouteNewData{baseAppData: h.base(r, "New domain mapping")}
	sess := middleware.SessionFromContext(r.Context())
	db := h.DB()
	if db == nil || sess == nil {
		h.render(w, "route_new", d)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 3_000_000_000)
	defer cancel()
	clientID, err := clientIDFor(ctx, db, sess.UserID)
	if err != nil {
		h.render(w, "route_new", d)
		return
	}
	rows, err := db.QueryContext(ctx,
		`SELECT id, name, allowed_port_start, allowed_port_end FROM services
		 WHERE client_id = ? AND status='active' ORDER BY id`, clientID)
	if err == nil {
		defer rows.Close()
		for rows.Next() {
			var s clientRouteNewServiceOpt
			if err := rows.Scan(&s.ID, &s.Name, &s.PortStart, &s.PortEnd); err == nil {
				d.Services = append(d.Services, s)
			}
		}
	}
	if sid := r.URL.Query().Get("service_id"); sid != "" {
		if v, err := strconv.ParseInt(sid, 10, 64); err == nil {
			d.SelectedServiceID = v
		}
	}

	// Show DNS target = first node in the plan's node group.
	if len(d.Services) > 0 {
		nodeRow := db.QueryRowContext(ctx,
			`SELECT COALESCE(n.public_hostname,''), COALESCE(n.public_ip,'')
			 FROM services s
			 JOIN caddy_nodes n ON n.node_group_id = s.node_group_id
			 WHERE s.client_id = ? AND n.is_enabled = 1
			 ORDER BY n.priority DESC, n.id ASC LIMIT 1`, clientID)
		_ = nodeRow.Scan(&d.NodeHostname, &d.NodeIP)
	}

	h.render(w, "route_new", d)
}

func (h *ClientHandlers) RouteCreate(w http.ResponseWriter, r *http.Request) {
	sess := middleware.SessionFromContext(r.Context())
	if sess == nil {
		http.Redirect(w, r, "/auth/login", http.StatusSeeOther)
		return
	}
	db := h.DB()
	if db == nil {
		http.Error(w, "no db", http.StatusServiceUnavailable)
		return
	}
	_ = r.ParseForm()
	serviceID, _ := strconv.ParseInt(r.FormValue("service_id"), 10, 64)
	port, _ := strconv.Atoi(r.FormValue("upstream_port"))

	ctx, cancel := context.WithTimeout(r.Context(), 8_000_000_000)
	defer cancel()
	clientID, err := clientIDFor(ctx, db, sess.UserID)
	if err != nil {
		http.Error(w, "no client record", http.StatusForbidden)
		return
	}

	in := routes.CreateInput{
		ServiceID:    serviceID,
		UpstreamPort: port,
		Domain:       r.FormValue("domain"),
		PathPrefix:   r.FormValue("path_prefix"),
		SSL:          r.FormValue("ssl") == "1",
		WebSocket:    r.FormValue("websocket") == "1",
		ForceHTTPS:   r.FormValue("force_https") == "1",
	}
	routeID, err := h.Routes.Create(ctx, clientID, in)
	if err != nil {
		msg := mapRouteErr(err)
		redirectWithFlash(w, r, "/app/routes/new", "", msg)
		return
	}
	uid := sess.UserID
	audit.Write(ctx, h.DB(), h.Logger, r, audit.Entry{
		UserID: &uid, Action: "route.create", Entity: "route",
		EntityID: fmt.Sprintf("%d", routeID),
		Meta: map[string]any{
			"service_id": in.ServiceID, "domain": strings.ToLower(strings.TrimSpace(in.Domain)),
			"path": in.PathPrefix, "port": in.UpstreamPort,
		},
	})
	redirectWithFlash(w, r, "/app/routes", "Domain mapping created. Update DNS and watch the status badge.", "")
}

func (h *ClientHandlers) RouteDelete(w http.ResponseWriter, r *http.Request) {
	sess := middleware.SessionFromContext(r.Context())
	if sess == nil {
		http.Redirect(w, r, "/auth/login", http.StatusSeeOther)
		return
	}
	db := h.DB()
	id, _ := strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)
	ctx, cancel := context.WithTimeout(r.Context(), 8_000_000_000)
	defer cancel()
	clientID, err := clientIDFor(ctx, db, sess.UserID)
	if err != nil {
		http.Error(w, "no client", http.StatusForbidden)
		return
	}
	if err := h.Routes.Delete(ctx, clientID, id); err != nil {
		redirectWithFlash(w, r, "/app/routes", "", "delete failed: "+sanitizeErr(err))
		return
	}
	uid := sess.UserID
	audit.Write(ctx, h.DB(), h.Logger, r, audit.Entry{
		UserID: &uid, Action: "route.delete", Entity: "route", EntityID: fmt.Sprintf("%d", id),
	})
	redirectWithFlash(w, r, "/app/routes", "Mapping deleted", "")
}

func (h *ClientHandlers) RouteVerifyDNS(w http.ResponseWriter, r *http.Request) {
	sess := middleware.SessionFromContext(r.Context())
	if sess == nil {
		http.Redirect(w, r, "/auth/login", http.StatusSeeOther)
		return
	}
	db := h.DB()
	id, _ := strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)
	ctx, cancel := context.WithTimeout(r.Context(), 10_000_000_000)
	defer cancel()
	clientID, _ := clientIDFor(ctx, db, sess.UserID)
	if err := h.Routes.VerifyDNS(ctx, clientID, id); err != nil {
		redirectWithFlash(w, r, "/app/routes", "", "re-check failed: "+sanitizeErr(err))
		return
	}
	redirectWithFlash(w, r, "/app/routes", "DNS re-check queued", "")
}

func (h *ClientHandlers) RouteRetrySSL(w http.ResponseWriter, r *http.Request) {
	// MVP: re-checking DNS triggers a re-push too. SSL retry is the same path.
	h.RouteVerifyDNS(w, r)
}

func mapRouteErr(err error) string {
	switch {
	case errors.Is(err, routes.ErrPortOutOfRange):
		return "Port is outside your allowed range."
	case errors.Is(err, routes.ErrInvalidDomain):
		return "Invalid domain."
	case errors.Is(err, routes.ErrDomainTaken):
		return "This domain (and path) is already mapped."
	case errors.Is(err, routes.ErrNoNodeFound):
		return "No proxy node has capacity for your plan. Contact support."
	case errors.Is(err, routes.ErrServiceNotYours):
		return "Service not found."
	case errors.Is(err, routes.ErrMaxDomains):
		return "Plan domain limit reached. Upgrade or remove an existing mapping."
	}
	if s := err.Error(); strings.Contains(s, "plan does not permit path routing") {
		return "Your plan does not allow path routing - leave path empty."
	}
	return "Create failed."
}

// ---- Client 2FA --------------------------------------------------------

type clientTwofaData struct {
	baseAppData
	Enabled         bool
	Enrolling       bool
	Secret          string
	QRBase64        string
	RecoveryCodes   []string
	SMSOTPEnabled   bool // user has SMS 2FA active
	SMSOTPAvailable bool // admin allowed SMS 2FA globally
	HasPhone        bool // user has phone_e164 set
	SMSOTPEnrolling bool // in-progress SMS enrollment (code sent, waiting confirm)
	// Email 2FA - always available as long as SMTP is wired (no admin gate).
	EmailOTPEnabled   bool
	EmailOTPEnrolling bool
	HasMailer         bool
}

func (h *ClientHandlers) TwoFAPage(w http.ResponseWriter, r *http.Request) {
	d := clientTwofaData{baseAppData: h.base(r, "Two-factor authentication")}
	d.HasMailer = h.Mailer != nil
	sess := middleware.SessionFromContext(r.Context())
	db := h.DB()
	if db != nil && sess != nil {
		ctx := r.Context()
		var smsOTPEnabled, emailOTPEnabled bool
		var phoneE164 sql.NullString
		_ = db.QueryRowContext(ctx,
			"SELECT totp_enabled, sms_otp_enabled, email_otp_enabled, phone_e164 FROM users WHERE id = ?",
			sess.UserID,
		).Scan(&d.Enabled, &smsOTPEnabled, &emailOTPEnabled, &phoneE164)
		d.SMSOTPEnabled = smsOTPEnabled
		d.EmailOTPEnabled = emailOTPEnabled
		d.HasPhone = phoneE164.Valid && phoneE164.String != ""
		var avail string
		_ = db.QueryRowContext(ctx,
			"SELECT value FROM settings WHERE `key` = 'sms_otp_available' LIMIT 1",
		).Scan(&avail)
		d.SMSOTPAvailable = avail == "1"
	}
	h.render(w, "twofa", d)
}

func (h *ClientHandlers) TwoFAStart(w http.ResponseWriter, r *http.Request) {
	sess := middleware.SessionFromContext(r.Context())
	if sess == nil {
		http.Redirect(w, r, "/auth/login", http.StatusSeeOther)
		return
	}
	_, secret, qrPNG, err := auth.GenerateTOTP("Hostyt Proxy", sess.Email)
	if err != nil {
		http.Error(w, "totp gen failed", http.StatusInternalServerError)
		return
	}
	d := clientTwofaData{
		baseAppData: h.base(r, "Set up 2FA"),
		Enrolling:   true,
		Secret:      secret,
		QRBase64:    base64.StdEncoding.EncodeToString(qrPNG),
	}
	h.render(w, "twofa", d)
}

func (h *ClientHandlers) TwoFAConfirm(w http.ResponseWriter, r *http.Request) {
	sess := middleware.SessionFromContext(r.Context())
	db := h.DB()
	if sess == nil || db == nil {
		http.Error(w, "no db / no session", http.StatusServiceUnavailable)
		return
	}
	_ = r.ParseForm()
	secret := strings.TrimSpace(r.FormValue("secret"))
	code := strings.TrimSpace(r.FormValue("code"))
	if err := auth.ValidateTOTP(secret, code); err != nil {
		redirectWithFlash(w, r, "/app/2fa", "", "invalid code; try again")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 8_000_000_000)
	defer cancel()
	codes, hashes, err := auth.GenerateRecoveryCodes(8)
	if err != nil {
		redirectWithFlash(w, r, "/app/2fa", "", "internal error")
		return
	}
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		redirectWithFlash(w, r, "/app/2fa", "", "tx begin failed")
		return
	}
	defer tx.Rollback() //nolint:errcheck
	encSecret := secret
	useEnc := false
	if h.State != nil {
		if enc, eerr := h.State.Encrypt(secret); eerr == nil {
			encSecret = enc
			useEnc = true
		}
	}
	var totpErr error
	if useEnc {
		_, totpErr = tx.ExecContext(ctx,
			"UPDATE users SET totp_secret_enc = ?, totp_secret = NULL, totp_enabled = 1 WHERE id = ?",
			encSecret, sess.UserID)
	} else {
		_, totpErr = tx.ExecContext(ctx,
			"UPDATE users SET totp_secret = ?, totp_secret_enc = NULL, totp_enabled = 1 WHERE id = ?",
			secret, sess.UserID)
	}
	if totpErr != nil {
		return
	}
	_, _ = tx.ExecContext(ctx, "DELETE FROM recovery_codes WHERE user_id = ?", sess.UserID)
	for _, h := range hashes {
		if _, err := tx.ExecContext(ctx,
			"INSERT INTO recovery_codes (user_id, code_hash) VALUES (?, ?)", sess.UserID, h); err != nil {
			return
		}
	}
	if err := tx.Commit(); err != nil {
		return
	}
	uid := sess.UserID
	audit.Write(ctx, db, h.Logger, r, audit.Entry{
		UserID: &uid, Action: "2fa.enable", Entity: "user", EntityID: fmt.Sprintf("%d", uid),
	})
	d := clientTwofaData{
		baseAppData:   h.base(r, "Two-factor authentication"),
		Enabled:       true,
		RecoveryCodes: codes,
	}
	h.render(w, "twofa", d)
}

func (h *ClientHandlers) TwoFADisable(w http.ResponseWriter, r *http.Request) {
	sess := middleware.SessionFromContext(r.Context())
	db := h.DB()
	if sess == nil || db == nil {
		http.Error(w, "no db", http.StatusServiceUnavailable)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 5_000_000_000)
	defer cancel()
	_, _ = db.ExecContext(ctx, "UPDATE users SET totp_secret = NULL, totp_secret_enc = NULL, totp_enabled = 0 WHERE id = ?", sess.UserID)
	_, _ = db.ExecContext(ctx, "DELETE FROM recovery_codes WHERE user_id = ?", sess.UserID)
	uid := sess.UserID
	audit.Write(ctx, db, h.Logger, r, audit.Entry{
		UserID: &uid, Action: "2fa.disable", Entity: "user", EntityID: fmt.Sprintf("%d", uid),
	})
	redirectWithFlash(w, r, "/app/2fa", "2FA disabled", "")
}

// ---- SMS OTP enrollment (client) ----------------------------------------

// SMSOTPStart sends a verification code to the user's phone and stores the
// OTP ticket in Redis. The pending ticket is held in a separate cookie
// (not hpg_2fa_pending) so it doesn't interfere with normal login flow.
func (h *ClientHandlers) SMSOTPStart(w http.ResponseWriter, r *http.Request) {
	sess := middleware.SessionFromContext(r.Context())
	db := h.DB()
	if sess == nil || db == nil {
		http.Redirect(w, r, "/auth/login", http.StatusSeeOther)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 8*time.Second)
	defer cancel()

	// Guard: admin must have enabled SMS OTP globally.
	var avail string
	_ = db.QueryRowContext(ctx,
		"SELECT value FROM settings WHERE `key` = 'sms_otp_available' LIMIT 1",
	).Scan(&avail)
	if avail != "1" {
		redirectWithFlash(w, r, "/app/2fa", "", "SMS 2FA is not available.")
		return
	}
	var phone sql.NullString
	_ = db.QueryRowContext(ctx, "SELECT phone_e164 FROM users WHERE id = ?", sess.UserID).Scan(&phone)
	if !phone.Valid || phone.String == "" {
		redirectWithFlash(w, r, "/app/2fa", "", "Set your phone in Account first.")
		return
	}
	if h.SMS == nil {
		redirectWithFlash(w, r, "/app/2fa", "", "SMS not configured.")
		return
	}
	// Generate and send code - need a redis.Client here; store ticket in session cookie.
	// We pass through the redirect back to twofa page with SMSOTPEnrolling=true.
	// Actual storage uses the auth.StoreSMSOTP helpers which need *redis.Client.
	// ClientHandlers doesn't hold RDB directly; store a short-lived Redis key via
	// the SMS field's Send - use a simple in-DB approach instead:
	// generate code → store SHA-256 hash in users.sms_otp_pending_hash + expiry.
	// This avoids injecting redis into ClientHandlers.
	code, err := auth.GenerateSMSOTP()
	if err != nil {
		redirectWithFlash(w, r, "/app/2fa", "", "Internal error.")
		return
	}
	// Store hash + expiry directly in DB (avoids redis dependency in ClientHandlers).
	hash := auth.SMSOTPHash(code)
	_, err = db.ExecContext(ctx,
		"UPDATE users SET sms_otp_pending_hash = ?, sms_otp_pending_exp = DATE_ADD(NOW(), INTERVAL 5 MINUTE) WHERE id = ?",
		hash, sess.UserID)
	if err != nil {
		redirectWithFlash(w, r, "/app/2fa", "", "Internal error.")
		return
	}
	if err := h.SMS.Send(ctx, phone.String, fmt.Sprintf("Your Hostyt Proxy SMS 2FA setup code: %s", code)); err != nil {
		redirectWithFlash(w, r, "/app/2fa", "", "Failed to send SMS: "+sanitizeErr(err))
		return
	}
	uid := sess.UserID
	audit.Write(ctx, db, h.Logger, r, audit.Entry{
		UserID: &uid, Action: "2fa.sms.enroll.start", Entity: "user", EntityID: fmt.Sprintf("%d", uid),
	})
	// Show the confirm form.
	d := clientTwofaData{
		baseAppData:     h.base(r, "Two-factor authentication"),
		SMSOTPAvailable: true, HasPhone: true,
		SMSOTPEnrolling: true,
	}
	h.render(w, "twofa", d)
}

// SMSOTPConfirm verifies the enrollment code and sets sms_otp_enabled=1.
func (h *ClientHandlers) SMSOTPConfirm(w http.ResponseWriter, r *http.Request) {
	sess := middleware.SessionFromContext(r.Context())
	db := h.DB()
	if sess == nil || db == nil {
		http.Redirect(w, r, "/auth/login", http.StatusSeeOther)
		return
	}
	_ = r.ParseForm()
	code := strings.TrimSpace(r.FormValue("code"))
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()

	var storedHash sql.NullString
	var exp sql.NullTime
	_ = db.QueryRowContext(ctx,
		"SELECT sms_otp_pending_hash, sms_otp_pending_exp FROM users WHERE id = ?", sess.UserID,
	).Scan(&storedHash, &exp)

	if !storedHash.Valid || storedHash.String == "" {
		redirectWithFlash(w, r, "/app/2fa", "", "No pending SMS code. Start again.")
		return
	}
	if !exp.Valid || time.Now().After(exp.Time) {
		redirectWithFlash(w, r, "/app/2fa", "", "Code expired. Start again.")
		return
	}
	// Constant-time compare: avoid leaking match via response timing.
	if subtle.ConstantTimeCompare([]byte(auth.SMSOTPHash(code)), []byte(storedHash.String)) != 1 {
		redirectWithFlash(w, r, "/app/2fa", "", "Invalid code.")
		return
	}
	_, err := db.ExecContext(ctx,
		"UPDATE users SET sms_otp_enabled = 1, sms_otp_pending_hash = NULL, sms_otp_pending_exp = NULL WHERE id = ?",
		sess.UserID)
	if err != nil {
		redirectWithFlash(w, r, "/app/2fa", "", "Internal error.")
		return
	}
	uid := sess.UserID
	audit.Write(ctx, db, h.Logger, r, audit.Entry{
		UserID: &uid, Action: "2fa.sms.enroll.complete", Entity: "user", EntityID: fmt.Sprintf("%d", uid),
	})
	redirectWithFlash(w, r, "/app/2fa", "SMS 2FA enabled.", "")
}

// SMSOTPDisable turns off SMS OTP for the current user.
func (h *ClientHandlers) SMSOTPDisable(w http.ResponseWriter, r *http.Request) {
	sess := middleware.SessionFromContext(r.Context())
	db := h.DB()
	if sess == nil || db == nil {
		http.Redirect(w, r, "/auth/login", http.StatusSeeOther)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()
	_, _ = db.ExecContext(ctx,
		"UPDATE users SET sms_otp_enabled = 0, sms_otp_pending_hash = NULL, sms_otp_pending_exp = NULL WHERE id = ?",
		sess.UserID)
	uid := sess.UserID
	audit.Write(ctx, db, h.Logger, r, audit.Entry{
		UserID: &uid, Action: "2fa.sms.disable", Entity: "user", EntityID: fmt.Sprintf("%d", uid),
	})
	redirectWithFlash(w, r, "/app/2fa", "SMS 2FA disabled.", "")
}

// ---- Client API keys ----------------------------------------------------

type clientAPIKeyRow struct {
	ID         int64
	Name       string
	Prefix     string
	Scopes     string
	LastUsedAt string
	CreatedAt  string
	ExpiresAt  string
	Revoked    bool
}

type clientAPIKeysData struct {
	baseAppData
	Keys     []clientAPIKeyRow
	NewPlain string
}

func (h *ClientHandlers) APIKeysPage(w http.ResponseWriter, r *http.Request) {
	d := clientAPIKeysData{baseAppData: h.base(r, "API tokens")}
	d.Keys = h.loadClientAPIKeys(r.Context())
	h.render(w, "api_keys", d)
}

func (h *ClientHandlers) APIKeysCreate(w http.ResponseWriter, r *http.Request) {
	sess := middleware.SessionFromContext(r.Context())
	db := h.DB()
	if db == nil || sess == nil {
		http.Error(w, "no db / no session", http.StatusServiceUnavailable)
		return
	}
	_ = r.ParseForm()
	name := strings.TrimSpace(r.FormValue("name"))
	if name == "" {
		redirectWithFlash(w, r, "/app/api-keys", "", "name required")
		return
	}
	expiresDays, _ := strconv.Atoi(strings.TrimSpace(r.FormValue("expires_days")))
	if expiresDays < 0 || expiresDays > 3650 {
		redirectWithFlash(w, r, "/app/api-keys", "", "expires_days must be 0..3650")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()
	// Client-owned tokens are intentionally limited to the read+write
	// scopes the customer routes actually accept. The admin /v1/* scopes
	// are reserved for admin-issued keys.
	plain, id, prefix, err := auth.CreateAPIKey(ctx, db, sess.UserID, name, "client:read,client:write")
	if err != nil {
		h.Logger.Error("client api key create", "err", err)
		redirectWithFlash(w, r, "/app/api-keys", "", "create failed")
		return
	}
	if expiresDays > 0 {
		_, _ = db.ExecContext(ctx,
			"UPDATE api_keys SET expires_at = (NOW() + INTERVAL ? DAY) WHERE id = ?",
			expiresDays, id)
	}
	uid := sess.UserID
	audit.Write(ctx, db, h.Logger, r, audit.Entry{
		UserID: &uid, Action: "api_key.create.client", Entity: "api_key",
		EntityID: strconv.FormatInt(id, 10),
		Meta:     map[string]any{"name": name, "prefix": prefix},
	})
	d := clientAPIKeysData{baseAppData: h.base(r, "API tokens"), NewPlain: plain}
	d.Keys = h.loadClientAPIKeys(r.Context())
	h.render(w, "api_keys", d)
}

func (h *ClientHandlers) APIKeysRevoke(w http.ResponseWriter, r *http.Request) {
	sess := middleware.SessionFromContext(r.Context())
	db := h.DB()
	if db == nil || sess == nil {
		http.Error(w, "no db", http.StatusServiceUnavailable)
		return
	}
	id, _ := strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()
	if _, err := db.ExecContext(ctx,
		"UPDATE api_keys SET revoked_at = NOW() WHERE id = ? AND user_id = ?", id, sess.UserID); err != nil {
		redirectWithFlash(w, r, "/app/api-keys", "", "revoke failed")
		return
	}
	uid := sess.UserID
	audit.Write(ctx, db, h.Logger, r, audit.Entry{
		UserID: &uid, Action: "api_key.revoke.client", Entity: "api_key",
		EntityID: strconv.FormatInt(id, 10),
	})
	redirectWithFlash(w, r, "/app/api-keys", "Token revoked", "")
}

func (h *ClientHandlers) loadClientAPIKeys(ctx context.Context) []clientAPIKeyRow {
	sess := middleware.SessionFromContext(ctx)
	db := h.DB()
	if db == nil || sess == nil {
		return nil
	}
	c, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	rows, err := db.QueryContext(c,
		`SELECT id, name, key_prefix, scopes,
		        COALESCE(DATE_FORMAT(last_used_at,'%Y-%m-%d %H:%i'),''),
		        DATE_FORMAT(created_at,'%Y-%m-%d'),
		        COALESCE(DATE_FORMAT(expires_at,'%Y-%m-%d'),''),
		        revoked_at IS NOT NULL
		 FROM api_keys WHERE user_id = ? ORDER BY id DESC`, sess.UserID)
	if err != nil {
		return nil
	}
	defer rows.Close()
	var out []clientAPIKeyRow
	for rows.Next() {
		var k clientAPIKeyRow
		if err := rows.Scan(&k.ID, &k.Name, &k.Prefix, &k.Scopes, &k.LastUsedAt, &k.CreatedAt, &k.ExpiresAt, &k.Revoked); err == nil {
			out = append(out, k)
		}
	}
	return out
}

// ---- legacy stubs kept compiling ---------------------------------------

func ClientDashboard(w http.ResponseWriter, _ *http.Request) {
	notImplemented(w, "ClientDashboard")
}
func ClientServices(w http.ResponseWriter, _ *http.Request) {
	notImplemented(w, "ClientServices")
}
func ClientRoutesList(w http.ResponseWriter, _ *http.Request) {
	notImplemented(w, "ClientRoutesList")
}
func ClientRouteCreate(w http.ResponseWriter, _ *http.Request) {
	notImplemented(w, "ClientRouteCreate")
}
func ClientRouteDelete(w http.ResponseWriter, _ *http.Request) {
	notImplemented(w, "ClientRouteDelete")
}
func ClientRouteVerifyDNS(w http.ResponseWriter, _ *http.Request) {
	notImplemented(w, "ClientRouteVerifyDNS")
}
func ClientRouteRetrySSL(w http.ResponseWriter, _ *http.Request) {
	notImplemented(w, "ClientRouteRetrySSL")
}
