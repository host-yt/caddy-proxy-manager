package handlers

import (
	"context"
	"database/sql"
	"errors"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/host-yt/caddy-proxy-manager/internal/audit"
	"github.com/host-yt/caddy-proxy-manager/internal/auth"
	"github.com/host-yt/caddy-proxy-manager/internal/httpserver/middleware"
	"github.com/host-yt/caddy-proxy-manager/internal/reseller"
	"github.com/go-chi/chi/v5"
)

// slugRe restricts reseller slugs to url-safe lowercase tokens (used in future
// per-reseller URLs / branding lookups).
var slugRe = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$`)

// resellerRow is one reseller plus derived counts for the management list.
type resellerRow struct {
	reseller.Reseller
	ClientCount int
	AdminCount  int
}

// rsClientOpt / adminOpt drive the assign/provision selects.
type rsClientOpt struct {
	ID          int64
	Name        string
	ResellerID  int64 // 0 = platform-direct
	ResellerNam string
}

type adminOpt struct {
	ID         int64
	Email      string
	Role       string
	ResellerID int64 // 0 = platform admin
}

type resellersData struct {
	baseAdminData
	Resellers []resellerRow
	Clients   []rsClientOpt
	Admins    []adminOpt
}

// guardSuperAdmin denies non-super_admin. Reseller provisioning is owner-level:
// it grants tenant ownership and rewrites session scope, so admin is not enough.
func (h *AdminHandlers) guardSuperAdmin(w http.ResponseWriter, r *http.Request) *auth.Session {
	sess := middleware.SessionFromContext(r.Context())
	if sess == nil || sess.Role != "super_admin" {
		http.Error(w, "forbidden", http.StatusForbidden)
		return nil
	}
	return sess
}

// ResellersList renders GET /admin/resellers (super_admin only).
func (h *AdminHandlers) ResellersList(w http.ResponseWriter, r *http.Request) {
	if h.guardSuperAdmin(w, r) == nil {
		return
	}
	d := resellersData{baseAdminData: h.base(r, "Resellers")}
	d.PageDesc = "White-label tenant groups - assign clients and provision reseller-admins"
	ctx := r.Context()
	db := h.DB()
	if h.Resellers != nil {
		list, err := h.Resellers.List(ctx)
		if err != nil {
			h.Logger.Error("resellers list", "err", err)
		}
		for _, rs := range list {
			row := resellerRow{Reseller: rs}
			if db != nil {
				db.QueryRowContext(ctx, `SELECT COUNT(*) FROM clients WHERE reseller_id=?`, rs.ID).Scan(&row.ClientCount)
				db.QueryRowContext(ctx, `SELECT COUNT(*) FROM users WHERE reseller_id=?`, rs.ID).Scan(&row.AdminCount)
			}
			d.Resellers = append(d.Resellers, row)
		}
	}
	d.Clients = h.listClientOpts(ctx, db)
	d.Admins = h.listAdminOpts(ctx, db)
	h.render(w, "resellers", d)
}

// listClientOpts returns clients with their current reseller (for assignment).
func (h *AdminHandlers) listClientOpts(ctx context.Context, db *sql.DB) []rsClientOpt {
	if db == nil {
		return nil
	}
	rows, err := db.QueryContext(ctx,
		`SELECT c.id, COALESCE(NULLIF(c.display_name,''), u.email), COALESCE(c.reseller_id,0), COALESCE(r.name,'')
		 FROM clients c JOIN users u ON u.id=c.user_id
		 LEFT JOIN resellers r ON r.id=c.reseller_id ORDER BY c.id`)
	if err != nil {
		h.Logger.Error("reseller client opts", "err", err)
		return nil
	}
	defer rows.Close()
	var out []rsClientOpt
	for rows.Next() {
		var o rsClientOpt
		if err := rows.Scan(&o.ID, &o.Name, &o.ResellerID, &o.ResellerNam); err != nil {
			return out
		}
		out = append(out, o)
	}
	return out
}

// listAdminOpts returns admin/support users eligible to become reseller-admins.
// super_admin is excluded: it bypasses scope checks and the route boundary keys
// off reseller_id alone, so a scoped super_admin would lock itself out.
func (h *AdminHandlers) listAdminOpts(ctx context.Context, db *sql.DB) []adminOpt {
	if db == nil {
		return nil
	}
	rows, err := db.QueryContext(ctx,
		`SELECT id, email, role, COALESCE(reseller_id,0) FROM users
		 WHERE role IN ('admin','support') ORDER BY email`)
	if err != nil {
		h.Logger.Error("reseller admin opts", "err", err)
		return nil
	}
	defer rows.Close()
	var out []adminOpt
	for rows.Next() {
		var o adminOpt
		if err := rows.Scan(&o.ID, &o.Email, &o.Role, &o.ResellerID); err != nil {
			return out
		}
		out = append(out, o)
	}
	return out
}

// ResellersCreate handles POST /admin/resellers.
func (h *AdminHandlers) ResellersCreate(w http.ResponseWriter, r *http.Request) {
	sess := h.guardSuperAdmin(w, r)
	if sess == nil {
		return
	}
	if h.Resellers == nil {
		redirectWithFlash(w, r, "/admin/resellers", "", "reseller store unavailable")
		return
	}
	_ = r.ParseForm()
	name := strings.TrimSpace(r.FormValue("name"))
	slug := strings.ToLower(strings.TrimSpace(r.FormValue("slug")))
	if name == "" || !slugRe.MatchString(slug) {
		redirectWithFlash(w, r, "/admin/resellers", "", "name required and slug must be lowercase alphanumeric/dashes")
		return
	}
	id, err := h.Resellers.Create(r.Context(), reseller.Reseller{
		Name: name, Slug: slug, Status: reseller.StatusActive,
		BrandName:    strings.TrimSpace(r.FormValue("brand_name")),
		SupportEmail: strings.TrimSpace(r.FormValue("support_email")),
	})
	if err != nil {
		h.Logger.Error("reseller create", "err", err)
		redirectWithFlash(w, r, "/admin/resellers", "", "could not create reseller (slug may be taken)")
		return
	}
	h.auditReseller(r, sess, "reseller.created", strconv.FormatInt(id, 10), map[string]any{"name": name, "slug": slug})
	redirectWithFlash(w, r, "/admin/resellers", "Reseller created", "")
}

// ResellersUpdate handles POST /admin/resellers/{id} (name/status/branding).
func (h *AdminHandlers) ResellersUpdate(w http.ResponseWriter, r *http.Request) {
	sess := h.guardSuperAdmin(w, r)
	if sess == nil {
		return
	}
	id := h.resellerParam(w, r)
	if id == 0 {
		return
	}
	_ = r.ParseForm()
	status := r.FormValue("status")
	if status != reseller.StatusActive && status != reseller.StatusSuspended {
		status = reseller.StatusActive
	}
	name := strings.TrimSpace(r.FormValue("name"))
	if name == "" {
		redirectWithFlash(w, r, "/admin/resellers", "", "name required")
		return
	}
	err := h.Resellers.Update(r.Context(), reseller.Reseller{
		ID: id, Name: name, Status: status,
		BrandName:    strings.TrimSpace(r.FormValue("brand_name")),
		LogoURL:      strings.TrimSpace(r.FormValue("logo_url")),
		SupportEmail: strings.TrimSpace(r.FormValue("support_email")),
		PrimaryColor: strings.TrimSpace(r.FormValue("primary_color")),
	})
	if err != nil {
		redirectWithFlash(w, r, "/admin/resellers", "", "could not update reseller")
		return
	}
	h.auditReseller(r, sess, "reseller.updated", strconv.FormatInt(id, 10), map[string]any{"status": status})
	redirectWithFlash(w, r, "/admin/resellers", "Reseller updated", "")
}

// ResellersDelete handles POST /admin/resellers/{id}/delete. FK ON DELETE SET
// NULL returns owned clients/users to platform-direct; we revoke the sessions of
// the freed reseller-admins so their cached scope does not linger.
func (h *AdminHandlers) ResellersDelete(w http.ResponseWriter, r *http.Request) {
	sess := h.guardSuperAdmin(w, r)
	if sess == nil {
		return
	}
	id := h.resellerParam(w, r)
	if id == 0 {
		return
	}
	ctx := r.Context()
	freed := h.resellerAdminIDs(ctx, id)
	if err := h.Resellers.Delete(ctx, id); err != nil {
		redirectWithFlash(w, r, "/admin/resellers", "", "could not delete reseller")
		return
	}
	h.revokeUsers(ctx, freed)
	h.auditReseller(r, sess, "reseller.deleted", strconv.FormatInt(id, 10), nil)
	redirectWithFlash(w, r, "/admin/resellers", "Reseller deleted", "")
}

// ResellerAssignClient handles POST /admin/resellers/{id}/clients (assign or,
// when reseller_id=0, release a client back to platform-direct).
func (h *AdminHandlers) ResellerAssignClient(w http.ResponseWriter, r *http.Request) {
	sess := h.guardSuperAdmin(w, r)
	if sess == nil {
		return
	}
	id := h.resellerParam(w, r)
	if id == 0 {
		return
	}
	_ = r.ParseForm()
	clientID, _ := strconv.ParseInt(r.FormValue("client_id"), 10, 64)
	if clientID <= 0 {
		redirectWithFlash(w, r, "/admin/resellers", "", "pick a client")
		return
	}
	var rid *int64
	if r.FormValue("action") != "release" {
		rid = &id
	}
	if err := h.Resellers.AssignClient(r.Context(), clientID, rid); err != nil {
		redirectWithFlash(w, r, "/admin/resellers", "", "could not assign client")
		return
	}
	h.auditReseller(r, sess, "reseller.client_assigned", strconv.FormatInt(id, 10),
		map[string]any{"client_id": clientID, "released": rid == nil})
	redirectWithFlash(w, r, "/admin/resellers", "Client ownership updated", "")
}

// ResellerProvisionAdmin handles POST /admin/resellers/{id}/admins. HARD
// INVARIANT: setting users.reseller_id must revoke that user's live sessions -
// a cached Session.ResellerID otherwise bypasses the route boundary until expiry.
func (h *AdminHandlers) ResellerProvisionAdmin(w http.ResponseWriter, r *http.Request) {
	sess := h.guardSuperAdmin(w, r)
	if sess == nil {
		return
	}
	id := h.resellerParam(w, r)
	if id == 0 {
		return
	}
	_ = r.ParseForm()
	userID, _ := strconv.ParseInt(r.FormValue("user_id"), 10, 64)
	if userID <= 0 {
		redirectWithFlash(w, r, "/admin/resellers", "", "pick a user")
		return
	}
	ctx := r.Context()
	// Never scope a super_admin: the boundary keys off reseller_id regardless of
	// role, so it would lock a super_admin out of global infra.
	var role string
	if db := h.DB(); db != nil {
		if err := db.QueryRowContext(ctx, "SELECT role FROM users WHERE id=?", userID).Scan(&role); err != nil {
			redirectWithFlash(w, r, "/admin/resellers", "", "user not found")
			return
		}
	}
	if role == "super_admin" {
		redirectWithFlash(w, r, "/admin/resellers", "", "cannot scope a super_admin to a reseller")
		return
	}
	release := r.FormValue("action") == "release"
	var rid *int64
	if !release {
		rid = &id
	}
	if err := h.Resellers.AssignAdmin(ctx, userID, rid); err != nil {
		redirectWithFlash(w, r, "/admin/resellers", "", "could not update reseller-admin")
		return
	}
	// Keystone: force re-login so the new (or cleared) scope is stamped fresh.
	h.revokeUsers(ctx, []int64{userID})
	h.auditReseller(r, sess, "reseller.admin_provisioned", strconv.FormatInt(id, 10),
		map[string]any{"user_id": userID, "released": release})
	redirectWithFlash(w, r, "/admin/resellers", "Reseller-admin updated; their sessions were revoked", "")
}

// resellerParam parses {id}, verifies the reseller exists, else flashes + returns 0.
func (h *AdminHandlers) resellerParam(w http.ResponseWriter, r *http.Request) int64 {
	if h.Resellers == nil {
		redirectWithFlash(w, r, "/admin/resellers", "", "reseller store unavailable")
		return 0
	}
	id, _ := strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)
	if id <= 0 {
		redirectWithFlash(w, r, "/admin/resellers", "", "bad reseller id")
		return 0
	}
	if _, err := h.Resellers.Get(r.Context(), id); err != nil {
		if errors.Is(err, reseller.ErrNotFound) {
			redirectWithFlash(w, r, "/admin/resellers", "", "reseller not found")
			return 0
		}
		redirectWithFlash(w, r, "/admin/resellers", "", "reseller lookup failed")
		return 0
	}
	return id
}

// resellerAdminIDs returns user ids currently scoped to a reseller.
func (h *AdminHandlers) resellerAdminIDs(ctx context.Context, resellerID int64) []int64 {
	db := h.DB()
	if db == nil {
		return nil
	}
	rows, err := db.QueryContext(ctx, `SELECT id FROM users WHERE reseller_id=?`, resellerID)
	if err != nil {
		return nil
	}
	defer rows.Close()
	var out []int64
	for rows.Next() {
		var id int64
		if rows.Scan(&id) == nil {
			out = append(out, id)
		}
	}
	return out
}

// revokeUsers destroys all live sessions of the given users (best-effort).
func (h *AdminHandlers) revokeUsers(ctx context.Context, ids []int64) {
	if h.Sessions == nil {
		return
	}
	for _, id := range ids {
		if _, err := h.Sessions.DestroyAllForUser(ctx, id); err != nil {
			h.Logger.Error("reseller session revoke", "user", id, "err", err)
		}
	}
}

func (h *AdminHandlers) auditReseller(r *http.Request, sess *auth.Session, action, entityID string, meta map[string]any) {
	if h.DB == nil {
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()
	audit.Write(ctx, h.DB(), h.Logger, r, audit.Entry{
		UserID: actorUserID(sess), Action: action, Entity: "reseller", EntityID: entityID, Meta: meta,
	})
}
