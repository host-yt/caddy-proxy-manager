package handlers

import (
	"context"
	"net/http"
	"strconv"
	"time"

	"github.com/go-chi/chi/v5"
)

// mtlsRoleRow is one named role in the UI.
type mtlsRoleRow struct {
	ID   int64
	Name string
}

// mtlsPathRuleRow is one path-rule entry in the host editor.
type mtlsPathRuleRow struct {
	ID           int64
	PathPattern  string
	RequiredRole string
}

// MTLSRoleCreate POST /admin/mtls/ca/{ca_id}/roles - add a named role to a CA.
func (h *AdminHandlers) MTLSRoleCreate(w http.ResponseWriter, r *http.Request) {
	if h.mtlsScopeDenied(w, r) {
		return
	}
	const page = "/admin/mtls"
	caID, err := strconv.ParseInt(chi.URLParam(r, "ca_id"), 10, 64)
	if err != nil || caID <= 0 {
		redirectWithFlash(w, r, page, "", "invalid CA id")
		return
	}
	if err := r.ParseForm(); err != nil {
		redirectWithFlash(w, r, page, "", "form parse error")
		return
	}
	name := r.FormValue("name")
	if name == "" {
		redirectWithFlash(w, r, page, "", "role name required")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()
	db := h.DB()
	if db == nil {
		redirectWithFlash(w, r, page, "", "db unavailable")
		return
	}
	_, err = db.ExecContext(ctx,
		"INSERT IGNORE INTO mtls_roles (ca_id, name) VALUES (?, ?)", caID, name)
	if err != nil {
		redirectWithFlash(w, r, page, "", "create role failed: "+sanitizeErr(err))
		return
	}
	redirectWithFlash(w, r, page, "Role created.", "")
}

// MTLSRoleDelete POST /admin/mtls/ca/{ca_id}/roles/{role_id}/delete - remove a role.
func (h *AdminHandlers) MTLSRoleDelete(w http.ResponseWriter, r *http.Request) {
	if h.mtlsScopeDenied(w, r) {
		return
	}
	const page = "/admin/mtls"
	roleID, err := strconv.ParseInt(chi.URLParam(r, "role_id"), 10, 64)
	if err != nil || roleID <= 0 {
		redirectWithFlash(w, r, page, "", "invalid role id")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()
	db := h.DB()
	if db == nil {
		redirectWithFlash(w, r, page, "", "db unavailable")
		return
	}
	if _, err := db.ExecContext(ctx, "DELETE FROM mtls_roles WHERE id=?", roleID); err != nil {
		redirectWithFlash(w, r, page, "", "delete role failed: "+sanitizeErr(err))
		return
	}
	redirectWithFlash(w, r, page, "Role deleted.", "")
}

// MTLSCertRoleAssign POST /admin/mtls/ca/{ca_id}/certs/{cert_id}/roles - assign a role to a cert.
func (h *AdminHandlers) MTLSCertRoleAssign(w http.ResponseWriter, r *http.Request) {
	if h.mtlsScopeDenied(w, r) {
		return
	}
	const page = "/admin/mtls"
	certID, err := strconv.ParseInt(chi.URLParam(r, "cert_id"), 10, 64)
	if err != nil || certID <= 0 {
		redirectWithFlash(w, r, page, "", "invalid cert id")
		return
	}
	if err := r.ParseForm(); err != nil {
		redirectWithFlash(w, r, page, "", "form parse error")
		return
	}
	roleID, err := strconv.ParseInt(r.FormValue("role_id"), 10, 64)
	if err != nil || roleID <= 0 {
		redirectWithFlash(w, r, page, "", "invalid role id")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()
	db := h.DB()
	if db == nil {
		redirectWithFlash(w, r, page, "", "db unavailable")
		return
	}
	_, err = db.ExecContext(ctx,
		"INSERT IGNORE INTO mtls_cert_roles (cert_id, role_id) VALUES (?, ?)", certID, roleID)
	if err != nil {
		redirectWithFlash(w, r, page, "", "assign role failed: "+sanitizeErr(err))
		return
	}
	redirectWithFlash(w, r, page, "Role assigned.", "")
}

// MTLSCertRoleRevoke POST /admin/mtls/ca/{ca_id}/certs/{cert_id}/roles/{role_id}/delete - remove role from cert.
func (h *AdminHandlers) MTLSCertRoleRevoke(w http.ResponseWriter, r *http.Request) {
	if h.mtlsScopeDenied(w, r) {
		return
	}
	const page = "/admin/mtls"
	certID, err := strconv.ParseInt(chi.URLParam(r, "cert_id"), 10, 64)
	if err != nil || certID <= 0 {
		redirectWithFlash(w, r, page, "", "invalid cert id")
		return
	}
	roleID, err := strconv.ParseInt(chi.URLParam(r, "role_id"), 10, 64)
	if err != nil || roleID <= 0 {
		redirectWithFlash(w, r, page, "", "invalid role id")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()
	db := h.DB()
	if db == nil {
		redirectWithFlash(w, r, page, "", "db unavailable")
		return
	}
	if _, err := db.ExecContext(ctx,
		"DELETE FROM mtls_cert_roles WHERE cert_id=? AND role_id=?", certID, roleID); err != nil {
		redirectWithFlash(w, r, page, "", "remove role failed: "+sanitizeErr(err))
		return
	}
	redirectWithFlash(w, r, page, "Role removed.", "")
}

// MTLSPathRuleCreate POST /admin/hosts/{id}/mtls-path-rules - add a path rule to a route.
func (h *AdminHandlers) MTLSPathRuleCreate(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)
	if err != nil || id <= 0 {
		http.Error(w, "bad id", http.StatusBadRequest)
		return
	}
	page := "/admin/hosts/" + strconv.FormatInt(id, 10) + "/edit"
	if err := r.ParseForm(); err != nil {
		redirectWithFlash(w, r, page, "", "form parse error")
		return
	}
	pattern := r.FormValue("path_pattern")
	roleIDStr := r.FormValue("role_id")
	roleID, err := strconv.ParseInt(roleIDStr, 10, 64)
	if err != nil || roleID <= 0 || pattern == "" {
		redirectWithFlash(w, r, page, "", "path and role required")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()
	db := h.DB()
	if db == nil {
		redirectWithFlash(w, r, page, "", "db unavailable")
		return
	}
	_, err = db.ExecContext(ctx,
		"INSERT INTO mtls_path_rules (route_id, path_pattern, required_role_id) VALUES (?, ?, ?)",
		id, pattern, roleID)
	if err != nil {
		redirectWithFlash(w, r, page, "", "create rule failed: "+sanitizeErr(err))
		return
	}
	redirectWithFlash(w, r, page, "Path rule added.", "")
}

// MTLSPathRuleDelete POST /admin/hosts/{id}/mtls-path-rules/{rule_id}/delete - remove a path rule.
func (h *AdminHandlers) MTLSPathRuleDelete(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)
	if err != nil || id <= 0 {
		http.Error(w, "bad id", http.StatusBadRequest)
		return
	}
	page := "/admin/hosts/" + strconv.FormatInt(id, 10) + "/edit"
	ruleID, err := strconv.ParseInt(chi.URLParam(r, "rule_id"), 10, 64)
	if err != nil || ruleID <= 0 {
		redirectWithFlash(w, r, page, "", "invalid rule id")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()
	db := h.DB()
	if db == nil {
		redirectWithFlash(w, r, page, "", "db unavailable")
		return
	}
	// WHERE route_id ensures a user can't delete another route's rule.
	if _, err := db.ExecContext(ctx,
		"DELETE FROM mtls_path_rules WHERE id=? AND route_id=?", ruleID, id); err != nil {
		redirectWithFlash(w, r, page, "", "delete rule failed: "+sanitizeErr(err))
		return
	}
	redirectWithFlash(w, r, page, "Path rule removed.", "")
}
