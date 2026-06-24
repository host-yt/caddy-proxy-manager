package handlers

import (
	"context"
	"database/sql"
	"net/http"
	"strings"
	"time"

	"github.com/hostyt/proxy-gateway/internal/audit"
	"github.com/hostyt/proxy-gateway/internal/httpserver/middleware"
)

// adminAccountData drives /admin/account. Admins always edit their own
// phone + email regardless of customer.phone_collection_enabled (that
// flag scopes only the customer-facing /app/account view).
type adminAccountData struct {
	baseAdminData
	Email string
	Phone string
}

// AdminAccountPage renders /admin/account.
func (h *AdminHandlers) AdminAccountPage(w http.ResponseWriter, r *http.Request) {
	d := adminAccountData{baseAdminData: h.base(r, "Account")}
	sess := middleware.SessionFromContext(r.Context())
	db := h.DB()
	if db == nil || sess == nil {
		h.render(w, "admin_account", d)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 3*time.Second)
	defer cancel()
	var phone sql.NullString
	_ = db.QueryRowContext(ctx,
		`SELECT email, phone_e164 FROM users WHERE id = ?`, sess.UserID).Scan(&d.Email, &phone)
	if phone.Valid {
		d.Phone = phone.String
	}
	h.render(w, "admin_account", d)
}

// AdminAccountUpdate handles POST /admin/account.
func (h *AdminHandlers) AdminAccountUpdate(w http.ResponseWriter, r *http.Request) {
	sess := middleware.SessionFromContext(r.Context())
	db := h.DB()
	if sess == nil || db == nil {
		redirectWithFlash(w, r, "/admin/account", "", "session expired")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 3*time.Second)
	defer cancel()
	phone := strings.TrimSpace(r.FormValue("phone_e164"))
	if phone != "" && !clientPhoneRe.MatchString(phone) {
		redirectWithFlash(w, r, "/admin/account", "", "phone must be E.164 (e.g. +48555111222)")
		return
	}
	var arg any
	if phone == "" {
		arg = nil
	} else {
		arg = phone
	}
	if _, err := db.ExecContext(ctx,
		`UPDATE users SET phone_e164 = ? WHERE id = ?`, arg, sess.UserID); err != nil {
		redirectWithFlash(w, r, "/admin/account", "", "save failed: "+sanitizeErr(err))
		return
	}
	uid := sess.UserID
	audit.Write(ctx, db, h.Logger, r, audit.Entry{
		UserID: &uid, Action: "admin.account.phone.update", Entity: "user",
		EntityID: itoa64(uid),
		Meta:     map[string]any{"set": phone != ""},
	})
	redirectWithFlash(w, r, "/admin/account", "Account updated", "")
}
