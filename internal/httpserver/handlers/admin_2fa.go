package handlers

import (
	"context"
	"database/sql"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/redis/go-redis/v9"

	"github.com/host-yt/caddy-proxy-manager/internal/audit"
	"github.com/host-yt/caddy-proxy-manager/internal/auth"
	"github.com/host-yt/caddy-proxy-manager/internal/httpserver/middleware"
	"github.com/host-yt/caddy-proxy-manager/internal/store"
)

// TwoFARequired renders the "you must enroll 2FA" interstitial shown by the
// RequireAdmin2FA middleware. The original destination is read from the ?next=
// query or the Redis setup_next key so enrollment can return the user there.
func (h *AdminHandlers) TwoFARequired(w http.ResponseWriter, r *http.Request) {
	sess := middleware.SessionFromContext(r.Context())
	next := r.URL.Query().Get("next")
	if next == "" && h.RDB != nil && sess != nil {
		next, _ = h.RDB.Get(r.Context(), fmt.Sprintf("hpg:2fa:setup_next:%d", sess.UserID)).Result()
	}
	type twoFARequiredData struct {
		baseAdminData
		Next string
	}
	d := twoFARequiredData{baseAdminData: h.base(r, "2FA required"), Next: next}
	h.render(w, "2fa_required", d)
}

// postEnrollRedirect consumes the pending setup_next destination (set by the
// 2FA-required middleware) and returns where to send the user after enrolling.
func postEnrollRedirect(ctx context.Context, rdb *redis.Client, userID int64) string {
	if rdb == nil {
		return "/admin/2fa"
	}
	dest, err := rdb.GetDel(ctx, fmt.Sprintf("hpg:2fa:setup_next:%d", userID)).Result()
	if err != nil || dest == "" {
		return "/admin/2fa"
	}
	return dest
}

// Extended TwoFAPage state (SMS + Email) is filled here. TwoFAStart /
// TwoFAConfirm / TwoFADisable (TOTP) stay in admin.go for now.

// loadAdminTwoFAState loads SMS + Email + phone columns onto the page data.
func (h *AdminHandlers) loadAdminTwoFAState(ctx context.Context, db *sql.DB, userID int64) (
	totp, smsOK, emailOK bool, phone string,
) {
	var p sql.NullString
	_ = db.QueryRowContext(ctx,
		"SELECT totp_enabled, sms_otp_enabled, email_otp_enabled, phone_e164 FROM users WHERE id = ?",
		userID,
	).Scan(&totp, &smsOK, &emailOK, &p)
	if p.Valid {
		phone = p.String
	}
	return
}

// ---- SMS 2FA enrollment (admin) ----------------------------------------

// AdminSMSOTPStart sends a confirmation SMS to the admin's phone.
func (h *AdminHandlers) AdminSMSOTPStart(w http.ResponseWriter, r *http.Request) {
	sess := middleware.SessionFromContext(r.Context())
	db := h.DB()
	if sess == nil || db == nil {
		redirectWithFlash(w, r, "/admin/2fa", "", "session expired")
		return
	}
	if h.SMS == nil {
		redirectWithFlash(w, r, "/admin/2fa", "", "SMS not configured. Configure under Settings → SMS.")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 8*time.Second)
	defer cancel()

	var phone sql.NullString
	_ = db.QueryRowContext(ctx, "SELECT phone_e164 FROM users WHERE id = ?", sess.UserID).Scan(&phone)
	if !phone.Valid || phone.String == "" {
		redirectWithFlash(w, r, "/admin/2fa", "", "Set your phone in Account first.")
		return
	}

	code, err := auth.GenerateSMSOTP()
	if err != nil {
		redirectWithFlash(w, r, "/admin/2fa", "", "internal error")
		return
	}
	hash := auth.SMSOTPHash(code)
	if _, err := db.ExecContext(ctx,
		"UPDATE users SET sms_otp_pending_hash = ?, sms_otp_pending_exp = "+store.DateAddMinutes(5)+" WHERE id = ?",
		hash, sess.UserID); err != nil {
		redirectWithFlash(w, r, "/admin/2fa", "", "internal error")
		return
	}
	// Push fresh decrypted secrets into the in-memory Sender before sending.
	secrets := h.loadSettings(ctx, db, []string{
		"sms.twilio_auth_token", "sms.smsapi_token",
		"sms.bulkgate_app_token", "sms.webhook_token",
	})
	h.SMS.SetSecrets(secrets["sms.twilio_auth_token"],
		secrets["sms.smsapi_token"],
		secrets["sms.bulkgate_app_token"],
		secrets["sms.webhook_token"])
	if err := h.SMS.Send(ctx, phone.String,
		fmt.Sprintf("Your Hostyt Proxy SMS 2FA setup code: %s", code)); err != nil {
		redirectWithFlash(w, r, "/admin/2fa", "", "Failed to send SMS: "+sanitizeErr(err))
		return
	}
	uid := sess.UserID
	audit.Write(ctx, db, h.Logger, r, audit.Entry{
		UserID: &uid, Action: "2fa.sms.enroll.start", Entity: "user", EntityID: fmt.Sprintf("%d", uid),
	})
	d := twofaData{baseAdminData: h.base(r, "Two-factor auth")}
	d.HasPhone = true
	d.SMSOTPEnrolling = true
	h.render(w, "twofa", d)
}

// AdminSMSOTPConfirm verifies the enrollment code and sets sms_otp_enabled=1.
func (h *AdminHandlers) AdminSMSOTPConfirm(w http.ResponseWriter, r *http.Request) {
	sess := middleware.SessionFromContext(r.Context())
	db := h.DB()
	if sess == nil || db == nil {
		redirectWithFlash(w, r, "/admin/2fa", "", "session expired")
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
		redirectWithFlash(w, r, "/admin/2fa", "", "No pending SMS code. Start again.")
		return
	}
	if !exp.Valid || time.Now().After(exp.Time) {
		redirectWithFlash(w, r, "/admin/2fa", "", "Code expired. Start again.")
		return
	}
	if auth.SMSOTPHash(code) != storedHash.String {
		redirectWithFlash(w, r, "/admin/2fa", "", "Invalid code.")
		return
	}
	if _, err := db.ExecContext(ctx,
		"UPDATE users SET sms_otp_enabled = 1, sms_otp_pending_hash = NULL, sms_otp_pending_exp = NULL WHERE id = ?",
		sess.UserID); err != nil {
		redirectWithFlash(w, r, "/admin/2fa", "", "save failed")
		return
	}
	uid := sess.UserID
	audit.Write(ctx, db, h.Logger, r, audit.Entry{
		UserID: &uid, Action: "2fa.sms.enroll.complete", Entity: "user", EntityID: fmt.Sprintf("%d", uid),
	})
	middleware.InvalidateAdmin2FACache(ctx, h.RDB, uid)
	redirectWithFlash(w, r, postEnrollRedirect(ctx, h.RDB, uid), "SMS 2FA enabled.", "")
}

// AdminSMSOTPDisable turns off SMS OTP for the admin.
func (h *AdminHandlers) AdminSMSOTPDisable(w http.ResponseWriter, r *http.Request) {
	sess := middleware.SessionFromContext(r.Context())
	db := h.DB()
	if sess == nil || db == nil {
		redirectWithFlash(w, r, "/admin/2fa", "", "session expired")
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
	middleware.InvalidateAdmin2FACache(ctx, h.RDB, uid)
	redirectWithFlash(w, r, "/admin/2fa", "SMS 2FA disabled.", "")
}

// ---- Email 2FA enrollment (admin) --------------------------------------

// AdminEmailOTPStart sends an enrollment code to the admin's email.
func (h *AdminHandlers) AdminEmailOTPStart(w http.ResponseWriter, r *http.Request) {
	sess := middleware.SessionFromContext(r.Context())
	db := h.DB()
	if sess == nil || db == nil {
		redirectWithFlash(w, r, "/admin/2fa", "", "session expired")
		return
	}
	if h.Mailer == nil {
		redirectWithFlash(w, r, "/admin/2fa", "", "SMTP not configured. Configure under Settings → SMTP.")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 12*time.Second)
	defer cancel()

	var email string
	var fullName sql.NullString
	_ = db.QueryRowContext(ctx, "SELECT email, full_name FROM users WHERE id = ?", sess.UserID).
		Scan(&email, &fullName)
	if email == "" {
		redirectWithFlash(w, r, "/admin/2fa", "", "no email on account")
		return
	}
	code, err := auth.GenerateEmailOTP()
	if err != nil {
		redirectWithFlash(w, r, "/admin/2fa", "", "internal error")
		return
	}
	hash := auth.EmailOTPHash(code)
	if _, err := db.ExecContext(ctx,
		"UPDATE users SET email_otp_pending_hash = ?, email_otp_pending_exp = "+store.DateAddMinutes(10)+" WHERE id = ?",
		hash, sess.UserID); err != nil {
		redirectWithFlash(w, r, "/admin/2fa", "", "internal error")
		return
	}
	name := ""
	if fullName.Valid {
		name = fullName.String
	}
	if err := sendOTPEmail(ctx, h.Mailer, db, r, email, name, code,
		"Email 2FA setup code",
		"To activate Email two-factor authentication on your account, enter this code in the panel.",
		10); err != nil {
		redirectWithFlash(w, r, "/admin/2fa", "", "Failed to send email: "+sanitizeErr(err))
		return
	}
	uid := sess.UserID
	audit.Write(ctx, db, h.Logger, r, audit.Entry{
		UserID: &uid, Action: "2fa.email.enroll.start", Entity: "user", EntityID: fmt.Sprintf("%d", uid),
	})
	d := twofaData{baseAdminData: h.base(r, "Two-factor auth")}
	d.EmailOTPEnrolling = true
	h.render(w, "twofa", d)
}

// AdminEmailOTPConfirm verifies the enrollment code and sets email_otp_enabled=1.
func (h *AdminHandlers) AdminEmailOTPConfirm(w http.ResponseWriter, r *http.Request) {
	sess := middleware.SessionFromContext(r.Context())
	db := h.DB()
	if sess == nil || db == nil {
		redirectWithFlash(w, r, "/admin/2fa", "", "session expired")
		return
	}
	_ = r.ParseForm()
	code := strings.TrimSpace(r.FormValue("code"))
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()

	var storedHash sql.NullString
	var exp sql.NullTime
	_ = db.QueryRowContext(ctx,
		"SELECT email_otp_pending_hash, email_otp_pending_exp FROM users WHERE id = ?", sess.UserID,
	).Scan(&storedHash, &exp)
	if !storedHash.Valid || storedHash.String == "" {
		redirectWithFlash(w, r, "/admin/2fa", "", "No pending email code. Start again.")
		return
	}
	if !exp.Valid || time.Now().After(exp.Time) {
		redirectWithFlash(w, r, "/admin/2fa", "", "Code expired. Start again.")
		return
	}
	if auth.EmailOTPHash(code) != storedHash.String {
		redirectWithFlash(w, r, "/admin/2fa", "", "Invalid code.")
		return
	}
	if _, err := db.ExecContext(ctx,
		"UPDATE users SET email_otp_enabled = 1, email_otp_pending_hash = NULL, email_otp_pending_exp = NULL WHERE id = ?",
		sess.UserID); err != nil {
		redirectWithFlash(w, r, "/admin/2fa", "", "save failed")
		return
	}
	uid := sess.UserID
	audit.Write(ctx, db, h.Logger, r, audit.Entry{
		UserID: &uid, Action: "2fa.email.enroll.complete", Entity: "user", EntityID: fmt.Sprintf("%d", uid),
	})
	middleware.InvalidateAdmin2FACache(ctx, h.RDB, uid)
	redirectWithFlash(w, r, postEnrollRedirect(ctx, h.RDB, uid), "Email 2FA enabled.", "")
}

// AdminEmailOTPDisable turns off Email OTP for the admin.
func (h *AdminHandlers) AdminEmailOTPDisable(w http.ResponseWriter, r *http.Request) {
	sess := middleware.SessionFromContext(r.Context())
	db := h.DB()
	if sess == nil || db == nil {
		redirectWithFlash(w, r, "/admin/2fa", "", "session expired")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()
	_, _ = db.ExecContext(ctx,
		"UPDATE users SET email_otp_enabled = 0, email_otp_pending_hash = NULL, email_otp_pending_exp = NULL WHERE id = ?",
		sess.UserID)
	uid := sess.UserID
	audit.Write(ctx, db, h.Logger, r, audit.Entry{
		UserID: &uid, Action: "2fa.email.disable", Entity: "user", EntityID: fmt.Sprintf("%d", uid),
	})
	middleware.InvalidateAdmin2FACache(ctx, h.RDB, uid)
	redirectWithFlash(w, r, "/admin/2fa", "Email 2FA disabled.", "")
}
