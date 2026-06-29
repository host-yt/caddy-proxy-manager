package handlers

import (
	"context"
	"database/sql"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/host-yt/caddy-proxy-manager/internal/audit"
	"github.com/host-yt/caddy-proxy-manager/internal/auth"
	"github.com/host-yt/caddy-proxy-manager/internal/httpserver/middleware"
	"github.com/host-yt/caddy-proxy-manager/internal/store"
)

// EmailOTPStart sends an enrollment code to the customer's email.
func (h *ClientHandlers) EmailOTPStart(w http.ResponseWriter, r *http.Request) {
	sess := middleware.SessionFromContext(r.Context())
	db := h.DB()
	if sess == nil || db == nil {
		http.Redirect(w, r, "/auth/login", http.StatusSeeOther)
		return
	}
	if h.Mailer == nil {
		redirectWithFlash(w, r, "/app/2fa", "", "Email is not configured.")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 12*time.Second)
	defer cancel()

	var email string
	var fullName sql.NullString
	_ = db.QueryRowContext(ctx, "SELECT email, full_name FROM users WHERE id = ?", sess.UserID).
		Scan(&email, &fullName)
	if email == "" {
		redirectWithFlash(w, r, "/app/2fa", "", "no email on account")
		return
	}
	code, err := auth.GenerateEmailOTP()
	if err != nil {
		redirectWithFlash(w, r, "/app/2fa", "", "internal error")
		return
	}
	hash := auth.EmailOTPHash(code)
	if _, err := db.ExecContext(ctx,
		"UPDATE users SET email_otp_pending_hash = ?, email_otp_pending_exp = "+store.DateAddMinutes(10)+" WHERE id = ?",
		hash, sess.UserID); err != nil {
		redirectWithFlash(w, r, "/app/2fa", "", "internal error")
		return
	}
	name := ""
	if fullName.Valid {
		name = fullName.String
	}
	if err := sendOTPEmail(ctx, h.Mailer, db, r, email, name, code,
		"Email 2FA setup code",
		"To activate Email two-factor authentication, enter this code in the panel.",
		10); err != nil {
		redirectWithFlash(w, r, "/app/2fa", "", "Failed to send email: "+sanitizeErr(err))
		return
	}
	uid := sess.UserID
	audit.Write(ctx, db, h.Logger, r, audit.Entry{
		UserID: &uid, Action: "2fa.email.enroll.start", Entity: "user", EntityID: fmt.Sprintf("%d", uid),
	})
	d := clientTwofaData{baseAppData: h.base(r, "Two-factor authentication")}
	d.EmailOTPEnrolling = true
	d.HasMailer = true
	h.render(w, "twofa", d)
}

// EmailOTPConfirm verifies the enrollment code and sets email_otp_enabled=1.
func (h *ClientHandlers) EmailOTPConfirm(w http.ResponseWriter, r *http.Request) {
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
		"SELECT email_otp_pending_hash, email_otp_pending_exp FROM users WHERE id = ?", sess.UserID,
	).Scan(&storedHash, &exp)
	if !storedHash.Valid || storedHash.String == "" {
		redirectWithFlash(w, r, "/app/2fa", "", "No pending email code. Start again.")
		return
	}
	if !exp.Valid || time.Now().After(exp.Time) {
		redirectWithFlash(w, r, "/app/2fa", "", "Code expired. Start again.")
		return
	}
	if auth.EmailOTPHash(code) != storedHash.String {
		redirectWithFlash(w, r, "/app/2fa", "", "Invalid code.")
		return
	}
	if _, err := db.ExecContext(ctx,
		"UPDATE users SET email_otp_enabled = 1, email_otp_pending_hash = NULL, email_otp_pending_exp = NULL WHERE id = ?",
		sess.UserID); err != nil {
		redirectWithFlash(w, r, "/app/2fa", "", "save failed")
		return
	}
	uid := sess.UserID
	audit.Write(ctx, db, h.Logger, r, audit.Entry{
		UserID: &uid, Action: "2fa.email.enroll.complete", Entity: "user", EntityID: fmt.Sprintf("%d", uid),
	})
	redirectWithFlash(w, r, "/app/2fa", "Email 2FA enabled.", "")
}

// EmailOTPDisable turns off Email OTP for the customer.
func (h *ClientHandlers) EmailOTPDisable(w http.ResponseWriter, r *http.Request) {
	sess := middleware.SessionFromContext(r.Context())
	db := h.DB()
	if sess == nil || db == nil {
		http.Redirect(w, r, "/auth/login", http.StatusSeeOther)
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
	redirectWithFlash(w, r, "/app/2fa", "Email 2FA disabled.", "")
}
