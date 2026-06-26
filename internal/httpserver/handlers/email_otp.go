package handlers

import (
	"context"
	"database/sql"
	"net/http"
	"strings"

	"github.com/host-yt/caddy-proxy-manager/internal/mail"
	"github.com/host-yt/caddy-proxy-manager/internal/security"
)

// otpLogoURL is the default Hostyt logo used in OTP emails. Overridden by
// branding.email_logo_url setting when present. Black on transparent - the
// template inverts on dark mode via CSS filter.
const otpLogoURL = "https://files.host.yt/graphics/logos/hostyt_logo_black.svg"

// sendOTPEmail renders + sends the otp_code template. `purpose` is the H1
// (e.g. "Sign-in verification code"); `intro` is one sentence shown above
// the code. ttlMin is rendered as "expires in N minutes".
//
// Nil-safe: returns nil if mailer is nil so callers can choose how to react
// (the login path should refuse the attempt; enrollment paths should flash).
func sendOTPEmail(ctx context.Context, m *mail.Mailer, db *sql.DB, r *http.Request,
	toEmail, name, code, purpose, intro string, ttlMin int) error {
	if m == nil {
		return errEmailNotConfigured
	}
	appName := "Hostyt Proxy"
	logoURL := otpLogoURL
	panelURL := ""
	if db != nil {
		b := LoadBranding(ctx, db)
		if b.BrandName != "" {
			appName = b.BrandName
		}
		// Prefer dark logo (typically white-on-transparent) for OTP emails so
		// it renders correctly in dark-mode clients without filter tricks.
		if b.LogoURLDark != "" {
			logoURL = b.LogoURLDark
		}
	}
	ua := ""
	if r != nil {
		ua = truncateUA(r.UserAgent())
		panelURL = panelOrigin(r)
	}
	ip := ""
	if r != nil {
		ip = security.ClientIP(r)
	}
	subject := appName + " - your verification code: " + code
	return m.Send(ctx, toEmail, subject, "otp_code", map[string]any{
		"AppName":    appName,
		"LogoURL":    logoURL,
		"PanelURL":   panelURL,
		"Name":       name,
		"Code":       code,
		"Purpose":    purpose,
		"Intro":      intro,
		"ExpiresMin": ttlMin,
		"IP":         ip,
		"UserAgent":  ua,
	})
}

func truncateUA(s string) string {
	s = strings.TrimSpace(s)
	if len(s) > 120 {
		return s[:117] + "…"
	}
	return s
}

func panelOrigin(r *http.Request) string {
	scheme := "https"
	if r.TLS == nil && r.Header.Get("X-Forwarded-Proto") != "https" {
		scheme = "http"
	}
	host := r.Host
	if host == "" {
		return ""
	}
	return scheme + "://" + host
}

type sentinelErr string

func (e sentinelErr) Error() string { return string(e) }

const errEmailNotConfigured sentinelErr = "email not configured"
