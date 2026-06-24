package handlers

import (
	"context"
	"database/sql"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/hostyt/proxy-gateway/internal/audit"
	"github.com/hostyt/proxy-gateway/internal/httpserver/middleware"
)

// Branding (panel logo / brand name / favicon / tagline) is stored in
// the same key-value settings table everything else uses. The values
// are public-by-nature (they render on the login page), so no
// encryption. A short in-memory cache keeps the per-request lookup
// off the hot path.

type Branding struct {
	BrandName    string
	Tagline      string
	LogoURLLight string // shown in light mode (default)
	LogoURLDark  string // shown in dark mode (falls back to light if empty)
	FaviconURL   string
	// Error-page skin (used by Caddy handle_errors + maintenance page).
	// Kept separate from the panel logo because the operator may want a
	// brand-coloured background and a different (e.g. all-white) logo
	// for public-facing 4xx/5xx surfaces.
	ErrorLogoURL  string
	ErrorLogoLink string
	ErrorBgColor  string
}

// LogoURL is a convenience getter for callers that only care about the
// light-mode logo (e.g. <meta og:image>). Templates that distinguish
// light vs dark read LogoURLLight / LogoURLDark directly.
func (b Branding) LogoURL() string { return b.LogoURLLight }

var (
	brandingCache   Branding
	brandingExpires time.Time
	brandingMu      sync.RWMutex
)

// LoadBranding returns the current branding, caching for ~30s.
// Caller must pass a *sql.DB that is already open; nil-safe (returns
// the zero-value Branding so the default "Hostyt Proxy" string wins
// in the templates).
func LoadBranding(ctx context.Context, db *sql.DB) Branding {
	brandingMu.RLock()
	if time.Now().Before(brandingExpires) {
		v := brandingCache
		brandingMu.RUnlock()
		return v
	}
	brandingMu.RUnlock()
	brandingMu.Lock()
	defer brandingMu.Unlock()
	if time.Now().Before(brandingExpires) {
		return brandingCache
	}
	out := Branding{}
	if db != nil {
		c, cancel := context.WithTimeout(ctx, 2*time.Second)
		defer cancel()
		rows, err := db.QueryContext(c,
			"SELECT `key`, value FROM settings WHERE `key` IN ("+
				"'branding.brand_name','branding.tagline',"+
				"'branding.logo_url','branding.logo_url_light','branding.logo_url_dark',"+
				"'branding.favicon_url',"+
				"'branding.error_logo_url','branding.error_logo_link','branding.error_bg_color')")
		if err == nil {
			defer rows.Close()
			for rows.Next() {
				var k, v string
				if err := rows.Scan(&k, &v); err != nil {
					continue
				}
				switch k {
				case "branding.brand_name":
					out.BrandName = v
				case "branding.tagline":
					out.Tagline = v
				case "branding.logo_url", "branding.logo_url_light":
					// branding.logo_url is the legacy single-URL key from
					// before the dark-mode split; keep it as a fallback for
					// the light slot so pre-upgrade rows keep rendering.
					if out.LogoURLLight == "" {
						out.LogoURLLight = v
					}
				case "branding.logo_url_dark":
					out.LogoURLDark = v
				case "branding.favicon_url":
					out.FaviconURL = v
				case "branding.error_logo_url":
					out.ErrorLogoURL = v
				case "branding.error_logo_link":
					out.ErrorLogoLink = v
				case "branding.error_bg_color":
					out.ErrorBgColor = v
				}
			}
		}
		// When the operator only supplied one logo, render the same on
		// both themes - saves them from having to upload twice for a
		// simple monochrome mark.
		if out.LogoURLDark == "" {
			out.LogoURLDark = out.LogoURLLight
		}
	}
	brandingCache = out
	brandingExpires = time.Now().Add(30 * time.Second)
	return out
}

// invalidateBranding forces the next LoadBranding to re-read the DB -
// called from the save handler so admins see their change immediately.
func invalidateBranding() {
	brandingMu.Lock()
	brandingExpires = time.Time{}
	brandingMu.Unlock()
}

type brandingData struct {
	baseAdminData
	Branding
}

// BrandingPage renders /admin/branding.
func (h *AdminHandlers) BrandingPage(w http.ResponseWriter, r *http.Request) {
	d := brandingData{baseAdminData: h.base(r, "Branding")}
	d.Branding = LoadBranding(r.Context(), h.DB())
	h.render(w, "branding", d)
}

// BrandingSave handles POST /admin/branding.
func (h *AdminHandlers) BrandingSave(w http.ResponseWriter, r *http.Request) {
	db := h.DB()
	if db == nil {
		http.Error(w, "no db", http.StatusServiceUnavailable)
		return
	}
	sess := middleware.SessionFromContext(r.Context())
	_ = r.ParseForm()
	name := strings.TrimSpace(r.FormValue("brand_name"))
	tagline := strings.TrimSpace(r.FormValue("tagline"))
	logoLight := strings.TrimSpace(r.FormValue("logo_url_light"))
	logoDark := strings.TrimSpace(r.FormValue("logo_url_dark"))
	favURL := strings.TrimSpace(r.FormValue("favicon_url"))
	errLogo := strings.TrimSpace(r.FormValue("error_logo_url"))
	errLogoLink := strings.TrimSpace(r.FormValue("error_logo_link"))
	errBg := strings.TrimSpace(r.FormValue("error_bg_color"))

	// Reject anything that isn't a normal http/https URL. The values
	// land in <img src> / <link href> on the login page, so a
	// javascript: scheme here would be an XSS sink.
	for _, u := range []string{logoLight, logoDark, favURL, errLogo, errLogoLink} {
		if u != "" && !isHTTPURL(u) {
			redirectWithFlash(w, r, "/admin/settings", "", "all URLs must be http(s)://")
			return
		}
	}
	// Background colour: accept #hex (3/6/8) or a CSS rgb(...) literal.
	// Reject anything else so we don't smuggle arbitrary CSS into the
	// inline style block of the error page.
	if errBg != "" && !isSafeCSSColor(errBg) {
		redirectWithFlash(w, r, "/admin/settings", "", "background colour must be #RGB / #RRGGBB / #RRGGBBAA or rgb()/rgba()")
		return
	}
	if len(name) > 64 {
		name = name[:64]
	}
	if len(tagline) > 128 {
		tagline = tagline[:128]
	}

	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()
	for _, kv := range []struct{ k, v string }{
		{"branding.brand_name", name},
		{"branding.tagline", tagline},
		{"branding.logo_url_light", logoLight},
		{"branding.logo_url_dark", logoDark},
		{"branding.logo_url", logoLight}, // keep legacy key in sync for old readers
		{"branding.favicon_url", favURL},
		{"branding.error_logo_url", errLogo},
		{"branding.error_logo_link", errLogoLink},
		{"branding.error_bg_color", errBg},
	} {
		if _, err := db.ExecContext(ctx,
			"INSERT INTO settings (`key`, value, is_encrypted) VALUES (?, ?, 0) "+
				"ON DUPLICATE KEY UPDATE value = VALUES(value)",
			kv.k, kv.v); err != nil {
			h.Logger.Warn("branding save", "key", kv.k, "err", err)
		}
	}
	invalidateBranding()
	audit.Write(ctx, db, h.Logger, r, audit.Entry{
		UserID: actorUserID(sess), Action: "branding.update", Entity: "settings",
		Meta: map[string]any{"name": name, "logo_light": logoLight != "", "logo_dark": logoDark != "", "favicon": favURL != ""},
	})
	redirectWithFlash(w, r, "/admin/settings", "Branding saved", "")
}

func isHTTPURL(s string) bool {
	u, err := url.Parse(s)
	if err != nil {
		return false
	}
	return (u.Scheme == "http" || u.Scheme == "https") && u.Host != ""
}

// isSafeCSSColor permits the narrow subset we splice into inline <style>
// of the Caddy-served error page. Anything else (url(), expression(),
// shell of any kind) is rejected so the colour field can't be used as
// an XSS sink.
func isSafeCSSColor(s string) bool {
	if len(s) > 32 {
		return false
	}
	// #RGB / #RRGGBB / #RRGGBBAA
	if strings.HasPrefix(s, "#") {
		rest := s[1:]
		if len(rest) != 3 && len(rest) != 6 && len(rest) != 8 {
			return false
		}
		for _, c := range rest {
			if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')) {
				return false
			}
		}
		return true
	}
	// rgb(...) / rgba(...) - numbers + commas + dots + spaces + percent.
	lower := strings.ToLower(s)
	if strings.HasPrefix(lower, "rgb(") || strings.HasPrefix(lower, "rgba(") {
		if !strings.HasSuffix(lower, ")") {
			return false
		}
		inner := strings.TrimSuffix(strings.SplitN(lower, "(", 2)[1], ")")
		for _, c := range inner {
			if !((c >= '0' && c <= '9') || c == ',' || c == ' ' || c == '.' || c == '%') {
				return false
			}
		}
		return true
	}
	return false
}
