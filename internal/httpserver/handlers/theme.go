package handlers

import (
	"net/http"
	"net/url"
	"strings"
)

// Palette theme slugs, separate from the light/dark mode mechanism.
// Order matters for the picker; display names live in the template.
const themeCookie = "ui_theme"

const defaultTheme = "default"

// validThemes is the single source of truth for allowed palette slugs.
// A cookie value is only ever trusted if it is one of these - the slug is
// rendered into <html data-theme="...">, so unvalidated input must never leak.
var validThemes = map[string]bool{
	"default":  true,
	"midnight": true,
	"ocean":    true,
	"forest":   true,
	"violet":   true,
	"sunset":   true,
	"nord":     true,
	"mono":     true,
}

// validThemeSlug returns s if it is a known slug, else "default".
func validThemeSlug(s string) string {
	s = strings.TrimSpace(s)
	if validThemes[s] {
		return s
	}
	return defaultTheme
}

// themeFromRequest reads + validates the palette cookie, defaulting to "default".
func themeFromRequest(r *http.Request) string {
	if r == nil {
		return defaultTheme
	}
	if c, err := r.Cookie(themeCookie); err == nil {
		return validThemeSlug(c.Value)
	}
	return defaultTheme
}

// setThemeCookie writes the validated palette as a year-long cookie. Not
// HttpOnly on purpose: the client bootstrap reads it for instant switch and
// the slug is not a secret.
func setThemeCookie(w http.ResponseWriter, slug string) {
	if !validThemes[slug] {
		return
	}
	http.SetCookie(w, &http.Cookie{
		Name:     themeCookie,
		Value:    slug,
		Path:     "/",
		HttpOnly: false,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   365 * 24 * 3600,
	})
}

// ThemeSwitch sets the palette cookie and redirects back. Mirrors LangSwitch.
// Wired at GET /theme/{slug}. Unknown slugs are ignored (no cookie written).
func ThemeSwitch(w http.ResponseWriter, r *http.Request) {
	slug := strings.TrimSpace(strings.TrimPrefix(r.URL.Path, "/theme/"))
	if validThemes[slug] {
		setThemeCookie(w, slug)
	}
	// Only honour a same-origin Referer to avoid open-redirect. Default to "/"
	// so the root handler routes non-admin roles to their correct home.
	dest := "/"
	if ref := r.Header.Get("Referer"); ref != "" {
		if u, err := url.Parse(ref); err == nil && u.Host == r.Host {
			dest = u.RequestURI()
		}
	}
	http.Redirect(w, r, dest, http.StatusSeeOther)
}
