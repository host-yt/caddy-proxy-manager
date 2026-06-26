package handlers

import (
	"net/http"
	"net/url"
	"strings"

	"github.com/host-yt/caddy-proxy-manager/internal/i18n"
)

// LangSwitch sets the language cookie and redirects to the referer (or /).
// Wired at GET /lang/{code}.
func LangSwitch(w http.ResponseWriter, r *http.Request) {
	code := strings.TrimPrefix(r.URL.Path, "/lang/")
	code = strings.TrimSpace(code)
	i18n.SetLangCookie(w, code)
	// Only honour a same-origin Referer to avoid open-redirect (mirror ThemeSwitch).
	dest := "/"
	if ref := r.Header.Get("Referer"); ref != "" {
		if u, err := url.Parse(ref); err == nil && u.Host == r.Host {
			dest = u.RequestURI()
		}
	}
	http.Redirect(w, r, dest, http.StatusSeeOther)
}
