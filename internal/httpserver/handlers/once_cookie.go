package handlers

import (
	"net/http"

	"github.com/host-yt/caddy-proxy-manager/internal/auth"
)

// Values shown once after a POST (bootstrap tokens, fresh secrets) travel in a
// short-lived cookie, not the redirect URL: query strings end up in browser
// history and proxy access logs, cookies are redacted there.
const onceCookieTTL = 120

func setOnceCookie(w http.ResponseWriter, r *http.Request, sm *auth.Manager, name, path, val string) {
	http.SetCookie(w, &http.Cookie{
		Name: name, Value: val, Path: path, MaxAge: onceCookieTTL, HttpOnly: true,
		Secure: sm != nil && sm.SecureForRequest(r), SameSite: http.SameSiteStrictMode,
	})
}

// takeOnceCookie returns the value and clears the cookie so a reload does not show it again.
func takeOnceCookie(w http.ResponseWriter, r *http.Request, sm *auth.Manager, name, path string) string {
	c, err := r.Cookie(name)
	if err != nil || c.Value == "" {
		return ""
	}
	http.SetCookie(w, &http.Cookie{
		Name: name, Value: "", Path: path, MaxAge: -1, HttpOnly: true,
		Secure: sm != nil && sm.SecureForRequest(r), SameSite: http.SameSiteStrictMode,
	})
	return c.Value
}
