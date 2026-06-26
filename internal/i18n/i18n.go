// Package i18n is a small message-catalog helper used by templates. It
// keeps two static maps (en + pl) and falls back to the key itself when a
// translation is missing. Selection comes from:
//
//  1. URL query ?lang=pl (sets cookie, redirects to clean URL).
//  2. Cookie hpg_lang.
//  3. Accept-Language header first match (en/pl only).
//  4. Default: en.
//
// Templates call `{{T .Lang "login.title"}}`. Adding a language = adding a
// new map. The catalog is intentionally tiny; we localise prominent labels
// + error strings only. Long-form copy (legal docs, customer docs) lives
// in DB or markdown files served separately.
package i18n

import (
	"net/http"
	"strings"
)

const (
	LangEN = "en"
	LangPL = "pl"
)

var supported = map[string]bool{LangEN: true, LangPL: true}

// Catalog: key → per-lang text. Missing key falls back to the key itself.
var catalog = map[string]map[string]string{
	LangEN: {
		"nav.dashboard":        "Dashboard",
		"nav.routes":           "Routes",
		"nav.services":         "Services",
		"nav.clients":          "Clients",
		"nav.plans":            "Plans",
		"nav.nodes":            "Caddy nodes",
		"nav.users":            "Users",
		"nav.api_keys":         "API keys",
		"apikeys.last_used_ip": "Last IP",
		"apikeys.scopes":       "Scopes",
		"apikeys.auth_failure": "Auth failure",
		"nav.audit":            "Audit log",
		"nav.backups":          "Backups",
		"nav.settings":         "Settings",
		"nav.signout":          "Sign out",
		"login.title":          "Sign in",
		"login.email":          "Email",
		"login.password":       "Password",
		"login.submit":         "Sign in",
		"login.forgot":         "Forgot password",
		"err.bad_login":        "Invalid email or password.",
		"err.captcha":          "Captcha verification failed.",
		"err.too_many":         "Too many failed attempts. Try again later.",
		"route.new":            "New route",
		"route.domain":         "Domain",
		"route.port":           "Upstream port",
		"route.verify_dns":     "Verify DNS",
		"route.delete":         "Delete",
		"backup.run_now":       "Run now",
		"backup.test":          "Test",
		"backup.delete":        "Delete",
		"common.save":          "Save",
		"common.cancel":        "Cancel",
		"common.delete":        "Delete",
		"common.confirm":       "Confirm",
	},
	LangPL: {
		"nav.dashboard":        "Pulpit",
		"nav.routes":           "Trasy",
		"nav.services":         "Usługi",
		"nav.clients":          "Klienci",
		"nav.plans":            "Plany",
		"nav.nodes":            "Węzły Caddy",
		"nav.users":            "Użytkownicy",
		"nav.api_keys":         "Klucze API",
		"apikeys.last_used_ip": "Ostatnie IP",
		"apikeys.scopes":       "Zakresy",
		"apikeys.auth_failure": "Błąd uwierzytelnienia",
		"nav.audit":            "Dziennik audytu",
		"nav.backups":          "Kopie zapasowe",
		"nav.settings":         "Ustawienia",
		"nav.signout":          "Wyloguj",
		"login.title":          "Zaloguj się",
		"login.email":          "Email",
		"login.password":       "Hasło",
		"login.submit":         "Zaloguj się",
		"login.forgot":         "Zapomniałem hasła",
		"err.bad_login":        "Nieprawidłowy email lub hasło.",
		"err.captcha":          "Weryfikacja Captcha nie powiodła się.",
		"err.too_many":         "Zbyt wiele nieudanych prób. Spróbuj później.",
		"route.new":            "Nowa trasa",
		"route.domain":         "Domena",
		"route.port":           "Port backendu",
		"route.verify_dns":     "Sprawdź DNS",
		"route.delete":         "Usuń",
		"backup.run_now":       "Uruchom teraz",
		"backup.test":          "Testuj",
		"backup.delete":        "Usuń",
		"common.save":          "Zapisz",
		"common.cancel":        "Anuluj",
		"common.delete":        "Usuń",
		"common.confirm":       "Potwierdź",
	},
}

// T translates `key` into the given language. Falls back to en, then key.
func T(lang, key string) string {
	if m, ok := catalog[lang]; ok {
		if v, ok := m[key]; ok {
			return v
		}
	}
	if v, ok := catalog[LangEN][key]; ok {
		return v
	}
	return key
}

// LangFromRequest returns the selected language using the rules described
// in the package doc.
func LangFromRequest(r *http.Request) string {
	if r == nil {
		return LangEN
	}
	if q := strings.ToLower(r.URL.Query().Get("lang")); supported[q] {
		return q
	}
	if c, err := r.Cookie("hpg_lang"); err == nil && supported[c.Value] {
		return c.Value
	}
	for _, part := range strings.Split(r.Header.Get("Accept-Language"), ",") {
		code := strings.ToLower(strings.SplitN(strings.TrimSpace(part), ";", 2)[0])
		if i := strings.IndexByte(code, '-'); i > 0 {
			code = code[:i]
		}
		if supported[code] {
			return code
		}
	}
	return LangEN
}

// SetLangCookie writes the chosen language as a year-long cookie. Caller
// is responsible for redirecting / re-rendering after.
func SetLangCookie(w http.ResponseWriter, lang string) {
	if !supported[lang] {
		return
	}
	http.SetCookie(w, &http.Cookie{
		Name:     "hpg_lang",
		Value:    lang,
		Path:     "/",
		HttpOnly: false,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   365 * 24 * 3600,
	})
}
