package i18n

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestTranslation(t *testing.T) {
	if got := T(LangEN, "nav.dashboard"); got != "Dashboard" {
		t.Errorf("en/nav.dashboard = %q", got)
	}
	if got := T(LangPL, "nav.dashboard"); got != "Pulpit" {
		t.Errorf("pl/nav.dashboard = %q", got)
	}
	if got := T(LangPL, "no.such.key"); got != "no.such.key" {
		t.Errorf("unknown key should fallback to itself, got %q", got)
	}
	if got := T("xx", "nav.dashboard"); got != "Dashboard" {
		t.Errorf("unknown lang should fall back to en, got %q", got)
	}
}

func TestLangFromRequest(t *testing.T) {
	cases := []struct {
		name   string
		setup  func(*http.Request)
		expect string
	}{
		{"query wins", func(r *http.Request) {
			r.URL.RawQuery = "lang=pl"
		}, "pl"},
		{"cookie next", func(r *http.Request) {
			r.AddCookie(&http.Cookie{Name: "hpg_lang", Value: "pl"})
		}, "pl"},
		{"accept-language", func(r *http.Request) {
			r.Header.Set("Accept-Language", "pl-PL,pl;q=0.9,en;q=0.8")
		}, "pl"},
		{"default en", func(_ *http.Request) {}, "en"},
		{"unsupported falls back", func(r *http.Request) {
			r.Header.Set("Accept-Language", "fr-FR,de;q=0.5")
		}, "en"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			r := httptest.NewRequest("GET", "/", nil)
			c.setup(r)
			got := LangFromRequest(r)
			if got != c.expect {
				t.Errorf("want %q, got %q", c.expect, got)
			}
		})
	}
}
