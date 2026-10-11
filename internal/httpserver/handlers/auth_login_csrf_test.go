package handlers

import (
	"database/sql"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/host-yt/caddy-proxy-manager/internal/installstate"
	"github.com/host-yt/caddy-proxy-manager/internal/view"
)

func newLoginCSRFHandlers(t *testing.T, secret string) *AuthHandlers {
	t.Helper()
	tpls, err := view.LoadAuthTemplates()
	if err != nil {
		t.Fatal(err)
	}
	st, err := installstate.New(t.TempDir(), strings.Repeat(secret, 32))
	if err != nil {
		t.Fatal(err)
	}
	return &AuthHandlers{
		DB:        func() *sql.DB { return nil },
		Logger:    slog.New(slog.NewTextHandler(io.Discard, nil)),
		Templates: tpls,
		State:     st,
	}
}

func loginCSRFCookieFrom(w *httptest.ResponseRecorder) *http.Cookie {
	for _, c := range w.Result().Cookies() {
		if c.Name == loginCSRFCookie {
			return c
		}
	}
	return nil
}

// postLogin submits an empty password: passing the CSRF gate lands on the 400
// validation error.
func postLogin(h *AuthHandlers, token string, ck *http.Cookie) *httptest.ResponseRecorder {
	form := url.Values{"email": {"a@example.com"}, "password": {""}, "csrf_token": {token}}
	r := httptest.NewRequest(http.MethodPost, "/auth/login", strings.NewReader(form.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if ck != nil {
		r.AddCookie(ck)
	}
	w := httptest.NewRecorder()
	h.LoginSubmit(w, r)
	return w
}

func TestLoginRequiresDoubleSubmitToken(t *testing.T) {
	h := newLoginCSRFHandlers(t, "a")
	w := httptest.NewRecorder()
	h.LoginPage(w, httptest.NewRequest(http.MethodGet, "/auth/login", nil))
	ck := loginCSRFCookieFrom(w)
	if ck == nil || ck.Value == "" {
		t.Fatal("login page did not set the login CSRF cookie")
	}
	if !strings.Contains(w.Body.String(), `name="csrf_token" value="`+ck.Value+`"`) {
		t.Fatal("login form does not carry the cookie's token")
	}

	if got := postLogin(h, ck.Value, nil).Code; got != http.StatusForbidden {
		t.Errorf("no cookie: got %d, want 403", got)
	}
	if got := postLogin(h, "forged", ck).Code; got != http.StatusForbidden {
		t.Errorf("mismatched token: got %d, want 403", got)
	}
	if got := postLogin(h, ck.Value, ck).Code; got != http.StatusBadRequest {
		t.Errorf("valid token: got %d, want 400 (past CSRF gate)", got)
	}

	// A second tab reuses the signed token instead of rotating it.
	r := httptest.NewRequest(http.MethodGet, "/auth/login", nil)
	r.AddCookie(ck)
	w = httptest.NewRecorder()
	h.LoginPage(w, r)
	if loginCSRFCookieFrom(w) != nil || !strings.Contains(w.Body.String(), `value="`+ck.Value+`"`) {
		t.Error("valid cookie was not reused")
	}
}

// A cookie tossed from a sibling subdomain must not pass unless the server signed it.
func TestLoginCSRFRejectsUnsignedAndForeignTokens(t *testing.T) {
	h := newLoginCSRFHandlers(t, "a")
	other := newLoginCSRFHandlers(t, "b")
	w := httptest.NewRecorder()
	other.LoginPage(w, httptest.NewRequest(http.MethodGet, "/auth/login", nil))
	foreign := loginCSRFCookieFrom(w)

	for name, tok := range map[string]string{
		"unsigned":    strings.Repeat("A", 43),
		"unsigned-86": strings.Repeat("A", 86),
		"other key":   foreign.Value,
	} {
		w := postLogin(h, tok, &http.Cookie{Name: loginCSRFCookie, Value: tok})
		if w.Code != http.StatusForbidden {
			t.Errorf("%s: got %d, want 403", name, w.Code)
		}
		fresh := loginCSRFCookieFrom(w)
		if fresh == nil || fresh.Value == tok || !validLoginCSRF(h.loginCSRFKey(), fresh.Value) {
			t.Errorf("%s: 403 did not issue a fresh signed token", name)
		}
	}
}
