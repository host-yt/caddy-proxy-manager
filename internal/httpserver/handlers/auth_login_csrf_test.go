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

	"github.com/host-yt/caddy-proxy-manager/internal/view"
)

func TestLoginRequiresDoubleSubmitToken(t *testing.T) {
	tpls, err := view.LoadAuthTemplates()
	if err != nil {
		t.Fatal(err)
	}
	h := &AuthHandlers{
		DB:        func() *sql.DB { return nil },
		Logger:    slog.New(slog.NewTextHandler(io.Discard, nil)),
		Templates: tpls,
	}

	w := httptest.NewRecorder()
	h.LoginPage(w, httptest.NewRequest(http.MethodGet, "/auth/login", nil))
	var ck *http.Cookie
	for _, c := range w.Result().Cookies() {
		if c.Name == loginCSRFCookie {
			ck = c
		}
	}
	if ck == nil || ck.Value == "" {
		t.Fatal("login page did not set the login CSRF cookie")
	}
	if !strings.Contains(w.Body.String(), `name="csrf_token" value="`+ck.Value+`"`) {
		t.Fatal("login form does not carry the cookie's token")
	}

	// Empty password: passing the CSRF gate lands on the 400 validation error.
	post := func(token string, withCookie bool) int {
		form := url.Values{"email": {"a@example.com"}, "password": {""}, "csrf_token": {token}}
		r := httptest.NewRequest(http.MethodPost, "/auth/login", strings.NewReader(form.Encode()))
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		if withCookie {
			r.AddCookie(ck)
		}
		w := httptest.NewRecorder()
		h.LoginSubmit(w, r)
		return w.Code
	}
	if got := post(ck.Value, false); got != http.StatusForbidden {
		t.Errorf("no cookie: got %d, want 403", got)
	}
	if got := post("forged", true); got != http.StatusForbidden {
		t.Errorf("mismatched token: got %d, want 403", got)
	}
	if got := post(ck.Value, true); got != http.StatusBadRequest {
		t.Errorf("valid token: got %d, want 400 (past CSRF gate)", got)
	}
}
