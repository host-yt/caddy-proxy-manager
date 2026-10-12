package handlers

import (
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/host-yt/caddy-proxy-manager/internal/mail"
)

func postClientCreate(h *AdminHandlers, password string) string {
	form := url.Values{"display_name": {"Acme"}, "email": {"a@acme.test"}, "password": {password}}
	req := httptest.NewRequest("POST", "/admin/clients", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	h.ClientsCreate(rec, req)
	return rec.Header().Get("Location")
}

// Empty password without SMTP must be rejected; a short one always.
func TestClientsCreateInviteNeedsSMTP(t *testing.T) {
	db := openLimitedAdminDB(t)
	if _, err := db.Exec("CREATE TABLE settings (`key` TEXT, value TEXT, is_encrypted INTEGER)"); err != nil {
		t.Fatal(err)
	}
	h := limitedAdminHandlers(db)
	h.Mailer = &mail.Mailer{DB: db, Logger: h.Logger}

	for _, pw := range []string{"", "short"} {
		if loc := postClientCreate(h, pw); !strings.Contains(loc, "password") {
			t.Errorf("pw %q: want password error, got %q", pw, loc)
		}
	}
	var n int
	_ = db.QueryRow("SELECT COUNT(*) FROM users WHERE email='a@acme.test'").Scan(&n)
	if n != 0 {
		t.Errorf("user created despite rejection")
	}
}
