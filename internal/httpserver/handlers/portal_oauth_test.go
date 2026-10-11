package handlers

import (
	"context"
	"database/sql"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/host-yt/caddy-proxy-manager/internal/auth"
	"github.com/host-yt/caddy-proxy-manager/internal/domain/portal"
)

// the OAuth handoff may only be redeemed on the host that
// started the flow, by the browser holding that flow's nonce.
func TestPortalOAuthCompleteBindsHostAndBrowser(t *testing.T) {
	rdb := portalTestRedis(t)
	db := portalVerifyDB(t)
	res, err := db.Exec(`INSERT INTO users (email, password_hash, role, full_name, is_active)
		VALUES ('o@example.com', 'x', 'client', 'O', 1)`)
	if err != nil {
		t.Fatal(err)
	}
	uid, _ := res.LastInsertId()
	ctx := context.Background()
	epoch, err := auth.UserEpoch(ctx, db, uid)
	if err != nil {
		t.Fatal(err)
	}
	dbf := func() *sql.DB { return db }
	h := &PortalHandlers{
		DB: dbf, RDB: rdb, Portal: portal.New(dbf),
		Logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
	}

	issue := func(back string) string {
		t.Helper()
		tk, err := randToken(32)
		if err != nil {
			t.Fatal(err)
		}
		b, _ := json.Marshal(portalOAuthHandoff{UserID: uid, Epoch: epoch, Email: "o@example.com",
			Back: back, Host: "app.example", Nonce: "browser-nonce", Provider: "github"})
		if err := rdb.Set(ctx, portalOAuthHandoffPrefix+tk, b, portalOAuthHandoffTTL).Err(); err != nil {
			t.Fatal(err)
		}
		return tk
	}
	complete := func(host, ticket, nonce string) *httptest.ResponseRecorder {
		r := httptest.NewRequest(http.MethodGet, "https://"+host+portalOAuthCompletePath+"?ticket="+ticket, nil)
		if nonce != "" {
			r.AddCookie(&http.Cookie{Name: portalOAuthStateCookie, Value: nonce})
		}
		rec := httptest.NewRecorder()
		h.PortalOAuthComplete(rec, r)
		return rec
	}

	cases := []struct {
		name, host, nonce, back string
		ok                      bool
	}{
		{"victim browser without nonce", "app.example", "", "/", false},
		{"other browser's nonce", "app.example", "attacker-nonce", "/", false},
		{"other host", "evil.example", "browser-nonce", "/", false},
		{"protected route without grant", "app.example", "browser-nonce", "/team-a/x", false},
		{"originating browser", "app.example", "browser-nonce", "/", true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			tk := issue(c.back)
			rec := complete(c.host, tk, c.nonce)
			got := cookieNamed(rec, portalCookie) != nil
			if got != c.ok {
				t.Fatalf("session minted = %v, want %v (status %d)", got, c.ok, rec.Code)
			}
			if c.ok && rec.Header().Get("Location") != c.back {
				t.Fatalf("redirect = %q, want %q", rec.Header().Get("Location"), c.back)
			}
			// Single use either way.
			if again := complete(c.host, tk, c.nonce); cookieNamed(again, portalCookie) != nil {
				t.Fatal("handoff ticket redeemed twice")
			}
		})
	}
}
