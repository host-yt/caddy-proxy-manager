package handlers

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestOnceCookieShownOnceAndNotInURL(t *testing.T) {
	post := httptest.NewRecorder()
	setOnceCookie(post, httptest.NewRequest("POST", "/admin/tunnels", nil), nil, "hpg_new_tunnel", "/admin/tunnels", "tok123")
	set := post.Result().Cookies()
	if len(set) != 1 || !set[0].HttpOnly || set[0].SameSite != http.SameSiteStrictMode || set[0].MaxAge <= 0 {
		t.Fatalf("bad cookie: %+v", set)
	}

	get := httptest.NewRequest("GET", "/admin/tunnels", nil)
	get.AddCookie(set[0])
	rec := httptest.NewRecorder()
	if v := takeOnceCookie(rec, get, nil, "hpg_new_tunnel", "/admin/tunnels"); v != "tok123" {
		t.Fatalf("got %q", v)
	}
	cleared := rec.Result().Cookies()
	if len(cleared) != 1 || cleared[0].MaxAge >= 0 {
		t.Fatalf("cookie not cleared: %+v", cleared)
	}
	if v := takeOnceCookie(httptest.NewRecorder(), httptest.NewRequest("GET", "/admin/tunnels", nil), nil, "hpg_new_tunnel", "/admin/tunnels"); v != "" {
		t.Fatalf("value without cookie: %q", v)
	}
}
