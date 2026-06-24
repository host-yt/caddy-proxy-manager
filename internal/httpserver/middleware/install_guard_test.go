package middleware

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func dummyOK(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(204) }

func TestInstallGuardAllowsGET(t *testing.T) {
	mw := InstallGuard(func() bool { return false }, "")
	srv := mw(http.HandlerFunc(dummyOK))
	r := httptest.NewRequest("GET", "/install", nil)
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, r)
	if w.Code != 204 {
		t.Fatalf("want 204, got %d", w.Code)
	}
}

// After install, state-changing /install/* requests must be refused: a
// POST /install/db / /install/admin / /install/caddy re-entry would repoint
// the DB, mint a rogue super_admin, or register a rogue node. Inert reads
// still pass through (they're harmless and handled by the wizard itself).
func TestInstallGuardBlocksStateChangeAfterInstall(t *testing.T) {
	mw := InstallGuard(func() bool { return true }, "")
	srv := mw(http.HandlerFunc(dummyOK))
	r := httptest.NewRequest("POST", "/install/db", strings.NewReader(""))
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, r)
	if w.Code != http.StatusNotFound {
		t.Fatalf("want 404 for POST after install, got %d", w.Code)
	}
}

func TestInstallGuardAllowsGETAfterInstall(t *testing.T) {
	mw := InstallGuard(func() bool { return true }, "")
	srv := mw(http.HandlerFunc(dummyOK))
	r := httptest.NewRequest("GET", "/install", nil)
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, r)
	if w.Code != 204 {
		t.Fatalf("GET after install should pass, want 204, got %d", w.Code)
	}
}

func TestInstallGuardLoopbackWhenNoToken(t *testing.T) {
	mw := InstallGuard(func() bool { return false }, "")
	srv := mw(http.HandlerFunc(dummyOK))
	r := httptest.NewRequest("POST", "/install/start", strings.NewReader(""))
	r.RemoteAddr = "127.0.0.1:12345"
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, r)
	if w.Code != 204 {
		t.Fatalf("loopback without token: want 204, got %d", w.Code)
	}
}

func TestInstallGuardBlocksNonLoopbackWhenNoToken(t *testing.T) {
	mw := InstallGuard(func() bool { return false }, "")
	srv := mw(http.HandlerFunc(dummyOK))
	r := httptest.NewRequest("POST", "/install/start", strings.NewReader(""))
	r.RemoteAddr = "203.0.113.5:55555"
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, r)
	if w.Code != 403 {
		t.Fatalf("public IP without token: want 403, got %d", w.Code)
	}
}

func TestInstallGuardAcceptsHeaderToken(t *testing.T) {
	mw := InstallGuard(func() bool { return false }, "expected-token")
	srv := mw(http.HandlerFunc(dummyOK))
	r := httptest.NewRequest("POST", "/install/start", strings.NewReader(""))
	r.Header.Set("X-Install-Token", "expected-token")
	r.RemoteAddr = "203.0.113.5:55555"
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, r)
	if w.Code != 204 {
		t.Fatalf("good token: want 204, got %d", w.Code)
	}
}

func TestInstallGuardRejectsBadToken(t *testing.T) {
	mw := InstallGuard(func() bool { return false }, "expected-token")
	srv := mw(http.HandlerFunc(dummyOK))
	r := httptest.NewRequest("POST", "/install/start", strings.NewReader(""))
	r.Header.Set("X-Install-Token", "wrong")
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, r)
	if w.Code != 403 {
		t.Fatalf("bad token: want 403, got %d", w.Code)
	}
}
