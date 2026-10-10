package middleware

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestSlaveReadOnly(t *testing.T) {
	tests := []struct {
		method, target string
		allowed        bool
	}{
		{http.MethodGet, "/admin/hosts", true},
		{http.MethodHead, "/api/v1/routes", true},
		{http.MethodOptions, "/app/routes", true},
		{http.MethodPost, "/internal/sync/push", true},
		{http.MethodPost, "/auth/login", true},
		{http.MethodPost, "/auth/2fa", true},
		{http.MethodPost, "/api/node/wg/stats", true},
		{http.MethodPost, "/hpg-portal/login", true},
		{http.MethodPost, "/install/db", true},
		{http.MethodPost, "/admin/hosts/new", false},
		{http.MethodPost, "/app/routes", false},
		{http.MethodPost, "/api/v1/services", false},
		{http.MethodPatch, "/api/v1/routes/1", false},
		{http.MethodDelete, "/admin/2fa/passkeys/1", false},
		{http.MethodPut, "/api/v1/routes/1", false},
		{"PROPFIND", "/admin", false},
		{http.MethodPost, "/auth/register", false},
		{http.MethodPost, "/auth/reset", false},
		{http.MethodPost, "/api/node/../v1/services", false},
		{http.MethodPost, "/auth/login/", false},
	}
	for _, tt := range tests {
		called := false
		h := SlaveReadOnly(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			called = true
			w.WriteHeader(http.StatusNoContent)
		}))
		req := httptest.NewRequest(tt.method, "http://x/", nil)
		req.URL.Path = tt.target
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		if called != tt.allowed {
			t.Errorf("%s %s: called=%v, want %v (status %d)", tt.method, tt.target, called, tt.allowed, rec.Code)
		}
		if !tt.allowed && rec.Code != http.StatusForbidden {
			t.Errorf("%s %s: status %d, want 403", tt.method, tt.target, rec.Code)
		}
	}
}
