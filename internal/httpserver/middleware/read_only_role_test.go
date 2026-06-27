package middleware

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/host-yt/caddy-proxy-manager/internal/auth"
)

func TestReadOnlyRoleAllowList(t *testing.T) {
	tests := []struct {
		name       string
		role       string
		method     string
		target     string
		wantStatus int
		wantCalled bool
	}{
		{
			name:       "support can read allowed path",
			role:       "support",
			method:     http.MethodGet,
			target:     "/admin/map",
			wantStatus: http.StatusNoContent,
			wantCalled: true,
		},
		{
			name:       "support can read allowed glob",
			role:       "support",
			method:     http.MethodGet,
			target:     "/admin/tunnels/42/bandwidth.json",
			wantStatus: http.StatusNoContent,
			wantCalled: true,
		},
		{
			name:       "support cannot read outside allow list",
			role:       "support",
			method:     http.MethodGet,
			target:     "/admin/users",
			wantStatus: http.StatusForbidden,
			wantCalled: false,
		},
		{
			name:       "support cannot mutate allowed path",
			role:       "support",
			method:     http.MethodPost,
			target:     "/admin/map",
			wantStatus: http.StatusForbidden,
			wantCalled: false,
		},
		{
			name:       "admin is not restricted by support allow list",
			role:       "admin",
			method:     http.MethodPost,
			target:     "/admin/map",
			wantStatus: http.StatusNoContent,
			wantCalled: true,
		},
	}

	mw := ReadOnlyRoleAllowList("support", []string{
		"/admin/map",
		"/admin/tunnels/*/bandwidth.json",
	})

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			called := false
			next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				called = true
				w.WriteHeader(http.StatusNoContent)
			})
			rr := httptest.NewRecorder()
			mw(next).ServeHTTP(rr, requestWithRole(tt.method, tt.target, tt.role))

			if rr.Code != tt.wantStatus {
				t.Fatalf("status = %d, want %d", rr.Code, tt.wantStatus)
			}
			if called != tt.wantCalled {
				t.Fatalf("called = %v, want %v", called, tt.wantCalled)
			}
		})
	}
}

func TestReadOnlyRoleAllowListWriteAllowed(t *testing.T) {
	mw := ReadOnlyRoleAllowList("support",
		[]string{"/admin/ai/chat", "/admin/ai/chat/sessions", "/admin/ai/chat/sessions/*/message"},
		[]string{"/admin/ai/chat/sessions", "/admin/ai/chat/sessions/*/message"})

	tests := []struct {
		name       string
		method     string
		target     string
		wantStatus int
		wantCalled bool
	}{
		{"support POST allowed AI message", http.MethodPost, "/admin/ai/chat/sessions/5/message", http.StatusNoContent, true},
		{"support POST allowed create session", http.MethodPost, "/admin/ai/chat/sessions", http.StatusNoContent, true},
		{"support GET AI page", http.MethodGet, "/admin/ai/chat", http.StatusNoContent, true},
		{"support POST not in write list blocked", http.MethodPost, "/admin/hosts/new", http.StatusForbidden, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			called := false
			next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				called = true
				w.WriteHeader(http.StatusNoContent)
			})
			rr := httptest.NewRecorder()
			mw(next).ServeHTTP(rr, requestWithRole(tt.method, tt.target, "support"))
			if rr.Code != tt.wantStatus {
				t.Fatalf("status = %d, want %d", rr.Code, tt.wantStatus)
			}
			if called != tt.wantCalled {
				t.Fatalf("called = %v, want %v", called, tt.wantCalled)
			}
		})
	}
}

func requestWithRole(method, target, role string) *http.Request {
	r := httptest.NewRequest(method, target, nil)
	ctx := context.WithValue(r.Context(), sessionCtxKey, &auth.Session{Role: role})
	return r.WithContext(ctx)
}
