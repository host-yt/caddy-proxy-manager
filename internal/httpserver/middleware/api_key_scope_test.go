package middleware

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func scopeStatus(t *testing.T, mw func(http.Handler) http.Handler, c *APICaller, method string) int {
	t.Helper()
	h := mw(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) }))
	req := httptest.NewRequest(method, "/api/v1/services", nil)
	if c != nil {
		req = req.WithContext(ContextWithAPICaller(req.Context(), c))
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec.Code
}

func TestRequireCustomerResourceScope(t *testing.T) {
	client := func(s ...string) *APICaller { return &APICaller{UserID: 9, Role: "client", Scopes: s} }
	admin := func(s ...string) *APICaller { return &APICaller{UserID: 1, Role: "admin", Scopes: s} }
	cases := []struct {
		name   string
		caller *APICaller
		method string
		want   int
	}{
		{"admin with resource scope", admin("services"), http.MethodPost, http.StatusOK},
		{"admin without resource scope", admin("routes"), http.MethodGet, http.StatusForbidden},
		{"admin key client:write does not widen", admin("client:read", "client:write"), http.MethodGet, http.StatusForbidden},
		{"client read on GET", client("client:read"), http.MethodGet, http.StatusOK},
		{"client read on POST denied", client("client:read"), http.MethodPost, http.StatusForbidden},
		{"client write on POST", client("client:write"), http.MethodPost, http.StatusOK},
		{"client write implies read", client("client:write"), http.MethodGet, http.StatusOK},
		{"client admin:write ignored", client("admin:write"), http.MethodGet, http.StatusForbidden},
		{"no caller", nil, http.MethodGet, http.StatusForbidden},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := scopeStatus(t, RequireCustomerResourceScope("services"), tc.caller, tc.method); got != tc.want {
				t.Fatalf("status = %d, want %d", got, tc.want)
			}
		})
	}
}
