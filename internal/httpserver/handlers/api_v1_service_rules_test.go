package handlers

import (
	"database/sql"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/host-yt/caddy-proxy-manager/internal/adminscope"
	"github.com/host-yt/caddy-proxy-manager/internal/httpserver/middleware"
)

// API service create applies the panel's port-overlap and reseller placement rules.
func TestAPIServiceCreate_PanelRules(t *testing.T) {
	db := mtlsTLSEditDB(t) // service 1: client 1, 10.9.9.9:10000-20000, plan 1 / group 1
	for _, q := range []string{
		`INSERT INTO node_groups (id, name, mode) VALUES (2, 'other', 'single')`,
		`INSERT INTO plans (id, name, node_group_id, max_domains, ssl_enabled, websocket_enabled) VALUES (2, 'p2', 2, 0, 1, 1)`,
		`INSERT INTO reseller_plans (id, name) VALUES (5, 'pkg')`,
		`INSERT INTO reseller_plan_node_groups (reseller_plan_id, node_group_id) VALUES (5, 1)`,
		`INSERT INTO resellers (id, name, slug, reseller_plan_id) VALUES (7, 'r', 'r', 5)`,
		`INSERT INTO users (id, email, password_hash, role, reseller_id) VALUES (2, 'r@b.c', 'x', 'admin', 7)`,
		`INSERT INTO clients (id, user_id, display_name, reseller_id) VALUES (2, 3, 'tenant', 7)`,
	} {
		if _, err := db.Exec(q); err != nil {
			t.Fatalf("seed %q: %v", q, err)
		}
	}
	h := &APIHandlers{
		DB:         func() *sql.DB { return db },
		AdminScope: adminscope.New(func() *sql.DB { return db }),
		Logger:     slog.New(slog.NewTextHandler(io.Discard, nil)),
	}
	create := func(body string) int {
		req := httptest.NewRequest(http.MethodPost, "/api/v1/services", strings.NewReader(body))
		req = req.WithContext(middleware.ContextWithAPICaller(req.Context(), &middleware.APICaller{UserID: 2, Role: "admin"}))
		rr := httptest.NewRecorder()
		h.ServiceCreate(rr, req)
		return rr.Code
	}
	const tpl = `{"client_id":2,"name":"s","plan_id":%s,"backend_ip":"%s","allowed_port_start":10000,"allowed_port_end":10010}`
	mk := func(plan, ip string) string { return fmt.Sprintf(tpl, plan, ip) }
	if code := create(mk("1", "10.9.9.9")); code != http.StatusConflict {
		t.Errorf("overlapping range: got %d, want 409", code)
	}
	if code := create(mk("2", "10.5.5.5")); code != http.StatusForbidden {
		t.Errorf("ungranted node group: got %d, want 403", code)
	}
	if code := create(mk("1", "10.5.5.5")); code != http.StatusCreated {
		t.Errorf("granted, free range: got %d, want 201", code)
	}
}
