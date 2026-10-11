package handlers

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/host-yt/caddy-proxy-manager/internal/httpserver/middleware"
)

// Omitted ssl/websocket flags must take the schema default (true), not false.
func TestPlanCreateOmittedBoolsDefault(t *testing.T) {
	db := openResellerAPIDB(t)
	if _, err := db.Exec(`DROP TABLE plans`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`CREATE TABLE plans (id INTEGER PRIMARY KEY, reseller_id INTEGER, name TEXT, kind TEXT,
		max_domains INTEGER, max_ports INTEGER, ssl_enabled INTEGER, path_routing_enabled INTEGER,
		wildcard_enabled INTEGER, websocket_enabled INTEGER, external_proxy_enabled INTEGER,
		allow_egress_ip INTEGER, rate_limit_rpm INTEGER, wg_key_rotation_days INTEGER, node_group_id INTEGER)`); err != nil {
		t.Fatal(err)
	}
	h := newResellerAPIHandlers(db)
	create := func(body string) {
		req := httptest.NewRequest(http.MethodPost, "/api/v1/plans", strings.NewReader(body))
		req = req.WithContext(middleware.ContextWithAPICaller(req.Context(), &middleware.APICaller{UserID: 5, Role: "super_admin"}))
		rr := httptest.NewRecorder()
		h.PlanCreate(rr, req)
		if rr.Code != http.StatusCreated {
			t.Fatalf("status %d: %s", rr.Code, rr.Body.String())
		}
	}
	create(`{"name":"a","max_domains":1,"max_ports":1,"node_group_id":1}`)
	create(`{"name":"b","max_domains":1,"max_ports":1,"node_group_id":1,"ssl_enabled":false,"websocket_enabled":false}`)
	for name, want := range map[string]int{"a": 1, "b": 0} {
		var ssl, ws int
		if err := db.QueryRow(`SELECT ssl_enabled, websocket_enabled FROM plans WHERE name = ?`, name).Scan(&ssl, &ws); err != nil {
			t.Fatal(err)
		}
		if ssl != want || ws != want {
			t.Errorf("plan %s: ssl=%d ws=%d, want %d", name, ssl, ws, want)
		}
	}
}
