package handlers

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/host-yt/caddy-proxy-manager/internal/httpserver/middleware"
)

// API-created nodes must be approved, otherwise placement never picks them.
func TestNodeCreateApproves(t *testing.T) {
	db := openResellerAPIDB(t)
	if _, err := db.Exec(`CREATE TABLE caddy_nodes (id INTEGER PRIMARY KEY, name TEXT, api_url TEXT,
		public_hostname TEXT, public_ip TEXT, node_group_id INTEGER, max_routes INTEGER, priority INTEGER,
		is_enabled INTEGER, health_status TEXT, approved_at DATETIME, approved_by INTEGER)`); err != nil {
		t.Fatal(err)
	}
	h := newResellerAPIHandlers(db)
	body := `{"name":"n1","api_url":"http://10.8.0.2:2021","node_group_id":1,"max_routes":10}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/nodes", strings.NewReader(body))
	req = req.WithContext(middleware.ContextWithAPICaller(req.Context(), &middleware.APICaller{UserID: 5, Role: "super_admin"}))
	rr := httptest.NewRecorder()
	h.NodeCreate(rr, req)
	if rr.Code != http.StatusCreated {
		t.Fatalf("status %d: %s", rr.Code, rr.Body.String())
	}
	var n int
	db.QueryRow(`SELECT COUNT(*) FROM caddy_nodes WHERE approved_at IS NOT NULL AND approved_by = 5`).Scan(&n)
	if n != 1 {
		t.Fatal("API-created node not approved")
	}
}

// Node/pool writes refuse values the panel forms refuse.
func TestNodeAPIValidation(t *testing.T) {
	h := newResellerAPIHandlers(openResellerAPIDB(t))
	call := func(fn http.HandlerFunc, body string) int {
		req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(body))
		req = req.WithContext(middleware.ContextWithAPICaller(req.Context(), &middleware.APICaller{UserID: 5, Role: "super_admin"}))
		rr := httptest.NewRecorder()
		fn(rr, req)
		return rr.Code
	}
	for name, c := range map[string]struct {
		fn   http.HandlerFunc
		body string
	}{
		"node create bad public_ip": {h.NodeCreate, `{"name":"n1","api_url":"http://10.8.0.2:2021","node_group_id":1,"max_routes":10,"public_ip":"nope"}`},
		"node update empty name":    {h.NodeUpdate, `{"name":""}`},
		"node update bad name":      {h.NodeUpdate, `{"name":"-x y"}`},
		"pool create blank name":    {h.NodePoolCreate, `{"name":"  "}`},
		"pool update blank name":    {h.NodePoolUpdate, `{"name":" "}`},
	} {
		if code := call(c.fn, c.body); code != http.StatusBadRequest {
			t.Errorf("%s: got %d, want 400", name, code)
		}
	}
}
