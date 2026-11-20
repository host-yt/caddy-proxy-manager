package handlers

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/host-yt/caddy-proxy-manager/internal/auth"
	"github.com/host-yt/caddy-proxy-manager/internal/httpserver/middleware"
)

// mapPage renders /admin/map?<query> as a super_admin and returns the HTML.
func mapPage(t *testing.T, h *AdminHandlers, query string) string {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, "/admin/map?"+query, nil)
	req = req.WithContext(middleware.ContextWithSession(req.Context(), &auth.Session{UserID: 1, Role: "super_admin"}))
	rec := httptest.NewRecorder()
	h.AdminMap(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /admin/map?%s: %d", query, rec.Code)
	}
	return rec.Body.String()
}

// #153: the map pages through clients and searches across every page, and
// each route is tied to its own service for the edge overlay.
func TestAdminMapPagingAndSearch(t *testing.T) {
	db := mtlsTLSEditDB(t)     // client 1 with service 1 and route 7 on node 1
	for i := 2; i <= 31; i++ { // 30 more clients, each with one service and host
		for _, q := range []string{
			fmt.Sprintf(`INSERT INTO users (id, email, password_hash, role) VALUES (%d, 'c%d@x.test', 'x', 'client')`, i, i),
			fmt.Sprintf(`INSERT INTO clients (id, user_id, display_name) VALUES (%d, %d, 'client-%d')`, i, i, i),
			fmt.Sprintf(`INSERT INTO services (id, client_id, name, backend_ip, allowed_port_start, allowed_port_end, plan_id, node_group_id)
			   VALUES (%d, %d, 'svc-%d', '10.0.0.%d', 20000, 20010, 1, 1)`, i, i, i, i),
			fmt.Sprintf(`INSERT INTO routes (id, service_id, caddy_node_id, domain, upstream_port, upstream_scheme, kind, ssl_enabled, status, domain_verified)
			   VALUES (%d, %d, 1, 'app%d.example', 20001, 'http', 'proxy', 1, 'active', 1)`, 100+i, i, i),
		} {
			if _, err := db.Exec(q); err != nil {
				t.Fatalf("seed: %v", err)
			}
		}
	}
	h := editFormHandlers(t, db)

	// Page 1: the 25 newest clients (31..7), a link to page 2.
	p1 := mapPage(t, h, "")
	if strings.Count(p1, "data-topology-lane>") != adminMapClientLimit {
		t.Fatalf("page 1 lanes = %d, want %d", strings.Count(p1, "data-topology-lane>"), adminMapClientLimit)
	}
	if !strings.Contains(p1, "client-31") || strings.Contains(p1, ">client-2<") {
		t.Error("page 1 should hold the newest clients only")
	}
	if !strings.Contains(p1, "page=2") || !strings.Contains(p1, "page 1 of 2") {
		t.Error("page 1 has no link to page 2")
	}

	// Page 2: the remaining 6 (6..1).
	p2 := mapPage(t, h, "page=2")
	if n := strings.Count(p2, "data-topology-lane>"); n != 31-adminMapClientLimit {
		t.Fatalf("page 2 lanes = %d, want %d", n, 31-adminMapClientLimit)
	}
	if !strings.Contains(p2, "acme") {
		t.Error("oldest client missing from page 2")
	}

	// Search reaches a client that is not on page 1, by its host name.
	s := mapPage(t, h, "q=app3.example")
	if n := strings.Count(s, "data-topology-lane>"); n != 1 || !strings.Contains(s, "client-3") {
		t.Fatalf("search by host: %d lanes", n)
	}
	// LIKE wildcards are literal: "_" must not match any character.
	if n := strings.Count(mapPage(t, h, "q=app_.example"), "data-topology-lane>"); n != 0 {
		t.Errorf("q=app_.example matched %d clients; _ must be literal", n)
	}
	// Out-of-range page clamps to the last page.
	if n := strings.Count(mapPage(t, h, "page=99"), "data-topology-lane>"); n != 31-adminMapClientLimit {
		t.Errorf("page 99 lanes = %d", n)
	}

	// Each route card names its own service, so the overlay links route to
	// service one-to-one instead of fanning out to every service.
	if !strings.Contains(s, `data-service-id="3"`) ||
		!strings.Contains(s, `class="hpg-map-node hpg-map-node-route" data-service-id="3"`) {
		t.Error("route card does not carry its service id")
	}
}

// Review of #153: a search can match fields the lane does not show (a
// contact's full name); a failing query is reported, not shown as "no match";
// a long term is cut on a rune.
func TestAdminMapSearchEdges(t *testing.T) {
	db := mtlsTLSEditDB(t)
	if _, err := db.Exec(`UPDATE users SET full_name = 'John Smith' WHERE id = 1`); err != nil {
		t.Fatal(err)
	}
	h := editFormHandlers(t, db)

	page := mapPage(t, h, "q=smith")
	if strings.Count(page, "data-topology-lane>") != 1 || !strings.Contains(page, "1 matching clients") {
		t.Fatal("search by full name did not return the client")
	}
	if !strings.Contains(page, `value="smith"`) {
		t.Error("server term not kept in the search box")
	}

	// 250 runes of "é" (2 bytes each): kept to 200 whole runes.
	long := strings.Repeat("é", 250)
	page = mapPage(t, h, "q="+long)
	if !strings.Contains(page, strings.Repeat("é", 200)) || strings.Contains(page, strings.Repeat("é", 201)) {
		t.Error("long term not cut to 200 runes")
	}
	if strings.Contains(page, "�") {
		t.Error("term cut mid-character")
	}

	// A query that fails is an error state, not "no client matches".
	if _, err := db.Exec(`DROP TABLE customer_wg_peer_usage_sample`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`DROP TABLE customer_wg_peer`); err != nil {
		t.Skipf("cannot drop customer_wg_peer here: %v", err)
	}
	page = mapPage(t, h, "q=acme")
	if !strings.Contains(page, "could not be loaded") || strings.Contains(page, "No client matches") {
		t.Error("failed search shown as no match")
	}
}
