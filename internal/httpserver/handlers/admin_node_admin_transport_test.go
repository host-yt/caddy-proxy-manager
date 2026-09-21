package handlers

import (
	"context"
	"database/sql"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
	_ "github.com/go-sql-driver/mysql"

	"github.com/host-yt/caddy-proxy-manager/internal/auth"
	"github.com/host-yt/caddy-proxy-manager/internal/httpserver/middleware"
	"github.com/host-yt/caddy-proxy-manager/internal/view"
)

// insertTransportNode creates an approved node in a real group (the nodes list
// query inner-joins node_groups) with the given legacy allowance.
func insertTransportNode(t *testing.T, db *sql.DB, allow bool) (int64, func()) {
	t.Helper()
	ctx := context.Background()
	suffix := time.Now().UnixNano()
	gres, err := db.ExecContext(ctx,
		"INSERT INTO node_groups (name) VALUES (?)", fmt.Sprintf("transport_%d", suffix))
	if err != nil {
		t.Fatalf("insert group: %v", err)
	}
	groupID, _ := gres.LastInsertId()
	res, err := db.ExecContext(ctx,
		`INSERT INTO caddy_nodes (name, api_url, node_group_id, max_routes, is_enabled,
		    health_status, approved_at, allow_unauthenticated_admin)
		 VALUES (?, 'http://10.9.9.9:2019', ?, 100, 1, 'unknown', NOW(), ?)`,
		fmt.Sprintf("transport_%d", suffix), groupID, allow)
	if err != nil {
		t.Fatalf("insert node: %v", err)
	}
	id, _ := res.LastInsertId()
	return id, func() {
		_, _ = db.ExecContext(ctx, "DELETE FROM caddy_nodes WHERE id = ?", id)
		_, _ = db.ExecContext(ctx, "DELETE FROM node_groups WHERE id = ?", groupID)
	}
}

func saveTransportNode(t *testing.T, db *sql.DB, nodeID int64, form url.Values) {
	t.Helper()
	h := &AdminHandlers{DB: func() *sql.DB { return db }, Logger: slog.Default()}
	req := httptest.NewRequest(http.MethodPost,
		"/admin/nodes/"+fmt.Sprint(nodeID)+"/edit", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rctx := chi.NewRouteContext()
	rctx.URLParams.Add("id", fmt.Sprint(nodeID))
	req = req.WithContext(middleware.ContextWithSession(
		context.WithValue(req.Context(), chi.RouteCtxKey, rctx),
		&auth.Session{UserID: 1, Role: "super_admin", Email: "a@example.com"}))
	rr := httptest.NewRecorder()
	h.NodesUpdate(rr, req)
	if rr.Code != http.StatusSeeOther {
		t.Fatalf("NodesUpdate: expected 303, got %d", rr.Code)
	}
}

func transportAllowance(t *testing.T, db *sql.DB, nodeID int64) bool {
	t.Helper()
	var allow bool
	if err := db.QueryRow(
		"SELECT COALESCE(allow_unauthenticated_admin,0) FROM caddy_nodes WHERE id = ?", nodeID).Scan(&allow); err != nil {
		t.Fatalf("read allowance: %v", err)
	}
	return allow
}

// SEC-002: the per-node migration-window allowance was reachable only by SQL.
// The edit form must be able to set it AND clear it - a save that cannot write
// the column leaves a grandfathered node on the legacy path forever.
func TestNodeEditWritesAdminTransportAllowance(t *testing.T) {
	db := openTestDBHandlers(t)
	defer db.Close()

	nodeID, cleanup := insertTransportNode(t, db, false)
	defer cleanup()

	form := url.Values{}
	form.Set("outbound_ips", "203.0.113.7")
	form.Set("allow_unauthenticated_admin", "1")
	saveTransportNode(t, db, nodeID, form)
	if !transportAllowance(t, db, nodeID) {
		t.Fatal("ticking the allowance did not persist - the box does nothing")
	}

	form.Del("allow_unauthenticated_admin")
	saveTransportNode(t, db, nodeID, form)
	if transportAllowance(t, db, nodeID) {
		t.Fatal("unticking the allowance did not persist - a node cannot be taken off the legacy path from the UI")
	}
}

// The nodes list must be able to show which nodes are still on the legacy
// path; without the column in the query the badge can never render.
func TestNodesListCarriesAdminTransportAllowance(t *testing.T) {
	db := openTestDBHandlers(t)
	defer db.Close()

	nodeID, cleanup := insertTransportNode(t, db, true)
	defer cleanup()

	h := &AdminHandlers{DB: func() *sql.DB { return db }, Logger: slog.Default()}
	var d nodesData
	h.populateNodesData(context.Background(), &d)

	found := false
	for _, n := range d.Nodes {
		if n.ID != nodeID {
			continue
		}
		found = true
		if !n.AllowUnauthAdmin {
			t.Fatal("nodes list does not carry the legacy allowance - the badge cannot render")
		}
	}
	if !found {
		t.Fatalf("node %d missing from the nodes list", nodeID)
	}
}

// A grandfathered node must render with the box ticked: an unchecked prefill
// would clear the allowance on any routine node save and stop its pushes.
func TestNodeEditPrefillsAdminTransportAllowance(t *testing.T) {
	db := openTestDBHandlers(t)
	defer db.Close()

	nodeID, cleanup := insertTransportNode(t, db, true)
	defer cleanup()

	tpls, err := view.LoadAdminTemplates()
	if err != nil {
		t.Fatalf("load admin templates: %v", err)
	}
	h := &AdminHandlers{DB: func() *sql.DB { return db }, Logger: slog.Default(), Templates: tpls}
	req := httptest.NewRequest(http.MethodGet, "/admin/nodes/"+fmt.Sprint(nodeID)+"/edit", nil)
	rctx := chi.NewRouteContext()
	rctx.URLParams.Add("id", fmt.Sprint(nodeID))
	req = req.WithContext(middleware.ContextWithSession(
		context.WithValue(req.Context(), chi.RouteCtxKey, rctx),
		&auth.Session{UserID: 1, Role: "super_admin", Email: "a@example.com"}))
	rr := httptest.NewRecorder()
	h.NodesEdit(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("NodesEdit: expected 200, got %d", rr.Code)
	}
	body := rr.Body.String()
	i := strings.Index(body, `name="allow_unauthenticated_admin"`)
	if i < 0 {
		t.Fatal("node edit form has no allowance checkbox")
	}
	tag := body[i:]
	if end := strings.Index(tag, ">"); end >= 0 {
		tag = tag[:end]
	}
	if !strings.Contains(tag, "checked") {
		t.Fatalf("allowance checkbox not prefilled for a grandfathered node: %s", tag)
	}
}
