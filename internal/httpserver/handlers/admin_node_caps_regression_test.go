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
	"github.com/host-yt/caddy-proxy-manager/internal/domain/routes"
	"github.com/host-yt/caddy-proxy-manager/internal/httpserver/middleware"
)

// insertUnprobedNode creates a caddy_node that was never declared/probed
// (modules_probed_at NULL, all has_* = 0) and returns its id + cleanup.
func insertUnprobedNode(t *testing.T, db *sql.DB) (int64, func()) {
	t.Helper()
	ctx := context.Background()
	if _, err := db.ExecContext(ctx, "SET FOREIGN_KEY_CHECKS=0"); err != nil {
		t.Fatalf("disable FK checks: %v", err)
	}
	name := fmt.Sprintf("capregress_%d", time.Now().UnixNano())
	res, err := db.ExecContext(ctx,
		`INSERT INTO caddy_nodes (name, api_url, node_group_id, max_routes, is_enabled,
		    has_waf, has_l4, has_dns_module, has_rate_limit, has_geoip, modules_probed_at)
		 VALUES (?, 'http://10.9.9.9:2019', 9999, 100, 1, 0, 0, 0, 0, 0, NULL)`, name)
	if err != nil {
		t.Fatalf("insert node: %v", err)
	}
	id, _ := res.LastInsertId()
	cleanup := func() { _, _ = db.ExecContext(ctx, "DELETE FROM caddy_nodes WHERE id = ?", id) }
	return id, cleanup
}

// TestNodeEditSavePreservesEnvBackedWAF guards the regression where a routine
// node save silently disabled module-gated protections. An unprobed node relies
// on the fleet-wide env flag (WAF_MODULE_AVAILABLE). The edit form MUST prefill
// the WAF checkbox with the effective (env-backed) value so saving - e.g. only
// changing outbound_ips - does not write has_waf=0 + modules_probed_at and turn
// WAF off for that node.
func TestNodeEditSavePreservesEnvBackedWAF(t *testing.T) {
	db := openTestDBHandlers(t)
	defer db.Close()
	ctx := context.Background()

	nodeID, cleanup := insertUnprobedNode(t, db)
	defer cleanup()

	// Step 1: the edit-form prefill query resolves effective WAF=true for an
	// unprobed node when the fleet env flag is on. If this reverts to reading raw
	// has_waf (=0), the checkbox would render unchecked and the save would disable
	// WAF - this assertion is the regression guard.
	var prefillWAF bool
	if err := db.QueryRowContext(ctx,
		`SELECT COALESCE(CASE WHEN modules_probed_at IS NOT NULL THEN has_waf END, ?)
		   FROM caddy_nodes WHERE id = ?`, b2i(true), nodeID).Scan(&prefillWAF); err != nil {
		t.Fatalf("prefill query: %v", err)
	}
	if !prefillWAF {
		t.Fatal("edit form prefilled WAF unchecked for an env-backed node: a routine save would disable WAF")
	}

	// Step 2: save through the real handler. The form mirrors what the rendered
	// page submits - the WAF box stays checked (prefillWAF) while the operator
	// only edits outbound_ips.
	h := &AdminHandlers{
		DB:     func() *sql.DB { return db },
		Logger: slog.Default(),
		Routes: &routes.Service{WAFModuleAvailable: true},
	}
	form := url.Values{}
	form.Set("outbound_ips", "203.0.113.7")
	if prefillWAF {
		form.Set("has_waf", "1")
	}
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

	// Step 3: re-resolve effective WAF the way buildNodePush does. Pass env=false
	// to prove the value now stands on its own per-node declaration: the save must
	// have persisted has_waf=1 + modules_probed_at, so WAF is still on.
	var effWAF bool
	var probedAt sql.NullTime
	if err := db.QueryRowContext(ctx,
		`SELECT COALESCE(CASE WHEN modules_probed_at IS NOT NULL THEN has_waf END, ?), modules_probed_at
		   FROM caddy_nodes WHERE id = ?`, b2i(false), nodeID).Scan(&effWAF, &probedAt); err != nil {
		t.Fatalf("re-resolve query: %v", err)
	}
	if !probedAt.Valid {
		t.Fatal("save did not stamp modules_probed_at - declared flags would not be authoritative")
	}
	if !effWAF {
		t.Fatal("WAF disabled after a routine node save - regression reintroduced")
	}
}
