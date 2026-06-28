package handlers

import (
	"context"
	"database/sql"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	_ "github.com/go-sql-driver/mysql"

	"github.com/host-yt/caddy-proxy-manager/internal/wafevents"
)

// insertWAFAttrFixture creates a node (with a known agent token) plus two routes
// on it sharing a domain: a bare route and a /api path-prefixed route.
func insertWAFAttrFixture(t *testing.T, db *sql.DB) (nodeID int64, token, domain string, bareID, apiID int64, cleanup func()) {
	t.Helper()
	ctx := context.Background()
	if _, err := db.ExecContext(ctx, "SET FOREIGN_KEY_CHECKS=0"); err != nil {
		t.Fatalf("disable FK checks: %v", err)
	}
	tag := fmt.Sprintf("wafattr_%d", time.Now().UnixNano())
	token = tag + "-token"
	domain = tag + ".example"

	res, err := db.ExecContext(ctx,
		`INSERT INTO caddy_nodes (name, api_url, node_group_id, agent_token_hash)
		 VALUES (?, 'http://10.0.0.9:2019', 9999, SHA2(?,256))`, tag, token)
	if err != nil {
		t.Fatalf("insert node: %v", err)
	}
	nodeID, _ = res.LastInsertId()

	mkRoute := func(prefix string) int64 {
		r, e := db.ExecContext(ctx,
			`INSERT INTO routes (service_id, caddy_node_id, domain, path_prefix, upstream_port, status)
			 VALUES (9999, ?, ?, ?, 8080, 'active')`, nodeID, domain, prefix)
		if e != nil {
			t.Fatalf("insert route %q: %v", prefix, e)
		}
		id, _ := r.LastInsertId()
		return id
	}
	bareID = mkRoute("")
	apiID = mkRoute("/api")

	cleanup = func() {
		_, _ = db.ExecContext(ctx, "DELETE FROM waf_events WHERE route_id IN (?,?)", bareID, apiID)
		_, _ = db.ExecContext(ctx, "DELETE FROM routes WHERE caddy_node_id = ?", nodeID)
		_, _ = db.ExecContext(ctx, "DELETE FROM caddy_nodes WHERE id = ?", nodeID)
	}
	return nodeID, token, domain, bareID, apiID, cleanup
}

// TestResolveRoute_HostPathAttribution proves server-side route attribution from
// host + path, scoped to the authenticated node (the Codex finding: events were
// inserted with NULL route_id, breaking per-route views and pruning).
func TestResolveRoute_HostPathAttribution(t *testing.T) {
	db := openTestDBHandlers(t)
	defer db.Close()
	ctx := context.Background()

	nodeID, _, domain, bareID, apiID, cleanup := insertWAFAttrFixture(t, db)
	defer cleanup()

	h := &NodeWAFIngestHandler{DB: func() *sql.DB { return db }, Logger: slog.Default()}

	cases := []struct {
		host, uri string
		want      int64
	}{
		{domain, "/foo", bareID},                            // bare domain
		{domain, "/api/x?q=1", apiID},                       // longest path prefix wins
		{strings.ToUpper(domain) + ":443", "/api/y", apiID}, // case-insensitive + :port
		{"nope-" + domain, "/api", 0},                       // unknown host -> 0
		{"", "/api", 0},                                     // no host -> 0
	}
	for _, c := range cases {
		if got := h.resolveRoute(ctx, nodeID, c.host, c.uri); got != c.want {
			t.Errorf("resolveRoute(%q,%q)=%d want %d", c.host, c.uri, got, c.want)
		}
	}
	// A node must never attribute to another node's route.
	if got := h.resolveRoute(ctx, nodeID+99999, domain, "/foo"); got != 0 {
		t.Errorf("cross-node resolve leaked: got %d want 0", got)
	}
}

// TestWAFIngest_RowGetsRouteID is the end-to-end proof Codex asked for: a Coraza-
// derived event POSTed by the node lands in waf_events with a non-NULL route_id.
func TestWAFIngest_RowGetsRouteID(t *testing.T) {
	db := openTestDBHandlers(t)
	defer db.Close()
	ctx := context.Background()

	nodeID, token, domain, _, apiID, cleanup := insertWAFAttrFixture(t, db)
	defer cleanup()
	_ = nodeID

	h := &NodeWAFIngestHandler{
		DB:        func() *sql.DB { return db },
		WAFEvents: wafevents.New(func() *sql.DB { return db }),
		Logger:    slog.Default(),
	}
	body := `{"events":[{"ts":"2026-06-28T13:54:06Z","severity":"critical","rule_id":"942100",` +
		`"action":"detected","remote_ip":"85.222.65.102","host":"` + domain + `","uri":"/api/z","message":"SQLi"}]}`
	req := httptest.NewRequest(http.MethodPost, "/api/node/waf/events", strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	h.Ingest(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("ingest: got %d body=%s", rr.Code, rr.Body.String())
	}

	var routeID sql.NullInt64
	if err := db.QueryRowContext(ctx,
		`SELECT route_id FROM waf_events WHERE host = ? ORDER BY id DESC LIMIT 1`, domain).Scan(&routeID); err != nil {
		t.Fatalf("select waf_event: %v", err)
	}
	if !routeID.Valid || routeID.Int64 != apiID {
		t.Errorf("waf_event route_id = %v (valid=%v) want %d - event not attributed to its route",
			routeID.Int64, routeID.Valid, apiID)
	}
}
