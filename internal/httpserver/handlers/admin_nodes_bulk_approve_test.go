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
)

// Bulk approval must enable auto-joined nodes exactly like single approval.
func TestNodesBulkApproveEnablesNode(t *testing.T) {
	db := openTestDBHandlers(t)
	defer db.Close()
	ctx := context.Background()

	sfx := time.Now().UnixNano()
	gres, err := db.ExecContext(ctx, "INSERT INTO node_groups (name) VALUES (?)", fmt.Sprintf("bulkappr_%d", sfx))
	if err != nil {
		t.Fatalf("insert group: %v", err)
	}
	gid, _ := gres.LastInsertId()
	defer db.ExecContext(ctx, "DELETE FROM node_groups WHERE id = ?", gid)
	nres, err := db.ExecContext(ctx,
		`INSERT INTO caddy_nodes (name, api_url, node_group_id, is_enabled, approved_at)
		 VALUES (?, 'http://10.9.9.8:2019', ?, 0, NULL)`, fmt.Sprintf("bulkappr_%d", sfx), gid)
	if err != nil {
		t.Fatalf("insert node: %v", err)
	}
	nid, _ := nres.LastInsertId()
	defer db.ExecContext(ctx, "DELETE FROM caddy_nodes WHERE id = ?", nid)

	h := &AdminHandlers{DB: func() *sql.DB { return db }, Logger: slog.Default()}
	form := url.Values{"action": {"approve"}, "ids": {fmt.Sprint(nid)}}
	req := httptest.NewRequest(http.MethodPost, "/admin/nodes/bulk", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	h.NodesBulk(httptest.NewRecorder(), req)

	var enabled bool
	var approved sql.NullTime
	if err := db.QueryRowContext(ctx, "SELECT is_enabled, approved_at FROM caddy_nodes WHERE id = ?", nid).
		Scan(&enabled, &approved); err != nil {
		t.Fatalf("select: %v", err)
	}
	if !approved.Valid || !enabled {
		t.Fatalf("bulk approve: approved=%v enabled=%v, want both true", approved.Valid, enabled)
	}
}
