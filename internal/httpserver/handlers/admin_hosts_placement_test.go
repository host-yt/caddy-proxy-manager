package handlers

import (
	"context"
	"database/sql"
	"errors"
	"log/slog"
	"testing"

	"github.com/host-yt/caddy-proxy-manager/internal/adminscope"
	"github.com/host-yt/caddy-proxy-manager/internal/auth"
)

// A reseller may only place routes/streams on node groups its package grants;
// a forged but valid group ID, or no package at all, is refused.
func TestCheckPlacementResellerGrants(t *testing.T) {
	db, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	for _, s := range []string{
		`CREATE TABLE users (id INTEGER PRIMARY KEY, reseller_id INTEGER, role TEXT, is_restricted INTEGER DEFAULT 0)`,
		`CREATE TABLE resellers (id INTEGER PRIMARY KEY, status TEXT, reseller_plan_id INTEGER)`,
		`CREATE TABLE reseller_plan_node_groups (reseller_plan_id INTEGER, node_group_id INTEGER)`,
		`CREATE TABLE clients (id INTEGER PRIMARY KEY, reseller_id INTEGER)`,
		`INSERT INTO users (id, reseller_id, role) VALUES (1, 10, 'admin'), (2, 20, 'admin'), (3, NULL, 'super_admin')`,
		`INSERT INTO resellers (id, status, reseller_plan_id) VALUES (10, 'active', 5), (20, 'active', NULL)`,
		`INSERT INTO reseller_plan_node_groups (reseller_plan_id, node_group_id) VALUES (5, 1)`,
	} {
		if _, err := db.Exec(s); err != nil {
			t.Fatalf("exec %q: %v", s, err)
		}
	}
	h := &AdminHandlers{
		DB:         func() *sql.DB { return db },
		AdminScope: adminscope.New(func() *sql.DB { return db }),
		Logger:     slog.Default(),
	}
	ctx := context.Background()
	reseller := &auth.Session{UserID: 1, Role: "admin", ResellerID: 10}
	noPackage := &auth.Session{UserID: 2, Role: "admin", ResellerID: 20}
	super := &auth.Session{UserID: 3, Role: "super_admin"}

	if err := h.checkPlacement(ctx, reseller, 1); err != nil {
		t.Errorf("granted group refused: %v", err)
	}
	if err := h.checkPlacement(ctx, reseller, 2); !errors.Is(err, errPlacementNotGranted) {
		t.Errorf("ungranted group: want errPlacementNotGranted, got %v", err)
	}
	if err := h.checkPlacement(ctx, noPackage, 1); !errors.Is(err, errPlacementNotGranted) {
		t.Errorf("no package: want errPlacementNotGranted, got %v", err)
	}
	if err := h.checkPlacement(ctx, super, 2); err != nil {
		t.Errorf("super_admin must place anywhere: %v", err)
	}
}
