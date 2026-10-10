package handlers

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"log/slog"
	"testing"
	"time"
)

// migrateFixture builds a group with a source holding nRoutes routes and
// peers with the given free slots. FK checks are off on the single conn.
func migrateFixture(t *testing.T, nRoutes int, free ...int) (*sql.DB, int64, int64, []int64) {
	t.Helper()
	db := openTestDBHandlers(t)
	db.SetMaxOpenConns(1)
	ctx := context.Background()
	if _, err := db.ExecContext(ctx, "SET FOREIGN_KEY_CHECKS=0"); err != nil {
		t.Fatal(err)
	}
	sfx := time.Now().UnixNano()
	res, err := db.ExecContext(ctx, "INSERT INTO node_groups (name) VALUES (?)", fmt.Sprintf("mig_%d", sfx))
	if err != nil {
		t.Fatal(err)
	}
	gid, _ := res.LastInsertId()
	node := func(name string, max, cur int) int64 {
		res, err := db.ExecContext(ctx,
			`INSERT INTO caddy_nodes (name, api_url, node_group_id, max_routes, current_routes, is_enabled, approved_at, health_status)
			 VALUES (?, 'http://10.1.1.1:2021', ?, ?, ?, 1, NOW(), 'healthy')`,
			fmt.Sprintf("mig_%s_%d", name, sfx), gid, max, cur)
		if err != nil {
			t.Fatal(err)
		}
		id, _ := res.LastInsertId()
		return id
	}
	src := node("src", 100, nRoutes)
	var peers []int64
	for i, f := range free {
		peers = append(peers, node(fmt.Sprint("p", i), 10, 10-f))
	}
	for i := 0; i < nRoutes; i++ {
		if _, err := db.ExecContext(ctx,
			"INSERT INTO routes (service_id, caddy_node_id, domain, upstream_port) VALUES (999999, ?, ?, 80)",
			src, fmt.Sprintf("mig%d-%d.example.test", sfx, i)); err != nil {
			t.Fatal(err)
		}
	}
	t.Cleanup(func() {
		_, _ = db.ExecContext(ctx, "DELETE FROM routes WHERE domain LIKE ?", fmt.Sprintf("mig%d-%%", sfx))
		_, _ = db.ExecContext(ctx, "DELETE FROM caddy_nodes WHERE node_group_id = ?", gid)
		_, _ = db.ExecContext(ctx, "DELETE FROM node_groups WHERE id = ?", gid)
		db.Close()
	})
	return db, gid, src, peers
}

func nodeLoad(t *testing.T, db *sql.DB, id int64) (routesOn, counter int) {
	t.Helper()
	ctx := context.Background()
	_ = db.QueryRowContext(ctx, "SELECT COUNT(*) FROM routes WHERE caddy_node_id = ?", id).Scan(&routesOn)
	_ = db.QueryRowContext(ctx, "SELECT current_routes FROM caddy_nodes WHERE id = ?", id).Scan(&counter)
	return
}

// Routes spread over peers by free capacity; nobody exceeds max_routes.
func TestMigrateNodeRoutesSpreadsByCapacity(t *testing.T) {
	db, gid, src, peers := migrateFixture(t, 4, 1, 3)
	h := &AdminHandlers{Logger: slog.Default(), ResyncNode: func(context.Context, int64) error { return nil }}
	moved, dests, err := h.migrateNodeRoutes(context.Background(), db, src, gid, false)
	if err != nil || moved != 4 || len(dests) != 2 {
		t.Fatalf("moved=%d dests=%v err=%v", moved, dests, err)
	}
	a, ac := nodeLoad(t, db, peers[0])
	b, bc := nodeLoad(t, db, peers[1])
	if a+b != 4 || ac > 10 || bc > 10 {
		t.Fatalf("peer loads: %d/%d counter, %d/%d counter", a, ac, b, bc)
	}
}

// Not enough room anywhere: nothing moves.
func TestMigrateNodeRoutesRefusesOverfill(t *testing.T) {
	db, gid, src, _ := migrateFixture(t, 4, 1, 1)
	h := &AdminHandlers{Logger: slog.Default()}
	if _, _, err := h.migrateNodeRoutes(context.Background(), db, src, gid, false); err == nil {
		t.Fatal("expected capacity error")
	}
	if n, c := nodeLoad(t, db, src); n != 4 || c != 4 {
		t.Fatalf("source changed: routes=%d counter=%d", n, c)
	}
}

// A failed destination push rolls every assignment and counter back.
func TestMigrateNodeRoutesRollsBackOnPushFailure(t *testing.T) {
	db, gid, src, peers := migrateFixture(t, 4, 2, 3)
	h := &AdminHandlers{Logger: slog.Default(), ResyncNode: func(_ context.Context, id int64) error {
		if id == peers[0] { // pushed second, after peers[1]
			return errors.New("boom")
		}
		return nil
	}}
	if _, _, err := h.migrateNodeRoutes(context.Background(), db, src, gid, false); err == nil {
		t.Fatal("expected push error")
	}
	if n, c := nodeLoad(t, db, src); n != 4 || c != 4 {
		t.Fatalf("source not restored: routes=%d counter=%d", n, c)
	}
	for i, want := range []int{8, 7} {
		if n, c := nodeLoad(t, db, peers[i]); n != 0 || c != want {
			t.Fatalf("peer %d not restored: routes=%d counter=%d", i, n, c)
		}
	}
}
