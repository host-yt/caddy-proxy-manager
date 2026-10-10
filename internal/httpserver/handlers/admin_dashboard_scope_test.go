package handlers

import (
	"context"
	"fmt"
	"log/slog"
	"testing"
	"time"
)

// A confined admin's dashboard counts only its own clients' data and no
// platform-wide fleet numbers.
func TestDashboardCountsScoped(t *testing.T) {
	db := openTestDBHandlers(t)
	db.SetMaxOpenConns(1)
	defer db.Close()
	ctx := context.Background()
	if _, err := db.ExecContext(ctx, "SET FOREIGN_KEY_CHECKS=0"); err != nil {
		t.Fatal(err)
	}
	sfx := time.Now().UnixNano()
	var clients []int64
	for i := range 2 {
		res, err := db.ExecContext(ctx, "INSERT INTO clients (user_id) VALUES (?)", 900000000+sfx%1000000*10+int64(i))
		if err != nil {
			t.Fatal(err)
		}
		cid, _ := res.LastInsertId()
		clients = append(clients, cid)
		res, err = db.ExecContext(ctx,
			`INSERT INTO services (client_id, name, backend_ip, allowed_port_start, allowed_port_end, plan_id, node_group_id)
			 VALUES (?, 'dash', '10.0.0.1', 1, 2, 999999, 999999)`, cid)
		if err != nil {
			t.Fatal(err)
		}
		sid, _ := res.LastInsertId()
		if _, err := db.ExecContext(ctx,
			"INSERT INTO routes (service_id, caddy_node_id, domain, upstream_port) VALUES (?, 999999, ?, 80)",
			sid, fmt.Sprintf("dash%d-%d.example.test", sfx, i)); err != nil {
			t.Fatal(err)
		}
	}
	t.Cleanup(func() {
		_, _ = db.ExecContext(ctx, "DELETE FROM routes WHERE domain LIKE ?", fmt.Sprintf("dash%d-%%", sfx))
		_, _ = db.ExecContext(ctx, "DELETE FROM services WHERE client_id IN (?, ?)", clients[0], clients[1])
		_, _ = db.ExecContext(ctx, "DELETE FROM clients WHERE id IN (?, ?)", clients[0], clients[1])
	})

	h := &AdminHandlers{Logger: slog.Default()}
	all := h.dashboardCounts(ctx, db, dashScope{})
	one := h.dashboardCounts(ctx, db, dashScope{scoped: true, ids: clients[:1]})
	none := h.dashboardCounts(ctx, db, dashScope{scoped: true})
	if all.TotalHosts < 2 || all.Clients < 2 {
		t.Fatalf("unscoped counts too low: %+v", all)
	}
	if one.TotalHosts != 1 || one.Clients != 1 || one.NodesTotal != 0 || one.Plans != 0 {
		t.Fatalf("scoped counts leak: %+v", one)
	}
	if none.TotalHosts != 0 || none.Clients != 0 {
		t.Fatalf("empty scope must see nothing: %+v", none)
	}
}
