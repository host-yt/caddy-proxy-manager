package handlers

import (
	"context"
	"database/sql"
	"testing"

	_ "modernc.org/sqlite"
)

func TestEnsureAdminServicePicksPortRange(t *testing.T) {
	db, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	db.SetMaxOpenConns(1)
	for _, q := range []string{
		`CREATE TABLE services (id INTEGER PRIMARY KEY AUTOINCREMENT, client_id INT, name TEXT, backend_ip TEXT,
		   allowed_port_start INT, allowed_port_end INT, plan_id INT, node_group_id INT, status TEXT)`,
		`INSERT INTO services (client_id, name, backend_ip, allowed_port_start, allowed_port_end, plan_id, node_group_id, status) VALUES
		   (1,'a','10.0.0.1',80,80,1,1,'active'), (1,'b','10.0.0.1',5000,5000,1,1,'active')`,
	} {
		if _, err := db.Exec(q); err != nil {
			t.Fatal(err)
		}
	}
	ctx := context.Background()
	for _, c := range []struct {
		port int
		want int64
	}{{80, 1}, {5000, 2}, {0, 1}, {8080, 3}} { // 8080 matches nothing: new service
		got, err := ensureAdminService(ctx, db, 1, "10.0.0.1", c.port, 1, 1)
		if err != nil || got != c.want {
			t.Fatalf("port %d: got %d err %v, want %d", c.port, got, err, c.want)
		}
	}
}
