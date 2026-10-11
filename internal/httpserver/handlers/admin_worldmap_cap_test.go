package handlers

import (
	"context"
	"database/sql"
	"testing"

	_ "modernc.org/sqlite"
)

// Traffic past the distinct-IP cap must still be counted (into unknown).
func TestAggregateTrafficCountsTailPastCap(t *testing.T) {
	db, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		t.Fatal(err)
	}
	db.SetMaxOpenConns(1)
	t.Cleanup(func() { db.Close() })
	const extra = 50
	for _, s := range []string{
		`CREATE TABLE host_access_log (remote_ip TEXT)`,
		`WITH RECURSIVE n(i) AS (SELECT 1 UNION ALL SELECT i+1 FROM n WHERE i < 5050)
		 INSERT INTO host_access_log SELECT 'ip' || i FROM n`,
	} {
		if _, err := db.Exec(s); err != nil {
			t.Fatal(err)
		}
	}
	agg := aggregateTrafficByCountry(context.Background(), db, "hal.remote_ip <> ''", nil, nil)
	if agg.dbErr != nil {
		t.Fatal(agg.dbErr)
	}
	if want := int64(worldmapDistinctIPCap + extra); agg.total != want || agg.unknown != want {
		t.Fatalf("total %d unknown %d, want %d", agg.total, agg.unknown, want)
	}
}
